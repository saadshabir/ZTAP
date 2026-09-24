//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func openPhase5EvidenceDirectory(path string) (int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return -1, fmt.Errorf("resolve Phase 5 evidence directory %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open root for Phase 5 evidence directory %q: %w", absPath, err)
	}
	currentFD := rootFD
	components := strings.Split(strings.TrimPrefix(absPath, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return -1, fmt.Errorf("create Phase 5 evidence directory component %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(currentFD)
			if errors.Is(openErr, unix.ELOOP) {
				return -1, fmt.Errorf("Phase 5 evidence directory %q contains symlink component %q", absPath, component)
			}
			if errors.Is(openErr, unix.ENOTDIR) {
				return -1, fmt.Errorf("Phase 5 evidence directory %q component %q is not a directory", absPath, component)
			}
			return -1, fmt.Errorf("inspect Phase 5 evidence directory component %q: %w", component, openErr)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}

func openPhase5EvidenceFile(path string) (*os.File, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve Phase 5 evidence path %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)
	name := filepath.Base(absPath)
	if name == "." || name == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid Phase 5 evidence file path %q", path)
	}
	directoryFD, err := openPhase5EvidenceDirectory(filepath.Dir(absPath))
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create Phase 5 evidence file %q: %w", absPath, err)
	}
	file := os.NewFile(uintptr(fd), absPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create Phase 5 evidence file %q returned no file handle", absPath)
	}
	return file, nil
}

func createPhase5EvidenceFile(path string, payload []byte) error {
	file, err := openPhase5EvidenceFile(path)
	if err != nil {
		return err
	}
	data := make([]byte, 0, len(payload)+1)
	data = append(data, payload...)
	data = append(data, '\n')
	written, err := file.Write(data)
	if err != nil || written != len(data) {
		_ = file.Close()
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	return file.Close()
}

func writePhase5EvidenceFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := createPhase5EvidenceFile(path, payload); err != nil {
		t.Fatalf("write Phase 5 evidence %q without following symlinks: %v", path, err)
	}
}

func TestPhase5EvidenceFileCreationIsExclusive(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "evidence.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("write stale evidence: %v", err)
	}
	if err := createPhase5EvidenceFile(path, []byte("new")); err == nil {
		t.Fatal("evidence writer overwrote an existing file")
	}
	link := filepath.Join(directory, "evidence-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := createPhase5EvidenceFile(link, []byte("redirected")); err == nil {
		t.Fatal("evidence writer followed a symlink")
	}
	targetDirectory := t.TempDir()
	linkedParent := filepath.Join(t.TempDir(), "evidence")
	if err := os.Symlink(targetDirectory, linkedParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := createPhase5EvidenceFile(filepath.Join(linkedParent, "nested.json"), []byte("redirected")); err == nil {
		t.Fatal("evidence writer followed a symlinked parent directory")
	}
	entries, err := os.ReadDir(targetDirectory)
	if err != nil {
		t.Fatalf("read symlink target directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received evidence: %v", entries)
	}
	if err := createPhase5EvidenceFile(filepath.Join(t.TempDir(), "nested", "evidence.json"), []byte("created")); err != nil {
		t.Fatalf("create missing evidence parent directories: %v", err)
	}
}
