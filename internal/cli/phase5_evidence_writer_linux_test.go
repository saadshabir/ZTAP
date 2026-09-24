//go:build linux && integration
// +build linux,integration

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func ensurePhase5AgentRunDirectory(t *testing.T, path string) {
	t.Helper()
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve supplied native agent run directory: %v", err)
	}
	directoryFD, err := openLockDirectory(absPath, "Phase 5 agent")
	if err != nil {
		t.Fatalf("create supplied native agent run directory: %v", err)
	}
	if err := unix.Close(directoryFD); err != nil {
		t.Fatalf("close supplied native agent run directory: %v", err)
	}
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
	directoryFD, err := openLockDirectory(filepath.Dir(absPath), "Phase 5 evidence")
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
