//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openZTAPLock creates or opens a node-local lock file without following
// symlinked path components. The run directory is created one component at a
// time so an attacker cannot redirect MkdirAll through an existing symlink.
func openZTAPLock(runDir, lockName, owner string) (*os.File, string, error) {
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		runDir = "/run/ztap"
	}
	if lockName == "" || filepath.Base(lockName) != lockName {
		return nil, "", fmt.Errorf("invalid %s lock name %q", owner, lockName)
	}
	absRunDir, err := filepath.Abs(runDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s run directory %q: %w", owner, runDir, err)
	}
	absRunDir = filepath.Clean(absRunDir)
	lockPath := filepath.Join(absRunDir, lockName)
	directoryFD, err := openLockDirectory(absRunDir, owner)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(directoryFD)

	fd, err := unix.Openat(directoryFD, lockName, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, "", fmt.Errorf("%s lock %q is a symlink", owner, lockPath)
		}
		if errors.Is(err, unix.EISDIR) {
			return nil, "", fmt.Errorf("%s lock %q is not a regular file", owner, lockPath)
		}
		return nil, "", fmt.Errorf("open %s lock %q: %w", owner, lockPath, err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("open %s lock %q returned no file handle", owner, lockPath)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, "", errors.Join(
			fmt.Errorf("stat %s lock %q: %w", owner, lockPath, err),
			file.Close(),
		)
	}
	if !info.Mode().IsRegular() {
		return nil, "", errors.Join(
			fmt.Errorf("%s lock %q is not a regular file", owner, lockPath),
			file.Close(),
		)
	}
	return file, lockPath, nil
}

func openLockDirectory(path, owner string) (int, error) {
	return openDirectoryNoFollow(path, owner, true)
}

func openExistingDirectory(path, owner string) (int, error) {
	return openDirectoryNoFollow(path, owner, false)
}

func openDirectoryNoFollow(path, owner string, createMissing bool) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("%s directory %q is not absolute", owner, path)
	}
	path = filepath.Clean(path)
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open root for %s directory %q: %w", owner, path, err)
	}
	currentFD := rootFD
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && createMissing {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o750); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return -1, fmt.Errorf("create %s directory component %q: %w", owner, component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(currentFD)
			if errors.Is(openErr, unix.ELOOP) {
				return -1, fmt.Errorf("%s directory %q contains symlink component %q", owner, path, component)
			}
			if errors.Is(openErr, unix.ENOTDIR) {
				return -1, fmt.Errorf("%s directory %q component %q is not a directory", owner, path, component)
			}
			return -1, fmt.Errorf("inspect %s directory component %q: %w", owner, component, openErr)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}
