//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openRegularFile walks every path component through directory descriptors
// without following symlinks, then verifies the opened descriptor itself is a
// regular file. The nonblocking flag prevents a FIFO supplied in place of
// evidence from stalling the verifier before that descriptor check. Together,
// the checks close both parent-component and final-file replacement windows.
func openRegularFile(path, description string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s %q: %w", description, path, err)
	}
	absolute = filepath.Clean(absolute)
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open root for %s %q: %w", description, absolute, err)
	}
	currentFD := rootFD
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." {
			continue
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := unix.Openat(currentFD, component, flags, 0)
		if openErr != nil {
			_ = unix.Close(currentFD)
			if errors.Is(openErr, unix.ELOOP) {
				return nil, fmt.Errorf("%s %q contains a symlink at %q", description, absolute, component)
			}
			return nil, fmt.Errorf("open %s %q component %q without following symlinks: %w", description, absolute, component, openErr)
		}
		_ = unix.Close(currentFD)
		currentFD = fd
	}
	file := os.NewFile(uintptr(currentFD), absolute)
	if file == nil {
		_ = unix.Close(currentFD)
		return nil, fmt.Errorf("open %s %q returned no file handle", description, absolute)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened %s %q: %w", description, absolute, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s %q is not a regular file", description, absolute)
	}
	return file, nil
}
