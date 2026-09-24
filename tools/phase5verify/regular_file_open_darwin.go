//go:build darwin

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openRegularFile protects the final evidence path component on Darwin. The
// release verifier runs on Linux, where the descriptor-relative implementation
// also protects parent components; this fallback permits macOS system paths
// such as /var -> /private/var while still rejecting final-file symlinks and
// special files.
func openRegularFile(path, description string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s %q without following symlinks: %w", description, path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened %s %q: %w", description, path, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s %q is not a regular file", description, path)
	}
	return file, nil
}
