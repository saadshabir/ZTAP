//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

// openRegularFile provides the verifier's regular-file check on targets that
// do not expose the Unix O_NOFOLLOW flag. Release verification itself runs on
// Linux; this fallback keeps the standard-library verifier buildable elsewhere.
func openRegularFile(path, description string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %q: %w", description, path, err)
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
