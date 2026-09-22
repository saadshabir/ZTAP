//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRegularFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	if file, err := openRegularFile(path, "evidence"); err == nil {
		_ = file.Close()
		t.Fatal("openRegularFile accepted a FIFO")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("FIFO disappeared during the check: %v", err)
	}
}
