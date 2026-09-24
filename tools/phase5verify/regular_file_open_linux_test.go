//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularFileRejectsSymlinkParent(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(target, "evidence.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write target evidence: %v", err)
	}
	linkParent := filepath.Join(t.TempDir(), "evidence-directory-link")
	if err := os.Symlink(target, linkParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if file, err := openRegularFile(filepath.Join(linkParent, "evidence.json"), "evidence"); err == nil {
		_ = file.Close()
		t.Fatal("openRegularFile followed a symlinked parent directory")
	}
}
