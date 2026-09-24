//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestValidatePhase5JSONDirectoryRejectsNonRegularEntry(t *testing.T) {
	directory := t.TempDir()
	for _, spec := range phase5JSONArtifactSpecs {
		if err := os.WriteFile(filepath.Join(directory, spec.name), []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write required artifact %q: %v", spec.name, err)
		}
	}
	fifo := filepath.Join(directory, "unexpected.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	if err := validatePhase5JSONDirectory(directory); err == nil {
		t.Fatal("Phase 5 verifier accepted a non-regular evidence-tree entry")
	}
}

func TestFindHostedEvidenceFileRejectsUnmatchedNonRegularEntry(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "required.txt"), []byte("evidence\n"), 0o600); err != nil {
		t.Fatalf("write required hosted evidence: %v", err)
	}
	fifo := filepath.Join(directory, "unexpected.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	if _, err := findHostedEvidenceFile(directory, "required.txt"); err == nil {
		t.Fatal("hosted evidence verifier accepted an unmatched non-regular entry")
	}
}
