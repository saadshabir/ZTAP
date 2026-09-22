//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestZTAPLocksRejectSymlinkedRunDirectories(t *testing.T) {
	target := t.TempDir()
	linkParent := t.TempDir()
	linkedRunDir := filepath.Join(linkParent, "run")
	if err := os.Symlink(target, linkedRunDir); err != nil {
		t.Fatalf("symlink run directory: %v", err)
	}

	for _, test := range []struct {
		name    string
		acquire func(string) (func() error, error)
	}{
		{name: "agent", acquire: acquireNativeAgentLock},
		{name: "flow reader", acquire: acquireFlowReaderLock},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.acquire(linkedRunDir); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("acquire through symlinked run directory error = %v, want symlink rejection", err)
			}
		})
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received lock entries: %v", entries)
	}
}

func TestZTAPDirectoryOpenRejectsRelativePaths(t *testing.T) {
	if fd, err := openExistingDirectory("relative/dir", "test"); err == nil {
		_ = unix.Close(fd)
		t.Fatal("openExistingDirectory accepted a relative path")
	} else if !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("relative directory error = %v, want absolute-path validation", err)
	}
}

func TestZTAPLocksRejectSymlinkedLockFiles(t *testing.T) {
	for _, test := range []struct {
		name     string
		lockName string
		acquire  func(string) (func() error, error)
	}{
		{name: "agent", lockName: "agent.lock", acquire: acquireNativeAgentLock},
		{name: "flow reader", lockName: "flows.lock", acquire: acquireFlowReaderLock},
	} {
		t.Run(test.name, func(t *testing.T) {
			runDir := t.TempDir()
			target := filepath.Join(t.TempDir(), "redirected.lock")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatalf("create redirected lock: %v", err)
			}
			if err := os.Symlink(target, filepath.Join(runDir, test.lockName)); err != nil {
				t.Fatalf("symlink lock file: %v", err)
			}
			if _, err := test.acquire(runDir); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("acquire through symlinked lock file error = %v, want symlink rejection", err)
			}
		})
	}
}
