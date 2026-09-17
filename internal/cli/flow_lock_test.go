//go:build !windows

package cli

import (
	"strings"
	"testing"
)

func TestAcquireFlowReaderLockIsExclusiveAndReleases(t *testing.T) {
	runDir := t.TempDir()
	unlock, err := acquireFlowReaderLock(runDir)
	if err != nil {
		t.Fatalf("first flow lock: %v", err)
	}
	if _, err := acquireFlowReaderLock(runDir); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("second flow lock error = %v, want already-held error", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("unlock flow reader: %v", err)
	}
	// The close of the owning descriptor releases the kernel lock. Calling the
	// returned cleanup more than once is safe for deferred shutdown paths.
	if err := unlock(); err != nil {
		t.Fatalf("repeat flow unlock: %v", err)
	}
	second, err := acquireFlowReaderLock(runDir)
	if err != nil {
		t.Fatalf("flow lock after release: %v", err)
	}
	if err := second(); err != nil {
		t.Fatalf("second flow unlock: %v", err)
	}
}
