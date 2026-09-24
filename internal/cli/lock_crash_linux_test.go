//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var lockCrashUnlock func() error

// TestLockCrashHelper is run in a child test process. It intentionally never
// releases the lock so the parent can verify that SIGKILL closes the owning
// descriptor and lets the kernel release the flock.
func TestLockCrashHelper(t *testing.T) {
	if os.Getenv("ZTAP_LOCK_CRASH_HELPER") != "1" {
		return
	}
	runDir := os.Getenv("ZTAP_LOCK_CRASH_RUN_DIR")
	readyPath := os.Getenv("ZTAP_LOCK_CRASH_READY")
	var err error
	switch os.Getenv("ZTAP_LOCK_CRASH_KIND") {
	case "agent":
		lockCrashUnlock, err = acquireNativeAgentLock(runDir)
	case "flow":
		lockCrashUnlock, err = acquireFlowReaderLock(runDir)
	default:
		t.Fatalf("unknown lock kind")
	}
	if err != nil {
		t.Fatalf("child lock acquisition: %v", err)
	}
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("write child lock readiness: %v", err)
	}
	// Keep the returned closure (and therefore its captured descriptor) live
	// until the parent sends SIGKILL. The child intentionally does not unlock.
	select {}
}

func requireLockReleasedAfterSIGKILL(t *testing.T, kind string, acquire func(string) (func() error, error)) {
	t.Helper()
	runDir := t.TempDir()
	readyPath := filepath.Join(runDir, "child.ready")
	command := exec.Command(os.Args[0], "-test.run", "^TestLockCrashHelper$")
	command.Env = append(os.Environ(),
		"ZTAP_LOCK_CRASH_HELPER=1",
		"ZTAP_LOCK_CRASH_KIND="+kind,
		"ZTAP_LOCK_CRASH_RUN_DIR="+runDir,
		"ZTAP_LOCK_CRASH_READY="+readyPath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start %s lock child: %v", kind, err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if command.ProcessState != nil {
			t.Fatalf("%s lock child exited before signaling readiness: %v", kind, command.ProcessState)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s lock child", kind)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill %s lock child: %v", kind, err)
	}
	if err := command.Wait(); err == nil {
		t.Fatalf("%s lock child exited cleanly after SIGKILL", kind)
	}
	waited = true

	unlock, err := acquire(runDir)
	if err != nil {
		t.Fatalf("acquire %s lock after child SIGKILL: %v", kind, err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("release %s lock after child SIGKILL: %v", kind, err)
	}
}

func TestNativeAgentLockReleasesAfterSIGKILL(t *testing.T) {
	requireLockReleasedAfterSIGKILL(t, "agent", acquireNativeAgentLock)
}

func TestFlowReaderLockReleasesAfterSIGKILL(t *testing.T) {
	requireLockReleasedAfterSIGKILL(t, "flow", acquireFlowReaderLock)
}
