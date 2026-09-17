//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// acquireFlowReaderLock obtains the node-local flow-reader lock. The lock is
// held by the returned file descriptor, so the operating system releases it
// automatically if the reader process exits unexpectedly.
func acquireFlowReaderLock(runDir string) (func() error, error) {
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		runDir = "/run/ztap"
	}
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return nil, fmt.Errorf("create flow reader run directory %q: %w", runDir, err)
	}
	lockPath := filepath.Join(runDir, "flows.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open flow reader lock %q: %w", lockPath, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another ZTAP flow reader already holds %s", lockPath)
		}
		return nil, fmt.Errorf("lock flow reader run %q: %w", lockPath, err)
	}

	var once sync.Once
	var unlockErr error
	return func() error {
		once.Do(func() {
			unlockErr = errors.Join(
				unix.Flock(int(file.Fd()), unix.LOCK_UN),
				file.Close(),
			)
		})
		return unlockErr
	}, nil
}
