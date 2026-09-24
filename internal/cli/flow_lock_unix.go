//go:build linux

package cli

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// acquireFlowReaderLock obtains the node-local flow-reader lock. The lock is
// held by the returned file descriptor, so the operating system releases it
// automatically if the reader process exits unexpectedly.
func acquireFlowReaderLock(runDir string) (func() error, error) {
	file, lockPath, err := openZTAPLock(runDir, "flows.lock", "flow reader")
	if err != nil {
		return nil, err
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
