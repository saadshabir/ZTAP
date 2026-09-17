//go:build windows

package cli

// Windows flow monitoring uses the platform's event subscription and does not
// share the Linux node-level file lock.
func acquireFlowReaderLock(string) (func() error, error) {
	return func() error { return nil }, nil
}
