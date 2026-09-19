//go:build !linux

package cli

import "errors"

func acquireFlowReaderLock(string) (func() error, error) {
	return nil, errors.New("flow streaming is supported only on Linux")
}
