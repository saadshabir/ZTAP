//go:build !linux && !windows

package cli

import (
	"errors"

	"ztap/internal/flow"
)

func openStreamingFlowReader() (flow.FlowReader, error) {
	return nil, errors.New("real flow streaming is supported only on Linux")
}

func createAnomalyFlowReader() (flow.FlowReader, error) {
	return nil, errors.New("real flow monitoring is unavailable on this platform")
}
