//go:build !linux

package cli

import (
	"errors"

	"github.com/saadshabir/ZTAP/internal/flow"
)

func openStreamingFlowReader(_ string) (flow.FlowReader, error) {
	return nil, errors.New("real flow streaming is supported only on Linux")
}
