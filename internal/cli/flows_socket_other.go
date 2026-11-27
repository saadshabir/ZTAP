//go:build !linux

package cli

import (
	"context"
	"io"
)

func openAgentFlowSocket(context.Context, string) (io.ReadCloser, error) { return nil, nil }
