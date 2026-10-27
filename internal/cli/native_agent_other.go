//go:build !linux

package cli

import (
	"context"
	"errors"
)

func runNativeKubernetesAgent(context.Context, nativeKubernetesClient, NativeAgentOptions) error {
	return errors.New("the native Kubernetes node agent requires Linux")
}
