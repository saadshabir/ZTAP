//go:build !linux

package cli

import (
	"context"
	"errors"

	"k8s.io/client-go/kubernetes"
)

func runNativeKubernetesAgent(context.Context, kubernetes.Interface, NativeAgentOptions) error {
	return errors.New("the native Kubernetes node agent requires Linux")
}
