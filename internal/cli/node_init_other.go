//go:build !linux

package cli

import (
	"context"
	"errors"

	"k8s.io/client-go/rest"
)

func initializeNodeBootstrap(context.Context, nativeCoreClient, *rest.Config, string, string, string) error {
	return errors.New("node guard initialization requires Linux")
}
