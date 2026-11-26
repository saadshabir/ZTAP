//go:build !linux

package cli

import (
	"context"
	"errors"
)

func installNodeBootGuard(context.Context, string, string, string) error {
	return errors.New("node boot guard requires Linux")
}

func verifyBootGuardKubelet(context.Context, string) error {
	return errors.New("node boot guard requires Linux")
}
