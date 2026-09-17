//go:build linux

package enforcer

import (
	"errors"
	"testing"
)

func TestLegacyLinuxEntryPointsAreRetired(t *testing.T) {
	if err := EnforceWithEBPFIfAvailable(EnforcementOptions{}); !errors.Is(err, ErrLegacyLinuxEnforcementRetired) {
		t.Fatalf("EnforceWithEBPFIfAvailable error = %v, want %v", err, ErrLegacyLinuxEnforcementRetired)
	}
	if err := EnforceWithEBPFIfAvailableScoped(ScopedEnforcementOptions{}); !errors.Is(err, ErrLegacyLinuxEnforcementRetired) {
		t.Fatalf("EnforceWithEBPFIfAvailableScoped error = %v, want %v", err, ErrLegacyLinuxEnforcementRetired)
	}
}
