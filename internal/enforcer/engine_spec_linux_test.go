//go:build linux

package enforcer

import (
	"strings"
	"testing"
)

func TestGeneratedEngineSpecPassesRuntimeValidation(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	if err := validateEngineCollectionSpec(spec); err != nil {
		t.Fatalf("generated engine spec failed runtime validation: %v", err)
	}
}

func TestEngineSpecValidationRejectsABIWidthDrift(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	spec.Maps["agent_status"].ValueSize++
	if err := validateEngineCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "agent_status") {
		t.Fatalf("ABI width drift error = %v, want agent_status mismatch", err)
	}
}

func TestEngineSpecValidationRejectsActiveConfigABIWidthDrift(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	spec.Maps["active_config"].ValueSize++
	if err := validateEngineCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "active_config") {
		t.Fatalf("active config ABI width drift error = %v, want active_config mismatch", err)
	}
}

func TestEngineSpecValidationRejectsActiveConfigFlagDrift(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	spec.Maps["active_config"].Flags = 1
	if err := validateEngineCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "active_config") {
		t.Fatalf("active config flag drift error = %v, want active_config mismatch", err)
	}
}

func TestEngineSpecValidationRejectsActiveConfigInnerFlagDrift(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	spec.Maps["active_config"].InnerMap.Flags = 1
	if err := validateEngineCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "active_config inner") {
		t.Fatalf("active config inner flag drift error = %v, want active_config inner mismatch", err)
	}
}

func TestEngineSpecValidationRejectsPolicyRuleMapFlagDrift(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	spec.Maps["policy_rules"].Flags = 0
	if err := validateEngineCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "policy_rules") {
		t.Fatalf("policy rule map flag drift error = %v, want policy_rules mismatch", err)
	}
}
