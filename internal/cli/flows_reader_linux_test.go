//go:build linux

package cli

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePinnedAgentStatus(t *testing.T) {
	now := uint64(100 * time.Second)
	base := pinnedAgentStatus{
		SchemaVersion:  flowAgentStatusSchema,
		LifecycleState: flowAgentStateEnforcing,
		AgentEpoch:     7,
		HeartbeatNS:    now - uint64(time.Second),
	}

	epoch, err := validatePinnedAgentStatus(base, 0, false, now)
	if err != nil || epoch != 7 {
		t.Fatalf("initial status validation = epoch %d, error %v; want epoch 7 and nil error", epoch, err)
	}
	if _, err := validatePinnedAgentStatus(base, 7, true, now); err != nil {
		t.Fatalf("matching status validation: %v", err)
	}

	cases := []struct {
		name   string
		status pinnedAgentStatus
		expect string
	}{
		{name: "schema", status: pinnedAgentStatus{SchemaVersion: 2, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: base.HeartbeatNS}, expect: "unsupported agent status schema"},
		{name: "lifecycle", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: 1, AgentEpoch: 7, HeartbeatNS: base.HeartbeatNS}, expect: "not enforcing"},
		{name: "epoch", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 8, HeartbeatNS: base.HeartbeatNS}, expect: "agent epoch changed"},
		{name: "missing heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7}, expect: "heartbeat is missing"},
		{name: "future heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: now + uint64(time.Second)}, expect: "heartbeat is in the future"},
		{name: "heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: now - uint64(6*time.Second)}, expect: "heartbeat is older"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validatePinnedAgentStatus(test.status, 7, true, now); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("validation error = %v, want %q", err, test.expect)
			}
		})
	}
}
