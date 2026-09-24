package enforcer

import (
	"fmt"
	"testing"

	"github.com/saadshabir/ZTAP/internal/flow"
)

const phase5FlowLoopbackIPv4 uint32 = 0x7f000001

// phase5FlowEventMatch validates the event contract used by the sustained
// flow-accounting harness. Events from another policy epoch are expected while
// the warm-up traffic drains and are ignored; an event in the measured epoch
// must belong to the selected cgroup, the 127.0.0.1 IPv4/UDP egress tuple,
// and the action implied by its destination port.
func phase5FlowEventMatch(event flow.RawFlowEvent, epoch, cgroupID uint64, allowedPort, blockedPort uint16) (bool, error) {
	if event.PolicyEpoch != epoch {
		return false, nil
	}
	if event.SchemaVersion != 1 {
		return false, fmt.Errorf("flow event schema version %d, want 1", event.SchemaVersion)
	}
	if event.CgroupID != cgroupID {
		return false, fmt.Errorf("flow event cgroup %d, want %d", event.CgroupID, cgroupID)
	}
	if event.Protocol != flow.ProtocolUDP {
		return false, fmt.Errorf("flow event protocol %d, want UDP", event.Protocol)
	}
	if event.Direction != flow.DirectionEgress {
		return false, fmt.Errorf("flow event direction %d, want egress", event.Direction)
	}
	if event.Family != 4 {
		return false, fmt.Errorf("flow event address family %d, want IPv4", event.Family)
	}
	if event.SrcIP != [4]uint32{phase5FlowLoopbackIPv4} {
		return false, fmt.Errorf("flow event source %#v, want loopback", event.SrcIP)
	}
	if event.DestIP != [4]uint32{phase5FlowLoopbackIPv4} {
		return false, fmt.Errorf("flow event destination %#v, want loopback", event.DestIP)
	}
	var expectedAction uint8
	switch event.DestPort {
	case allowedPort:
		expectedAction = flow.ActionAllowed
	case blockedPort:
		expectedAction = flow.ActionBlocked
	default:
		return false, fmt.Errorf("flow event destination port %d is outside the measured pair", event.DestPort)
	}
	if event.Action != expectedAction {
		return false, fmt.Errorf("flow event action %d for destination port %d, want %d", event.Action, event.DestPort, expectedAction)
	}
	return true, nil
}

func phase5DecisionDelta(before, after EngineMetricsSnapshot) (uint64, error) {
	type counterKey struct {
		action    string
		direction string
		reason    string
	}
	counts := func(metrics []EngineDecisionMetric) (map[counterKey]uint64, error) {
		result := make(map[counterKey]uint64, len(metrics))
		for _, metric := range metrics {
			key := counterKey{action: metric.Action, direction: metric.Direction, reason: metric.Reason}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("duplicate decision counter %q/%q/%q", key.action, key.direction, key.reason)
			}
			result[key] = metric.Count
		}
		return result, nil
	}
	beforeCounts, err := counts(before.Decisions)
	if err != nil {
		return 0, fmt.Errorf("read before decision counters: %w", err)
	}
	afterCounts, err := counts(after.Decisions)
	if err != nil {
		return 0, fmt.Errorf("read after decision counters: %w", err)
	}
	if len(beforeCounts) != len(afterCounts) {
		return 0, fmt.Errorf("decision counter shape changed from %d to %d entries", len(beforeCounts), len(afterCounts))
	}
	var total uint64
	for key, beforeCount := range beforeCounts {
		afterCount, ok := afterCounts[key]
		if !ok {
			return 0, fmt.Errorf("decision counter %q/%q/%q disappeared", key.action, key.direction, key.reason)
		}
		delta, err := phase5CounterDelta(beforeCount, afterCount)
		if err != nil {
			return 0, fmt.Errorf("decision counter %q/%q/%q: %w", key.action, key.direction, key.reason, err)
		}
		total, err = phase5CounterSum(total, delta)
		if err != nil {
			return 0, fmt.Errorf("sum decision counter deltas: %w", err)
		}
	}
	for key := range afterCounts {
		if _, ok := beforeCounts[key]; !ok {
			return 0, fmt.Errorf("decision counter %q/%q/%q appeared", key.action, key.direction, key.reason)
		}
	}
	return total, nil
}

func phase5DropDelta(before, after EngineMetricsSnapshot, reason string) (uint64, error) {
	counts := func(metrics []EngineEventDropMetric) (map[string]uint64, error) {
		result := make(map[string]uint64, len(metrics))
		for _, metric := range metrics {
			if _, exists := result[metric.Reason]; exists {
				return nil, fmt.Errorf("duplicate event-drop counter %q", metric.Reason)
			}
			result[metric.Reason] = metric.Count
		}
		return result, nil
	}
	beforeCounts, err := counts(before.EventDrops)
	if err != nil {
		return 0, fmt.Errorf("read before event-drop counters: %w", err)
	}
	afterCounts, err := counts(after.EventDrops)
	if err != nil {
		return 0, fmt.Errorf("read after event-drop counters: %w", err)
	}
	if len(beforeCounts) != len(afterCounts) {
		return 0, fmt.Errorf("event-drop counter shape changed from %d to %d entries", len(beforeCounts), len(afterCounts))
	}
	var selected uint64
	selectedFound := false
	for counterReason, beforeCount := range beforeCounts {
		afterCount, ok := afterCounts[counterReason]
		if !ok {
			return 0, fmt.Errorf("event-drop counter %q disappeared", counterReason)
		}
		delta, err := phase5CounterDelta(beforeCount, afterCount)
		if err != nil {
			return 0, fmt.Errorf("event-drop counter %q: %w", counterReason, err)
		}
		if counterReason == reason {
			selected = delta
			selectedFound = true
		}
	}
	for counterReason := range afterCounts {
		if _, ok := beforeCounts[counterReason]; !ok {
			return 0, fmt.Errorf("event-drop counter %q appeared", counterReason)
		}
	}
	if !selectedFound {
		return 0, fmt.Errorf("event-drop counter %q is missing", reason)
	}
	return selected, nil
}

func phase5CounterDelta(before, after uint64) (uint64, error) {
	if after < before {
		return 0, fmt.Errorf("counter decreased from %d to %d", before, after)
	}
	return after - before, nil
}

func phase5CounterSum(values ...uint64) (uint64, error) {
	return sumCounterValues(values)
}

func TestPhase5CounterDeltaRejectsReset(t *testing.T) {
	if _, err := phase5CounterDelta(10, 9); err == nil {
		t.Fatal("phase5CounterDelta accepted a reset counter")
	}
	got, err := phase5CounterDelta(9, 10)
	if err != nil {
		t.Fatalf("phase5CounterDelta rejected a monotonic counter: %v", err)
	}
	if got != 1 {
		t.Fatalf("phase5CounterDelta = %d, want 1", got)
	}
	if _, err := phase5CounterSum(^uint64(0), 1); err == nil {
		t.Fatal("phase5CounterSum accepted an overflowing sum")
	}
}

func TestPhase5FlowEventMatchBindsSelectedTraffic(t *testing.T) {
	const (
		epoch       = 7
		cgroupID    = 42
		allowedPort = 41000
		blockedPort = 41001
	)
	tests := []struct {
		name    string
		event   flow.RawFlowEvent
		matched bool
		wantErr bool
	}{
		{
			name: "allowed tuple",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			matched: true,
		},
		{
			name: "blocked tuple",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: blockedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionBlocked, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			matched: true,
		},
		{
			name: "previous epoch is ignored",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch - 1, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
		},
		{
			name: "wrong schema fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 2,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "other cgroup fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID + 1, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "other tuple fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: 41002,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionBlocked, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "wrong protocol fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolTCP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "wrong direction fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionIngress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "wrong family fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 6, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "wrong destination fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{0x7f000002},
			},
			wantErr: true,
		},
		{
			name: "wrong source fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionAllowed, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{0x0a000001}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
		{
			name: "wrong action fails closed",
			event: flow.RawFlowEvent{
				PolicyEpoch: epoch, CgroupID: cgroupID, DestPort: allowedPort,
				Protocol: flow.ProtocolUDP, Direction: flow.DirectionEgress,
				Action: flow.ActionBlocked, Family: 4, SchemaVersion: 1,
				SrcIP: [4]uint32{phase5FlowLoopbackIPv4}, DestIP: [4]uint32{phase5FlowLoopbackIPv4},
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched, err := phase5FlowEventMatch(test.event, epoch, cgroupID, allowedPort, blockedPort)
			if test.wantErr {
				if err == nil {
					t.Fatal("phase5FlowEventMatch accepted a measured-epoch contract mismatch")
				}
				return
			}
			if err != nil {
				t.Fatalf("phase5FlowEventMatch returned an error: %v", err)
			}
			if matched != test.matched {
				t.Fatalf("phase5FlowEventMatch = %t, want %t", matched, test.matched)
			}
		})
	}
}

func TestSumCounterValuesRejectsPerCPUOverflow(t *testing.T) {
	if _, err := sumCounterValues([]uint64{^uint64(0), 1}); err == nil {
		t.Fatal("sumCounterValues accepted an overflowing per-CPU counter total")
	}
	got, err := sumCounterValues([]uint64{4, 5, 6})
	if err != nil {
		t.Fatalf("sumCounterValues rejected a valid total: %v", err)
	}
	if got != 15 {
		t.Fatalf("sumCounterValues = %d, want 15", got)
	}
}

func TestPhase5DecisionDeltaRejectsMaskedCounterReset(t *testing.T) {
	before := EngineMetricsSnapshot{Decisions: []EngineDecisionMetric{
		{Action: "allowed", Direction: "egress", Reason: "policy", Count: 10},
		{Action: "blocked", Direction: "egress", Reason: "policy", Count: 20},
	}}
	after := EngineMetricsSnapshot{Decisions: []EngineDecisionMetric{
		{Action: "allowed", Direction: "egress", Reason: "policy", Count: 9},
		{Action: "blocked", Direction: "egress", Reason: "policy", Count: 31},
	}}
	if _, err := phase5DecisionDelta(before, after); err == nil {
		t.Fatal("phase5DecisionDelta accepted an individual reset masked by another counter")
	}
}

func TestPhase5DropDeltaRejectsCounterReset(t *testing.T) {
	before := EngineMetricsSnapshot{EventDrops: []EngineEventDropMetric{
		{Reason: "rate_limited", Count: 10},
		{Reason: "ring_full", Count: 20},
	}}
	after := EngineMetricsSnapshot{EventDrops: []EngineEventDropMetric{
		{Reason: "rate_limited", Count: 9},
		{Reason: "ring_full", Count: 21},
	}}
	if _, err := phase5DropDelta(before, after, "rate_limited"); err == nil {
		t.Fatal("phase5DropDelta accepted a counter reset")
	}
}

func TestPhase5DecisionDeltaRejectsCounterShapeDrift(t *testing.T) {
	before := EngineMetricsSnapshot{Decisions: []EngineDecisionMetric{{Action: "allowed", Direction: "egress", Reason: "policy", Count: 10}}}
	after := EngineMetricsSnapshot{Decisions: []EngineDecisionMetric{{Action: "blocked", Direction: "egress", Reason: "policy", Count: 10}}}
	if _, err := phase5DecisionDelta(before, after); err == nil {
		t.Fatal("phase5DecisionDelta accepted counter identity drift")
	}
}
