package enforcer

import (
	"net/netip"
	"reflect"
	"testing"
	"unsafe"

	"ztap/internal/policy"

	"github.com/cilium/ebpf"
)

func TestEncodePolicySetSerializesDirectionalSlotKeys(t *testing.T) {
	set := policy.PolicySet{
		NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Subjects: []policy.Subject{{
			CgroupID:    77,
			Isolated:    policy.DirectionIngress | policy.DirectionEgress,
			Quarantined: policy.DirectionIngress,
			PodIPs:      []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		}},
		Rules: []policy.Rule{{
			CgroupID:  77,
			Direction: policy.DirectionIngress,
			Peer:      netip.MustParsePrefix("198.51.100.0/24"),
			Protocol:  policy.ProtocolUDP,
			Port:      53,
		}},
	}

	encoded, err := encodePolicySet(1, set)
	if err != nil {
		t.Fatalf("encode policy set: %v", err)
	}
	if len(encoded.Subjects) != 1 || encoded.Subjects[0].Key != (subjectStateKey{CgroupID: 77, Slot: 1}) {
		t.Fatalf("subject key = %+v", encoded.Subjects)
	}
	if got := encoded.Subjects[0].Value; got.Isolated != uint8(policy.DirectionIngress|policy.DirectionEgress) || got.Quarantined != uint8(policy.DirectionIngress) {
		t.Fatalf("subject masks = %+v", got)
	}
	if len(encoded.Nodes) != 1 || encoded.Nodes[0].Slot != 1 || encoded.Nodes[0].Address != [4]byte{192, 0, 2, 1} {
		t.Fatalf("Node bypass key = %+v", encoded.Nodes)
	}
	if len(encoded.Self) != 1 || encoded.Self[0].CgroupID != 77 || encoded.Self[0].Slot != 1 || encoded.Self[0].Address != [4]byte{192, 0, 2, 10} {
		t.Fatalf("self bypass key = %+v", encoded.Self)
	}
	if len(encoded.Rules) != 1 {
		t.Fatalf("rule key count = %d, want 1", len(encoded.Rules))
	}
	rule := encoded.Rules[0]
	if rule.PrefixLength != 120 || rule.CgroupID != 77 || rule.Peer != [4]byte{198, 51, 100, 0} {
		t.Fatalf("rule prefix/key fields = %+v", rule)
	}
	if rule.Meta != (1<<31)|(1<<30)|(uint32(policy.ProtocolUDP)<<16)|53 {
		t.Fatalf("rule meta = %#x", rule.Meta)
	}

	encodedAgain, err := encodePolicySet(1, set)
	if err != nil {
		t.Fatalf("encode policy set again: %v", err)
	}
	if !reflect.DeepEqual(encoded, encodedAgain) {
		t.Fatalf("encoding is not deterministic:\nfirst:  %+v\nsecond: %+v", encoded, encodedAgain)
	}
}

func TestEngineMapKeyLayoutsMatchBPF(t *testing.T) {
	layouts := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "policy_rule_key", got: unsafe.Sizeof(policyRuleKey{}), want: 24},
		{name: "subject_state_key", got: unsafe.Sizeof(subjectStateKey{}), want: 16},
		{name: "subject_state_value", got: unsafe.Sizeof(subjectStateValue{}), want: 8},
		{name: "node_bypass_key", got: unsafe.Sizeof(nodeBypassKey{}), want: 8},
		{name: "self_bypass_key", got: unsafe.Sizeof(selfBypassKey{}), want: 16},
		{name: "active_config_value", got: unsafe.Sizeof(bpfActiveConfig{}), want: 16},
		{name: "cgroup_storage_key", got: unsafe.Sizeof(cgroupStorageKey{}), want: 16},
		{name: "connection_key", got: unsafe.Sizeof(bpfConnectionKey{}), want: 32},
		{name: "epoch_decision_key", got: unsafe.Sizeof(bpfEpochDecisionKey{}), want: 16},
		{name: "epoch_event_drop_key", got: unsafe.Sizeof(bpfEpochEventDropKey{}), want: 16},
		{name: "event_limiter_value", got: unsafe.Sizeof(bpfEventLimiterValue{}), want: 16},
	}
	for _, layout := range layouts {
		if layout.got != layout.want {
			t.Errorf("%s size = %d, want %d", layout.name, layout.got, layout.want)
		}
	}
}

func TestGeneratedEngineSpecContainsExpectedOwnedMaps(t *testing.T) {
	spec, err := loadEngine()
	if err != nil {
		t.Fatalf("load generated engine spec: %v", err)
	}
	for _, name := range []string{"ztap_egress", "ztap_ingress"} {
		if spec.Programs[name] == nil {
			t.Errorf("generated engine is missing program %q", name)
		}
	}
	wantMaps := map[string]struct {
		mapType   ebpf.MapType
		entries   uint32
		flags     uint32
		keySize   uint32
		valueSize uint32
	}{
		"active_config":           {ebpf.ArrayOfMaps, 1, 0, 4, 4},
		"policy_rules":            {ebpf.LPMTrie, 32_768, enginePolicyRulesMapFlags, 24, 1},
		"subject_state":           {ebpf.Hash, 32_768, 0, 16, 8},
		"node_bypass":             {ebpf.Hash, 32_768, 0, 8, 1},
		"self_bypass":             {ebpf.Hash, 32_768, 0, 16, 1},
		"conn_state":              {ebpf.LRUHash, 65_536, 0, 32, 8},
		"flow_events":             {ebpf.RingBuf, 1 << 20, 0, 0, 0},
		"decision_counts":         {ebpf.PerCPUArray, 48, 0, 4, 8},
		"decision_epoch_counts":   {ebpf.LRUCPUHash, 4096, 0, 16, 8},
		"event_drops":             {ebpf.PerCPUArray, 2, 0, 4, 8},
		"event_drop_epoch_counts": {ebpf.LRUCPUHash, 1024, 0, 16, 8},
		"event_limiter":           {ebpf.PerCPUArray, 1, 0, 4, 16},
		"in_flight":               {ebpf.PerCPUArray, 2, 0, 4, 8},
		"attached_cgroup":         {ebpf.CGroupStorage, 0, 0, 16, 8},
		"agent_status":            {ebpf.Array, 1, 0, 4, 24},
	}
	for name, want := range wantMaps {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			t.Errorf("generated engine is missing map %q", name)
			continue
		}
		if mapSpec.Type != want.mapType || mapSpec.MaxEntries != want.entries || mapSpec.Flags != want.flags || mapSpec.KeySize != want.keySize || mapSpec.ValueSize != want.valueSize {
			t.Errorf("map %q = type %s, entries %d, flags %#x, key %d, value %d; want %s, entries %d, flags %#x, key %d, value %d", name,
				mapSpec.Type, mapSpec.MaxEntries, mapSpec.Flags, mapSpec.KeySize, mapSpec.ValueSize,
				want.mapType, want.entries, want.flags, want.keySize, want.valueSize)
		}
	}
	activeConfig := spec.Maps["active_config"]
	if activeConfig == nil || activeConfig.InnerMap == nil {
		t.Fatal("active_config is missing its inner map spec")
	}
	if inner := activeConfig.InnerMap; inner.Type != ebpf.Array || inner.Flags != 0 || inner.KeySize != 4 || inner.ValueSize != 16 || inner.MaxEntries != 1 {
		t.Fatalf("active_config inner map = type %s, flags %#x, key %d, value %d, entries %d", inner.Type, inner.Flags, inner.KeySize, inner.ValueSize, inner.MaxEntries)
	}
}
