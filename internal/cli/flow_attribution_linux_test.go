//go:build linux

package cli

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/saadshabir/ZTAP/internal/flow"
	"github.com/saadshabir/ZTAP/internal/policy"
	"github.com/saadshabir/ZTAP/internal/telemetry"
)

func TestFlowAttributionKeepsCommittedPodWithDelayedEvent(t *testing.T) {
	history := &flowDecisionHistory{}
	pod := func(uid string) map[uint64]telemetry.PodIdentity {
		return flowSubjects([]policy.ResolvedPod{{Name: "pod", Namespace: "fixtures", UID: uid,
			PodIPs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}, CgroupIDs: []uint64{41}, Local: true}})
	}
	old, replacement := pod("old"), pod("replacement")
	apply := func() error { return nil }
	if err := history.publish(5, apply, old); err != nil {
		t.Fatal(err)
	}
	flipErr := errors.New("flip failed")
	if err := history.publish(6, func() error { return flipErr }, replacement); !errors.Is(err, flipErr) {
		t.Fatalf("publish error = %v, want flip failure", err)
	}
	requireFlowUID(t, history, 6, 1, "")
	if err := history.publish(6, apply, replacement); err != nil {
		t.Fatal(err)
	}
	if err := history.publish(5, nil, replacement); err != nil {
		t.Fatal(err)
	}
	requireFlowUID(t, history, 5, 1, "old")
	requireFlowUID(t, history, 6, 1, "replacement")
	for epoch := uint64(7); epoch < 7+flowIdentityEpochs; epoch++ {
		if err := history.publish(epoch, apply, replacement); err != nil {
			t.Fatal(err)
		}
	}
	requireFlowUID(t, history, 5, 1, "")
}

func TestRecoveredFlowEpochExcludesOldRingRecords(t *testing.T) {
	before, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	history := &flowDecisionHistory{}
	if err := history.publish(5, nil, map[uint64]telemetry.PodIdentity{41: {UID: "current"}}); err != nil {
		t.Fatal(err)
	}
	after, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	requireFlowUID(t, history, 5, before, "")
	requireFlowUID(t, history, 5, after+1, "current")
	requireFlowUID(t, history, 4, after+1, "")
}

func requireFlowUID(t *testing.T, history *flowDecisionHistory, epoch, ns uint64, want string) {
	t.Helper()
	if got := history.subject(flow.FlowEvent{PolicyEpoch: epoch, CgroupID: 41, KernelTimeNS: ns}).UID; got != want {
		t.Errorf("epoch %d at %d: subject = %q, want %q", epoch, ns, got, want)
	}
}

func TestFlowNamespaceExclusionsAfterRecovery(t *testing.T) {
	history := &flowDecisionHistory{}
	subject := telemetry.PodIdentity{UID: "agent-pod", Namespace: "ztap-system"}
	before, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	if err := history.publish(5, nil, map[uint64]telemetry.PodIdentity{41: subject}); err != nil {
		t.Fatal(err)
	}
	buffered := history.subject(flow.FlowEvent{PolicyEpoch: 5, CgroupID: 41, KernelTimeNS: before})
	exclusions := []string{subject.Namespace}
	if !excludeFlowSubject(buffered, exclusions) || !excludeFlowSubject(subject, exclusions) {
		t.Fatal("namespace filter must omit both unresolved and excluded subjects")
	}
	if excludeFlowSubject(buffered, nil) || excludeFlowSubject(subject, []string{"another-namespace"}) {
		t.Fatal("unexpectedly excluded an eligible record")
	}
}
