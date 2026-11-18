package enforcer

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/saadshabir/ZTAP/internal/policy"
)

type preservingTestLink struct{ released, removed int }

func (l *preservingTestLink) Close() error  { l.released++; return nil }
func (l *preservingTestLink) Remove() error { l.removed++; return l.Close() }

type guardedTestStore struct {
	*fakePolicyStore
	identityErr error
}

func (s *guardedTestStore) ValidateCandidate(context.Context, encodedPolicySet) error {
	return s.identityErr
}

func TestRecoveredEnginePreservesEpochForIdenticalSnapshot(t *testing.T) {
	set := testPolicySet(10)
	encoded, err := encodePolicySet(0, set)
	if err != nil {
		t.Fatal(err)
	}
	active := activeConfiguration{Slot: 1, PolicyEpoch: 42}
	store := newFakePolicyStore()
	store.active = active
	store.slots[1] = encoded
	handle := &preservingTestLink{}
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.recover(active, encoded, map[uint64]io.Closer{10: handle}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if store.active != active || len(linker.links) != 0 || handle.removed != 0 {
		t.Fatalf("unchanged recovery changed enforcement: config=%+v links=%d removals=%d", store.active, len(linker.links), handle.removed)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if handle.released != 1 || handle.removed != 0 {
		t.Fatalf("close removed pinned enforcement: %+v", handle)
	}
}

func TestRecoveredEngineDefersEntireSnapshotWhileIdentityIsUncertain(t *testing.T) {
	for _, state := range []string{"container-id-missing", "container-pending", "pod-missing", "identity-inconsistent"} {
		t.Run(state, func(t *testing.T) {
			set := testPolicySet(10)
			unisolated := policy.PolicySet{NodeIPs: set.NodeIPs}
			encoded, err := encodePolicySet(0, set)
			if err != nil {
				t.Fatal(err)
			}
			store := &guardedTestStore{fakePolicyStore: newFakePolicyStore(), identityErr: errors.New(state)}
			active := activeConfiguration{Slot: 1, PolicyEpoch: 27}
			store.active = active
			store.slots[1] = encoded
			handle := &preservingTestLink{}
			engine := newEngineCore(store, newFakeLinker(nil), nil)
			if err := engine.recover(active, encoded, map[uint64]io.Closer{10: handle}); err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []policy.PolicySet{unisolated, set, testPolicySet(20)} {
				if err := engine.Apply(context.Background(), candidate); err == nil {
					t.Fatal("accepted uncertain candidate")
				}
				if store.active != active || len(store.calls) != 0 || handle.removed != 0 {
					t.Fatalf("uncertainty mutated committed state: config=%+v calls=%v", store.active, store.calls)
				}
			}
			store.identityErr = nil
			if err := engine.Apply(context.Background(), unisolated); err != nil {
				t.Fatal(err)
			}
			if store.active.PolicyEpoch != 28 || handle.removed != 1 {
				t.Fatalf("resolved unisolated identity did not allow cleanup: config=%+v link=%+v", store.active, handle)
			}
		})
	}
}

func TestRecoveredEngineWaitsForRetiredReadersBeforeMutation(t *testing.T) {
	set := testPolicySet(10)
	encoded, err := encodePolicySet(0, set)
	if err != nil {
		t.Fatal(err)
	}
	store := newFakePolicyStore()
	store.waitErr = errors.New("retired packet reader still active")
	active := activeConfiguration{Slot: 0, PolicyEpoch: 8}
	store.active = active
	handle := &preservingTestLink{}
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	if err := engine.recover(active, encoded, map[uint64]io.Closer{10: handle}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), testPolicySet(20)); err == nil {
		t.Fatal("reused slot while retired reader was active")
	}
	if store.active != active || len(store.calls) != 1 || store.calls[0] != "quiescent:1" || handle.removed != 0 {
		t.Fatalf("unsafe recovered cleanup: calls=%v config=%+v", store.calls, store.active)
	}
}

func TestRecoveryRejectsMissingCommittedLinkWithoutMutation(t *testing.T) {
	encoded, err := encodePolicySet(0, testPolicySet(10))
	if err != nil {
		t.Fatal(err)
	}
	store := newFakePolicyStore()
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	if err := engine.recover(activeConfiguration{Slot: 1, PolicyEpoch: 9}, encoded, map[uint64]io.Closer{}); err == nil {
		t.Fatal("adopted missing committed link")
	}
	if len(store.calls) != 0 || engine.hasApplied {
		t.Fatal("failed recovery changed state")
	}
}
