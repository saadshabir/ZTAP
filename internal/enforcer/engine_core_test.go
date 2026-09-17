package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"ztap/internal/policy"
)

type fakePolicyStore struct {
	active       activeConfiguration
	slots        map[uint32]policy.PolicySet
	calls        []string
	callSequence *[]string
	populateErr  error
	flipErr      error
	waitErr      error
	clearErr     map[uint32]int
	closed       int
	partialWrite bool
	closeErr     error
	populateHook func()
}

func newFakePolicyStore(sequence ...*[]string) *fakePolicyStore {
	store := &fakePolicyStore{slots: make(map[uint32]policy.PolicySet), clearErr: make(map[uint32]int)}
	if len(sequence) > 0 {
		store.callSequence = sequence[0]
	}
	return store
}

func (s *fakePolicyStore) record(call string) {
	s.calls = append(s.calls, call)
	if s.callSequence != nil {
		*s.callSequence = append(*s.callSequence, call)
	}
}

func (s *fakePolicyStore) ClearSlot(slot uint32) error {
	s.record("clear:" + slotString(slot))
	if s.clearErr[slot] > 0 {
		s.clearErr[slot]--
		return errors.New("injected clear failure")
	}
	delete(s.slots, slot)
	return nil
}

func (s *fakePolicyStore) PopulateSlot(_ context.Context, slot uint32, set policy.PolicySet) error {
	s.record("populate:" + slotString(slot))
	if s.partialWrite || s.populateErr == nil {
		s.slots[slot] = clonePolicySet(set)
	}
	if s.populateHook != nil {
		s.populateHook()
	}
	return s.populateErr
}

func (s *fakePolicyStore) Flip(config activeConfiguration) error {
	s.record("flip:" + slotString(config.Slot))
	if s.flipErr != nil {
		return s.flipErr
	}
	s.active = config
	return nil
}

func (s *fakePolicyStore) WaitQuiescent(_ context.Context, slot uint32) error {
	s.record("quiescent:" + slotString(slot))
	return s.waitErr
}

func (s *fakePolicyStore) Close() error {
	s.closed++
	s.record("store-close")
	return s.closeErr
}

type fakeLinker struct {
	links        map[uint64]*fakeLink
	attachErr    map[uint64]error
	partialLinks map[uint64]io.Closer
	callSequence *[]string
}

func newFakeLinker(sequence *[]string) *fakeLinker {
	return &fakeLinker{
		links:        make(map[uint64]*fakeLink),
		attachErr:    make(map[uint64]error),
		partialLinks: make(map[uint64]io.Closer),
		callSequence: sequence,
	}
}

func (l *fakeLinker) Attach(_ context.Context, cgroupID uint64) (io.Closer, error) {
	if l.callSequence != nil {
		*l.callSequence = append(*l.callSequence, "attach:"+uintString(cgroupID))
	}
	if err := l.attachErr[cgroupID]; err != nil {
		return l.partialLinks[cgroupID], err
	}
	link := &fakeLink{cgroupID: cgroupID, callSequence: l.callSequence}
	l.links[cgroupID] = link
	return link, nil
}

type fakeLink struct {
	cgroupID     uint64
	closed       int
	closeErr     error
	callSequence *[]string
}

func (l *fakeLink) Close() error {
	l.closed++
	if l.callSequence != nil {
		*l.callSequence = append(*l.callSequence, "close-link:"+uintString(l.cgroupID))
	}
	return l.closeErr
}

func TestEngineApplyPublishesCompleteCandidateAndDetachesRemovedSubjectsAfterFlip(t *testing.T) {
	sequence := make([]string, 0)
	store := newFakePolicyStore(&sequence)
	linker := newFakeLinker(&sequence)
	engine := newEngineCore(store, linker, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if store.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("first active config = %+v", store.active)
	}
	if indexOf(sequence, "quiescent:0") < 0 {
		t.Fatalf("first commit did not retire slot 0: %v", sequence)
	}
	if linker.links[10].closed != 0 {
		t.Fatal("new subject link was closed after successful commit")
	}

	sequence = sequence[:0]
	linker.callSequence = &sequence
	if err := engine.Apply(context.Background(), testPolicySet(20)); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if store.active != (activeConfiguration{Slot: 0, PolicyEpoch: 2}) {
		t.Fatalf("second active config = %+v", store.active)
	}
	if linker.links[10].closed != 1 {
		t.Fatalf("removed subject link closed %d times, want 1", linker.links[10].closed)
	}
	if got := indexOf(sequence, "flip:0"); got < 0 {
		t.Fatalf("missing candidate flip in sequence %v", sequence)
	}
	if flip, closeOld := indexOf(sequence, "flip:0"), indexOf(sequence, "close-link:10"); closeOld <= flip {
		t.Fatalf("removed link closed before commit: %v", sequence)
	}
	if indexOf(sequence, "quiescent:1") < 0 {
		t.Fatalf("second commit did not retire slot 1: %v", sequence)
	}
	if slot := store.slots[0]; len(slot.Subjects) != 1 || slot.Subjects[0].CgroupID != 20 {
		t.Fatalf("active candidate slot was not populated: %+v", slot)
	}
	if _, exists := store.slots[1]; exists {
		t.Fatal("old slot was not garbage-collected after readers quiesced")
	}
}

func TestEngineApplyRollsBackPartialPopulationAndLinkAttachment(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	store.populateErr = errors.New("injected map write failure")
	store.partialWrite = true
	err := engine.Apply(context.Background(), testPolicySet(20))
	if err == nil || !strings.Contains(err.Error(), "injected map write failure") {
		t.Fatalf("population error = %v", err)
	}
	if store.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("failed population changed active config: %+v", store.active)
	}
	if _, exists := store.slots[0]; exists {
		t.Fatal("partially populated candidate slot was not cleared")
	}
	if linker.links[10].closed != 0 {
		t.Fatal("failed candidate disturbed the active subject link")
	}

	store.populateErr = nil
	store.partialWrite = false
	linker.attachErr[20] = errors.New("injected attach failure")
	err = engine.Apply(context.Background(), testPolicySet(20))
	if err == nil || !strings.Contains(err.Error(), "injected attach failure") {
		t.Fatalf("attach error = %v", err)
	}
	if store.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("failed attachment changed active config: %+v", store.active)
	}
	if _, exists := store.slots[0]; exists {
		t.Fatal("candidate slot remained populated after attachment failure")
	}
}

func TestEngineApplyCancellationAfterPopulationClearsCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newFakePolicyStore()
	store.populateHook = cancel
	engine := newEngineCore(store, newFakeLinker(nil), nil)

	err := engine.Apply(ctx, testPolicySet(10))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want context.Canceled", err)
	}
	if store.active != (activeConfiguration{}) {
		t.Fatalf("cancellation changed active configuration: %+v", store.active)
	}
	if len(store.slots) != 0 {
		t.Fatalf("candidate slot remained populated after cancellation: %+v", store.slots)
	}
}

func TestEngineApplyCancellationWhileWaitingForLifecycleLock(t *testing.T) {
	store := newFakePolicyStore()
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	engine.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- engine.Apply(ctx, testPolicySet(10))
	}()
	err := <-done
	engine.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting apply error = %v, want context deadline", err)
	}
	if len(store.calls) != 0 {
		t.Fatalf("waiting apply mutated store: %v", store.calls)
	}
}

func TestEngineApplyFlipFailureClosesOnlyNewLinks(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	store.flipErr = errors.New("injected config map update failure")
	err := engine.Apply(context.Background(), testPolicySet(20))
	if err == nil || !strings.Contains(err.Error(), "config map update failure") {
		t.Fatalf("flip error = %v", err)
	}
	if store.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("failed flip changed active config: %+v", store.active)
	}
	if linker.links[20].closed != 1 {
		t.Fatalf("candidate link closed %d times, want 1", linker.links[20].closed)
	}
	if linker.links[10].closed != 0 {
		t.Fatal("failed flip disturbed the prior active link")
	}
	if _, exists := store.slots[0]; exists {
		t.Fatal("candidate slot remained populated after flip failure")
	}
}

func TestEngineApplySurfacesLifecycleStatusFailureAfterCommit(t *testing.T) {
	store := &lifecycleFakeStore{fakePolicyStore: newFakePolicyStore()}
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	store.markErr = errors.New("injected status publication failure")
	err := engine.Apply(context.Background(), testPolicySet(20))
	if err == nil || !strings.Contains(err.Error(), "status publication failure") {
		t.Fatalf("lifecycle status error = %v, want wrapped publication failure", err)
	}
	if store.active != (activeConfiguration{Slot: 0, PolicyEpoch: 2}) {
		t.Fatalf("committed config = %+v, want candidate despite status failure", store.active)
	}
	if linker.links[10].closed != 1 || linker.links[20].closed != 0 {
		t.Fatalf("link lifecycle after status failure: old=%d new=%d", linker.links[10].closed, linker.links[20].closed)
	}
}

func TestEngineClosePublishesStoppingBeforeDetachingLinks(t *testing.T) {
	sequence := make([]string, 0)
	store := &lifecycleFakeStore{fakePolicyStore: newFakePolicyStore(&sequence)}
	linker := newFakeLinker(&sequence)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	sequence = sequence[:0]
	if err := engine.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if stopping, detach := indexOf(sequence, "stopping"), indexOf(sequence, "close-link:10"); stopping < 0 || detach < 0 || stopping >= detach {
		t.Fatalf("shutdown sequence = %v, want stopping before link detach", sequence)
	}
	if store.stopCalls != 1 {
		t.Fatalf("stopping lifecycle publications = %d, want 1", store.stopCalls)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if store.stopCalls != 1 {
		t.Fatalf("stopping lifecycle publications after second close = %d, want 1", store.stopCalls)
	}
}

func TestEngineApplyRetriesDeferredSlotCleanupBeforeReuse(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	store.waitErr = errors.New("packet readers did not quiesce")
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("committed policy should survive deferred cleanup: %v", err)
	}
	if engine.pendingCleanup == nil || *engine.pendingCleanup != 1 {
		t.Fatalf("pending cleanup = %v, want slot 1", engine.pendingCleanup)
	}
	committed := store.active

	store.waitErr = nil
	store.clearErr[1] = 1
	if err := engine.Apply(context.Background(), testPolicySet(10)); err == nil {
		t.Fatal("expected slot cleanup retry to fail before candidate population")
	}
	if store.active != committed {
		t.Fatalf("failed cleanup retry changed active config: %+v", store.active)
	}
	if engine.pendingCleanup == nil || *engine.pendingCleanup != 1 {
		t.Fatalf("pending cleanup lost after retry failure: %v", engine.pendingCleanup)
	}

	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("apply after cleanup succeeds: %v", err)
	}
	if engine.pendingCleanup != nil {
		t.Fatalf("pending cleanup remained after successful reuse: %v", engine.pendingCleanup)
	}
}

func TestEngineApplyDefersInactiveSlotCleanupFailure(t *testing.T) {
	store := newFakePolicyStore()
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	// Slot zero is the next candidate after the first commit. A failed clear
	// must block population and remain scheduled for retry on the next apply.
	store.clearErr[0] = 1
	if err := engine.Apply(context.Background(), testPolicySet(20)); err == nil || !strings.Contains(err.Error(), "clear inactive policy slot 0") {
		t.Fatalf("inactive-slot cleanup error = %v, want clear failure", err)
	}
	if engine.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("failed inactive-slot cleanup changed active config: %+v", engine.active)
	}
	if engine.pendingCleanup == nil || *engine.pendingCleanup != 0 {
		t.Fatalf("pending cleanup = %v, want slot 0", engine.pendingCleanup)
	}
	if engine.slotCleanupFailures != 1 {
		t.Fatalf("slot cleanup failures = %d, want 1", engine.slotCleanupFailures)
	}

	if err := engine.Apply(context.Background(), testPolicySet(20)); err != nil {
		t.Fatalf("apply after deferred inactive-slot cleanup: %v", err)
	}
	if engine.pendingCleanup != nil {
		t.Fatalf("pending cleanup remained after retry: %v", engine.pendingCleanup)
	}
}

func TestEngineApplyRejectsInvalidInputAndEpochWrapBeforeMutation(t *testing.T) {
	store := newFakePolicyStore()
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	invalid := testPolicySet(10)
	invalid.NodeIPs = nil
	if err := engine.Apply(context.Background(), invalid); err == nil {
		t.Fatal("expected invalid policy set to be rejected")
	}
	if len(store.calls) != 0 {
		t.Fatalf("invalid input mutated engine state: %v", store.calls)
	}

	engine.active.PolicyEpoch = math.MaxUint64
	if err := engine.Apply(context.Background(), testPolicySet(10)); err == nil || !strings.Contains(err.Error(), "epoch exhausted") {
		t.Fatalf("epoch exhaustion error = %v", err)
	}
	if len(store.calls) != 0 {
		t.Fatalf("epoch overflow mutated engine state: %v", store.calls)
	}
}

func TestEngineCloseIsIdempotentAndClosesOwnedResources(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if store.closed != 1 || linker.links[10].closed != 1 {
		t.Fatalf("close counts: store=%d links=%d", store.closed, linker.links[10].closed)
	}
	if err := engine.Apply(context.Background(), testPolicySet(10)); err == nil {
		t.Fatal("apply after close should fail")
	}
}

func TestEngineApplyRetriesCleanupOfPartialAttachBeforeNextCandidate(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	partial := &retryingFakeCloser{failures: 1}
	linker.attachErr[20] = errors.New("ingress attach failed")
	linker.partialLinks[20] = partial
	err := engine.Apply(context.Background(), testPolicySet(20))
	if err == nil || !strings.Contains(err.Error(), "ingress attach failed") {
		t.Fatalf("partial attach error = %v", err)
	}
	if partial.attempts != 1 || len(engine.orphanLinks[20]) != 1 {
		t.Fatalf("partial attach cleanup attempts=%d orphans=%v", partial.attempts, engine.orphanLinks)
	}
	if store.active != (activeConfiguration{Slot: 1, PolicyEpoch: 1}) {
		t.Fatalf("failed partial attach changed active config: %+v", store.active)
	}

	delete(linker.attachErr, 20)
	delete(linker.partialLinks, 20)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("apply after partial-link cleanup recovers: %v", err)
	}
	if partial.attempts != 2 || len(engine.orphanLinks) != 0 {
		t.Fatalf("partial link was not cleaned on retry: attempts=%d orphans=%v", partial.attempts, engine.orphanLinks)
	}
}

func TestEngineReattachesAfterRemovedLinkCloseFailure(t *testing.T) {
	store := newFakePolicyStore()
	linker := newFakeLinker(nil)
	engine := newEngineCore(store, linker, nil)
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	oldLink := linker.links[10]
	oldLink.closeErr = errors.New("injected detach failure")

	if err := engine.Apply(context.Background(), testPolicySet(20)); err != nil {
		t.Fatalf("remove cgroup with deferred detach: %v", err)
	}
	if _, exists := engine.links[10]; exists {
		t.Fatal("removed cgroup link remained eligible for reuse")
	}
	if len(engine.orphanLinks[10]) != 1 {
		t.Fatalf("orphaned links for cgroup 10 = %v, want one", engine.orphanLinks[10])
	}

	oldLink.closeErr = nil
	if err := engine.Apply(context.Background(), testPolicySet(10)); err != nil {
		t.Fatalf("re-add cgroup after detach retry: %v", err)
	}
	if linker.links[10] == oldLink {
		t.Fatal("re-added cgroup reused a link pair that had failed to detach")
	}
	if oldLink.closed != 2 || len(engine.orphanLinks) != 0 {
		t.Fatalf("old link close attempts=%d, remaining orphans=%v", oldLink.closed, engine.orphanLinks)
	}
}

func TestEngineCloseRetriesStoreCloseFailure(t *testing.T) {
	store := newFakePolicyStore()
	engine := newEngineCore(store, newFakeLinker(nil), nil)
	store.closeErr = errors.New("injected store close failure")
	if err := engine.Close(); err == nil || !strings.Contains(err.Error(), "store close failure") {
		t.Fatalf("first close error = %v", err)
	}
	if store.closed != 1 {
		t.Fatalf("store close attempts = %d, want 1", store.closed)
	}

	store.closeErr = nil
	if err := engine.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("idempotent close after success: %v", err)
	}
	if store.closed != 2 {
		t.Fatalf("store close attempts = %d, want 2", store.closed)
	}
}

type retryingFakeCloser struct {
	attempts int
	failures int
}

type lifecycleFakeStore struct {
	*fakePolicyStore
	markErr   error
	markCalls int
	stopErr   error
	stopCalls int
}

func (s *lifecycleFakeStore) MarkEnforcing() error {
	s.markCalls++
	return s.markErr
}

func (s *lifecycleFakeStore) MarkStopping() error {
	s.stopCalls++
	s.record("stopping")
	return s.stopErr
}

func (c *retryingFakeCloser) Close() error {
	c.attempts++
	if c.attempts <= c.failures {
		return errors.New("injected close failure")
	}
	return nil
}

func testPolicySet(cgroupID uint64) policy.PolicySet {
	return policy.PolicySet{
		NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Subjects: []policy.Subject{{
			CgroupID: cgroupID,
			Isolated: policy.DirectionEgress | policy.DirectionIngress,
			PodIPs:   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		}},
		Rules: []policy.Rule{{
			CgroupID:  cgroupID,
			Direction: policy.DirectionEgress,
			Peer:      netip.MustParsePrefix("198.51.100.0/24"),
			Protocol:  policy.ProtocolTCP,
			Port:      443,
		}},
	}
}

func slotString(slot uint32) string {
	if slot == 0 {
		return "0"
	}
	return "1"
}

func uintString(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func indexOf(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return -1
}
