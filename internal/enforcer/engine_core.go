package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/saadshabir/ZTAP/internal/policy"
)

const slotQuiescenceTimeout = 5 * time.Second

type activeConfiguration struct {
	Slot        uint32
	PolicyEpoch uint64
}

type enginePolicyStore interface {
	ClearSlot(uint32) error
	// PopulateSlot accepts a normalized snapshot encoded for slot zero.
	PopulateSlot(context.Context, uint32, encodedPolicySet) error
	Flip(activeConfiguration) error
	WaitQuiescent(context.Context, uint32) error
	Close() error
}

type subjectLinker interface {
	Attach(context.Context, uint64) (io.Closer, error)
}

type engineCore struct {
	mu                  sync.Mutex
	store               enginePolicyStore
	linker              subjectLinker
	logger              *slog.Logger
	active              activeConfiguration
	applied             encodedPolicySet
	hasApplied          bool
	links               map[uint64]io.Closer
	orphanLinks         map[uint64][]io.Closer
	pendingCleanup      *uint32
	slotCleanupFailures uint64
	closed              bool
	storeClosed         bool
}

func newEngineCore(store enginePolicyStore, linker subjectLinker, logger *slog.Logger) *engineCore {
	if logger == nil {
		logger = slog.Default()
	}
	return &engineCore{
		store:       store,
		linker:      linker,
		logger:      logger,
		links:       make(map[uint64]io.Closer),
		orphanLinks: make(map[uint64][]io.Closer),
		active:      activeConfiguration{Slot: 0, PolicyEpoch: 0},
	}
}

func (e *engineCore) Apply(ctx context.Context, desired policy.PolicySet) error {
	return e.ApplyWithPolicyEpoch(ctx, desired, nil)
}

// ApplyWithPolicyEpoch lets a caller publish metadata atomically with the
// slot flip. The callback must call and return commit's result. A nil commit
// means the validated snapshot already matches the active policy epoch.
func (e *engineCore) ApplyWithPolicyEpoch(ctx context.Context, desired policy.PolicySet, publish func(epoch uint64, commit func() error) error) error {
	if ctx == nil {
		return errors.New("apply context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Normalize once for comparison, identity validation, and population.
	// Keep these keys encoded for slot zero so equality is independent of the
	// active slot, including when the committed contents came from recovery.
	encoded, err := encodePolicySet(0, desired)
	if err != nil {
		return err
	}

	if err := lockEngineMutex(ctx, &e.mu); err != nil {
		return err
	}
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("eBPF engine is closed")
	}
	// Identity uncertainty rejects the whole transaction, including the no-op
	// path. A synchronized informer cache may still omit a live container.
	if validator, ok := e.store.(interface {
		ValidateCandidate(context.Context, encodedPolicySet) error
	}); ok {
		if err := validator.ValidateCandidate(ctx, encoded); err != nil {
			return fmt.Errorf("preserve committed enforcement: %w", err)
		}
	}
	if e.pendingCleanup != nil {
		if err := e.reclaimPendingSlot(ctx, 1-e.active.Slot); err != nil {
			return err
		}
	}
	if err := e.retryOrphanLinks(); err != nil {
		return fmt.Errorf("retry cleanup of candidate cgroup links: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.active.Slot > 1 {
		return fmt.Errorf("invalid active policy slot %d", e.active.Slot)
	}
	if e.hasApplied && equalEncodedPolicySets(e.applied, encoded) {
		if err := e.reclaimPendingSlot(ctx, 1-e.active.Slot); err != nil {
			return err
		}
		e.closeRemovedLinks(encoded.Subjects)
		if publish != nil {
			if err := publish(e.active.PolicyEpoch, nil); err != nil {
				return err
			}
		}
		return e.markEnforcing()
	}
	if e.active.PolicyEpoch == math.MaxUint64 {
		return errors.New("policy epoch exhausted")
	}

	candidate := activeConfiguration{
		Slot:        1 - e.active.Slot,
		PolicyEpoch: e.active.PolicyEpoch + 1,
	}
	if err := e.reclaimPendingSlot(ctx, candidate.Slot); err != nil {
		return err
	}
	if err := e.store.ClearSlot(candidate.Slot); err != nil {
		e.slotCleanupFailures++
		e.pendingCleanup = slotPointer(candidate.Slot)
		return fmt.Errorf("clear inactive policy slot %d: %w", candidate.Slot, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.store.PopulateSlot(ctx, candidate.Slot, encoded); err != nil {
		cleanupErr := e.store.ClearSlot(candidate.Slot)
		if cleanupErr != nil {
			e.slotCleanupFailures++
			e.logger.Warn("failed to clear partially populated policy slot", "slot", candidate.Slot, "error", cleanupErr)
			e.pendingCleanup = slotPointer(candidate.Slot)
		}
		return errors.Join(fmt.Errorf("populate inactive policy slot %d: %w", candidate.Slot, err),
			wrapCleanupError(candidate.Slot, cleanupErr))
	}
	if err := ctx.Err(); err != nil {
		return e.rollbackCandidate(candidate.Slot, nil, err)
	}
	e.observeCheckpoint("inactive-slot-populated")

	newLinks := make(map[uint64]io.Closer)
	for _, subject := range encoded.Subjects {
		cgroupID := subject.Key.CgroupID
		if _, exists := e.links[cgroupID]; exists {
			continue
		}
		if err := ctx.Err(); err != nil {
			return e.rollbackCandidate(candidate.Slot, newLinks, err)
		}
		link, err := e.linker.Attach(ctx, cgroupID)
		if err != nil {
			if link != nil {
				if closeErr := removeSubjectLink(link); closeErr != nil {
					e.orphanLinks[cgroupID] = append(e.orphanLinks[cgroupID], link)
					err = errors.Join(err, fmt.Errorf("close partial link: %w", closeErr))
				}
			}
			return e.rollbackCandidate(candidate.Slot, newLinks,
				fmt.Errorf("attach policy programs to cgroup %d: %w", cgroupID, err))
		}
		if link == nil {
			return e.rollbackCandidate(candidate.Slot, newLinks,
				fmt.Errorf("attach policy programs to cgroup %d: linker returned no link", cgroupID))
		}
		newLinks[cgroupID] = link
	}

	if err := ctx.Err(); err != nil {
		return e.rollbackCandidate(candidate.Slot, newLinks, err)
	}
	e.observeCheckpoint("candidate-links-pinned")
	var flipErr error
	if publish == nil {
		flipErr = e.store.Flip(candidate)
	} else {
		flipErr = publish(candidate.PolicyEpoch, func() error { return e.store.Flip(candidate) })
	}
	if flipErr != nil {
		return e.rollbackCandidate(candidate.Slot, newLinks,
			fmt.Errorf("commit active slot %d at epoch %d: %w", candidate.Slot, candidate.PolicyEpoch, flipErr))
	}
	e.observeCheckpoint("active-config-committed")

	old := e.active
	e.active = candidate
	e.applied = encoded
	e.hasApplied = true
	// Cache the committed contents even if lifecycle publication fails. A retry
	// must publish readiness without invalidating established reply state.
	statusErr := e.markEnforcing()
	for cgroupID, link := range newLinks {
		e.links[cgroupID] = link
	}
	e.closeRemovedLinks(encoded.Subjects)
	e.reclaimCommittedSlot(old.Slot)
	if statusErr != nil {
		return statusErr
	}
	return nil
}

func equalEncodedPolicySets(a, b encodedPolicySet) bool {
	return slices.Equal(a.Subjects, b.Subjects) && slices.Equal(a.Nodes, b.Nodes) &&
		slices.Equal(a.Self, b.Self) && slices.Equal(a.Rules, b.Rules) && slices.Equal(a.Classified, b.Classified)
}

func (e *engineCore) markEnforcing() error {
	if lifecycle, ok := e.store.(interface{ MarkEnforcing() error }); ok {
		if err := lifecycle.MarkEnforcing(); err != nil {
			return fmt.Errorf("publish enforcing lifecycle status: %w", err)
		}
	}
	return nil
}

func (e *engineCore) observeCheckpoint(name string) {
	if observer, ok := e.store.(interface{ ObserveCheckpoint(string) }); ok {
		observer.ObserveCheckpoint(name)
	}
}

func lockEngineMutex(ctx context.Context, mu *sync.Mutex) error {
	if mu == nil {
		return errors.New("engine mutex is nil")
	}
	if mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *engineCore) reclaimPendingSlot(ctx context.Context, candidateSlot uint32) error {
	if e.pendingCleanup == nil {
		return nil
	}
	if *e.pendingCleanup != candidateSlot {
		return fmt.Errorf("pending cleanup for policy slot %d conflicts with candidate slot %d", *e.pendingCleanup, candidateSlot)
	}
	if err := e.store.WaitQuiescent(ctx, candidateSlot); err != nil {
		e.slotCleanupFailures++
		return fmt.Errorf("wait for packet readers before reusing policy slot %d: %w", candidateSlot, err)
	}
	if err := e.store.ClearSlot(candidateSlot); err != nil {
		e.slotCleanupFailures++
		return fmt.Errorf("retry cleanup of policy slot %d: %w", candidateSlot, err)
	}
	e.pendingCleanup = nil
	return nil
}

func (e *engineCore) rollbackCandidate(slot uint32, newLinks map[uint64]io.Closer, cause error) error {
	var rollbackErrors []error
	for cgroupID, link := range newLinks {
		if err := removeSubjectLink(link); err != nil {
			// Keep ownership separately from active links. A failed candidate may
			// have only one direction attached and must never be reused as active.
			e.orphanLinks[cgroupID] = append(e.orphanLinks[cgroupID], link)
			rollbackErrors = append(rollbackErrors, fmt.Errorf("close candidate link for cgroup %d: %w", cgroupID, err))
		}
	}
	if err := e.store.ClearSlot(slot); err != nil {
		e.slotCleanupFailures++
		e.pendingCleanup = slotPointer(slot)
		rollbackErrors = append(rollbackErrors, fmt.Errorf("clear candidate slot %d: %w", slot, err))
	}
	return errors.Join(append([]error{cause}, rollbackErrors...)...)
}

func (e *engineCore) retryOrphanLinks() error {
	var closeErrors []error
	for cgroupID, links := range e.orphanLinks {
		remaining := links[:0]
		for _, link := range links {
			if err := removeSubjectLink(link); err != nil {
				remaining = append(remaining, link)
				closeErrors = append(closeErrors, fmt.Errorf("close candidate link for cgroup %d: %w", cgroupID, err))
			}
		}
		if len(remaining) == 0 {
			delete(e.orphanLinks, cgroupID)
		} else {
			e.orphanLinks[cgroupID] = remaining
		}
	}
	return errors.Join(closeErrors...)
}

func (e *engineCore) closeRemovedLinks(subjects []encodedSubjectState) {
	desired := make(map[uint64]struct{}, len(subjects))
	for _, subject := range subjects {
		desired[subject.Key.CgroupID] = struct{}{}
	}
	for cgroupID, link := range e.links {
		if _, keep := desired[cgroupID]; keep {
			continue
		}
		if err := removeSubjectLink(link); err != nil {
			e.logger.Warn("failed to detach removed subject cgroup", "cgroup_id", cgroupID, "error", err)
			// The committed policy no longer selects this cgroup. Keep any
			// partially detached link separate so a future Apply retries it
			// before attaching a fresh pair for the same cgroup.
			e.orphanLinks[cgroupID] = append(e.orphanLinks[cgroupID], link)
			delete(e.links, cgroupID)
			continue
		}
		delete(e.links, cgroupID)
	}
}

func (e *engineCore) reclaimCommittedSlot(slot uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), slotQuiescenceTimeout)
	defer cancel()
	if err := e.store.WaitQuiescent(ctx, slot); err != nil {
		e.pendingCleanup = slotPointer(slot)
		e.slotCleanupFailures++
		e.logger.Warn("policy slot cleanup deferred until packet readers quiesce", "slot", slot, "error", err)
		return
	}
	e.observeCheckpoint("retired-slot-cleanup-started")
	if err := e.store.ClearSlot(slot); err != nil {
		e.pendingCleanup = slotPointer(slot)
		e.slotCleanupFailures++
		e.logger.Warn("policy slot cleanup failed; it will be retried before the next apply", "slot", slot, "error", err)
		return
	}
	e.observeCheckpoint("retired-slot-cleared")
	e.pendingCleanup = nil
}

func (e *engineCore) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true

	var closeErrors []error
	if !e.storeClosed {
		if lifecycle, ok := e.store.(interface{ MarkStopping() error }); ok {
			// This is controller lifecycle only. Pinned enforcement survives
			// release of every local descriptor, including on startup failure.
			if err := lifecycle.MarkStopping(); err != nil {
				closeErrors = append(closeErrors, fmt.Errorf("publish stopping lifecycle status: %w", err))
			}
		}
	}
	for cgroupID, link := range e.links {
		if err := link.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close cgroup %d links: %w", cgroupID, err))
			continue
		}
		delete(e.links, cgroupID)
	}
	for cgroupID, links := range e.orphanLinks {
		remaining := links[:0]
		for _, link := range links {
			if err := link.Close(); err != nil {
				remaining = append(remaining, link)
				closeErrors = append(closeErrors, fmt.Errorf("close candidate cgroup %d link: %w", cgroupID, err))
			}
		}
		if len(remaining) == 0 {
			delete(e.orphanLinks, cgroupID)
		} else {
			e.orphanLinks[cgroupID] = remaining
		}
	}
	// Keep the collection alive when any attachment is still owned. A later
	// Close call can retry detachment before releasing the programs and maps.
	if len(e.links) == 0 && len(e.orphanLinks) == 0 && !e.storeClosed {
		if err := e.store.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			e.storeClosed = true
		}
	}
	return errors.Join(closeErrors...)
}

// Close releases a local handle. Remove is reserved for an uncommitted
// candidate or an obsolete subject after the authoritative kernel commit.
func removeSubjectLink(handle io.Closer) error {
	if removable, ok := handle.(interface{ Remove() error }); ok {
		return removable.Remove()
	}
	return handle.Close()
}

func (e *engineCore) recover(active activeConfiguration, encoded encodedPolicySet, links map[uint64]io.Closer) error {
	if active.Slot > 1 {
		return fmt.Errorf("invalid recovered policy slot %d", active.Slot)
	}
	for _, subject := range encoded.Subjects {
		if links[subject.Key.CgroupID] == nil {
			return fmt.Errorf("committed cgroup %d has no verified directional links", subject.Key.CgroupID)
		}
	}
	e.active = active
	e.applied = encoded
	e.hasApplied = active.PolicyEpoch != 0
	e.links = links
	// Even an apparently empty retired slot may have readers from a crash
	// immediately following a flip. Never reset its packet-reader counters.
	e.pendingCleanup = slotPointer(1 - active.Slot)
	return nil
}

func slotPointer(slot uint32) *uint32 {
	return &slot
}

func wrapCleanupError(slot uint32, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("clear partially populated policy slot %d: %w", slot, err)
}
