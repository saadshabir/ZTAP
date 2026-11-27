//go:build linux

package cli

import (
	"context"
	"sync"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/flow"
	"github.com/saadshabir/ZTAP/internal/policy"
	"github.com/saadshabir/ZTAP/internal/telemetry"
)

const flowIdentityEpochs = 8

type flowAttributingEngine struct {
	*enforcer.LinuxEngine
	history  *flowDecisionHistory
	subjects map[uint64]telemetry.PodIdentity
}

func (e flowAttributingEngine) Apply(ctx context.Context, desired policy.PolicySet) error {
	return e.ApplyWithPolicyEpoch(ctx, desired, func(epoch uint64, flip func() error) error {
		return e.history.publish(epoch, flip, e.subjects)
	})
}

// All subjects in this index belong to this agent's node. The snapshot joins
// the exact Pod UID with its validated container cgroup during reconciliation.
func flowSubjects(pods []policy.ResolvedPod) map[uint64]telemetry.PodIdentity {
	subjects := make(map[uint64]telemetry.PodIdentity)
	for _, pod := range pods {
		if !pod.Local || pod.HostNetwork || pod.UID == "" {
			continue
		}
		for _, id := range pod.CgroupIDs {
			subjects[id] = telemetry.PodIdentity{UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name}
		}
	}
	return subjects
}

type flowDecisionHistory struct {
	mu     sync.RWMutex
	epochs [flowIdentityEpochs]flowIdentityEpoch
	next   int
}

type flowIdentityEpoch struct {
	epoch    uint64
	afterNS  uint64
	subjects map[uint64]telemetry.PodIdentity
}

func (h *flowDecisionHistory) publish(epoch uint64, flip func() error, subjects map[uint64]telemetry.PodIdentity) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var cutoff uint64
	if flip != nil {
		// Ring records bearing the new epoch can arrive during the syscall.
		// Hold only the attribution lock across the flip and publication.
		if err := flip(); err != nil {
			return err
		}
	} else {
		for _, known := range h.epochs {
			if known.epoch == epoch {
				return nil
			}
		}
		// A recovered epoch may have unread records from an earlier agent.
		// Only observations made after validating the current snapshot can
		// use its recovered-epoch metadata.
		var err error
		cutoff, err = monotonicNowNS()
		if err != nil {
			return nil
		}
	}
	h.epochs[h.next] = flowIdentityEpoch{epoch: epoch, afterNS: cutoff, subjects: subjects}
	h.next = (h.next + 1) % len(h.epochs)
	return nil
}

func (h *flowDecisionHistory) subject(event flow.FlowEvent) telemetry.PodIdentity {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, known := range h.epochs {
		if known.epoch == event.PolicyEpoch && event.KernelTimeNS > known.afterNS {
			return known.subjects[event.CgroupID]
		}
	}
	return telemetry.PodIdentity{}
}
