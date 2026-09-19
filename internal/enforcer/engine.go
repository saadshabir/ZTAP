package enforcer

import (
	"context"
	"log/slog"

	"github.com/saadshabir/ZTAP/internal/policy"
)

// Agent status ABI constants are shared by the engine and readers of its
// stable status pin. Keep the wire values explicit because they are persisted
// in bpffs while the agent is running.
const (
	AgentStatusSchemaVersion  uint32 = 1
	AgentLifecycleStarting    uint32 = 1
	AgentLifecycleEnforcing   uint32 = 2
	AgentLifecycleStopping    uint32 = 3
	DefaultFlowEventsPinPath         = "/sys/fs/bpf/ztap/flow_events"
	DefaultAgentStatusPinPath        = "/sys/fs/bpf/ztap/agent_status"
)

// Engine applies complete, kernel-neutral policy snapshots to one node.
// Implementations own their programs, maps, links, and cleanup lifecycle.
type Engine interface {
	Apply(context.Context, policy.PolicySet) error
	Close() error
}

// EngineMetricsSnapshot is the bounded, process-owned observability surface
// exposed by engines that can read their persistent kernel counters. Decision
// and drop counters are cumulative for the engine lifetime; callers may
// publish them directly as Prometheus counters.
type EngineMetricsSnapshot struct {
	ActivePolicyEpoch   uint64
	Decisions           []EngineDecisionMetric
	EventDrops          []EngineEventDropMetric
	SlotCleanupFailures uint64
}

type EngineDecisionMetric struct {
	Action    string
	Direction string
	Reason    string
	Count     uint64
}

type EngineEventDropMetric struct {
	Reason string
	Count  uint64
}

// MetricsProvider is optional so dry-run and non-Linux engines can implement
// the Engine contract without pretending to have kernel counters.
type MetricsProvider interface {
	MetricsSnapshot(context.Context) (EngineMetricsSnapshot, error)
}

// CgroupPathResolver resolves the filesystem path corresponding to a kernel
// cgroup ID. The caller owns the resolver and may back it with a cache.
type CgroupPathResolver func(context.Context, uint64) (string, error)

// LinuxEngineOptions contains the operating-system resources required by the
// Linux eBPF engine. The caller must hold the node's agent lock before removing
// stale pins or constructing an engine.
type LinuxEngineOptions struct {
	CgroupRoot        string
	BPFFSRoot         string
	ResolveCgroupPath CgroupPathResolver
	AgentEpoch        uint64
	Logger            *slog.Logger
}
