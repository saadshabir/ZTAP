// Command phase5verify validates the raw JSON evidence emitted by the Linux
// Phase 5 performance harness. It intentionally checks only the documented
// fixture shape, sample counts, measurement validity, budgets, and accounting
// invariants; it does not manufacture or reinterpret measurements.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

const (
	referenceSubjects        = 250
	referencePolicies        = 25
	referenceRules           = 2500
	referenceCPUs            = 2
	repeatedSamples          = 3
	flowRate                 = 1000
	flowSeconds              = 60
	flowMaxSeconds           = flowSeconds + 5
	packetRoundTrips         = 1000
	packetTCPBytes           = 128 << 20
	applyBudgetMS            = 2000
	latencyBudgetUS          = 10
	throughputBudget         = 10
	activationBudget         = 3000
	reconcileBudget          = 2000
	eventBudget              = 3000
	cpuBudgetCores           = 0.10
	rssBudgetMiB             = 200
	flowTrafficPattern       = "one alternating allowed/blocked UDP decision per millisecond"
	referenceKernelPathScope = "real cgroup creation, eBPF map population, policy flip, and cgroup link attachment"
	flowScope                = "full 250-subject/2,500-rule real-cgroup fixture with one selected subject generating alternating allowed/blocked UDP decisions"
	packetScope              = "full 250-subject/2,500-rule real-cgroup fixture with loopback UDP round trips and TCP transfers from one selected subject, cgroup eBPF detached versus attached"
	activationScope          = "fake Kubernetes informer cache, exact containerd systemd cgroup resolution, native compilation, and real engine apply"
	reconciliationScope      = "actual native agent compile-and-apply reconciliation after synchronized fake informer cache sync; excludes Kubernetes list latency and fixed dirty-event debounce"
	eventScope               = "synchronized fake Kubernetes informer event, fixed debounce, native compilation, and real engine apply"
	podStartScope            = "new running Pod added to a synchronized fake informer cache with a pre-created exact containerd systemd cgroup; excludes API-server and container-runtime startup"
	restartScope             = "orderly process-owned engine shutdown followed by replacement startup and initial native policy apply; crash and DaemonSet rollout are excluded"
	crashScope               = "SIGKILL of a child process owning the real engine links after applying the full 250-Pod/25-policy/2,500-rule fixture, followed by an allowed UDP sender in one selected cgroup; Kubernetes restart scheduling and DaemonSet rollout are excluded"
	resourceScope            = "dedicated helper process running the native agent with a fake Kubernetes client and the 250-Pod/25-policy/2,500-rule fixture; kernel-map memory is excluded"
	maxEvidenceJSONDepth     = 128
	maxHostedYAMLDepth       = 128
	maxEnvironmentBytes      = 1 << 20
	hostedAgentNamespace     = "ztap-system"
)

var referenceMapMemoryStages = [...]string{
	"before_warmup",
	"after_warmup",
	"after_apply_1",
	"after_apply_2",
	"after_apply_3",
}

type phase5JSONArtifactSpec struct {
	name      string
	newOutput func() any
}

var phase5JSONArtifactSpecs = [...]phase5JSONArtifactSpec{
	{name: "phase5-performance.json", newOutput: func() any { return new(referenceEvidence) }},
	{name: "phase5-flow.json", newOutput: func() any { return new(flowEvidence) }},
	{name: "phase5-packet.json", newOutput: func() any { return new(packetEvidence) }},
	{name: "phase5-agent.json", newOutput: func() any { return new(activationEvidence) }},
	{name: "phase5-agent-reconcile.json", newOutput: func() any { return new(reconciliationEvidence) }},
	{name: "phase5-agent-event.json", newOutput: func() any { return new(eventEvidence) }},
	{name: "phase5-agent-pod-start.json", newOutput: func() any { return new(podStartEvidence) }},
	{name: "phase5-agent-restart.json", newOutput: func() any { return new(restartEvidence) }},
	{name: "phase5-agent-crash.json", newOutput: func() any { return new(crashEvidence) }},
	{name: "phase5-agent-resource.json", newOutput: func() any { return new(resourceEvidence) }},
}

var phase5EnvironmentKeys = map[string]struct{}{
	"timestamp_utc":         {},
	"phase5_run_id":         {},
	"migration_ci_run_id":   {},
	"release_commit":        {},
	"release_ref":           {},
	"release_workflow":      {},
	"release_event":         {},
	"migration_ci_workflow": {},
	"migration_ci_event":    {},
	"migration_ci_branch":   {},
	"go_version":            {},
	"goos":                  {},
	"goarch":                {},
	"nproc":                 {},
	"reference_cpu_set":     {},
	"reference_nproc":       {},
	"reference_gomaxprocs":  {},
	"getconf_clk_tck":       {},
	"uname":                 {},
	"cgroup2":               {},
	"bpffs":                 {},
	"cpu_max":               {},
}

var hostedResourceEvidenceKeys = map[string]struct{}{
	"agent_namespace":                       {},
	"agent_pod":                             {},
	"budget_result":                         {},
	"container_id":                          {},
	"cpu_budget_cores":                      {},
	"cgroup_path":                           {},
	"max_cpu_cores":                         {},
	"max_memory_current_mib":                {},
	"memory_current_budget_mib":             {},
	"memory_peak_sample_interval_ms":        {},
	"memory_metric":                         {},
	"observed_fixture_pods":                 {},
	"observed_fixture_policies":             {},
	"quiet_settle_seconds":                  {},
	"reference_cpu_max":                     {},
	"reference_fixture_active_policy_epoch": {},
	"reference_fixture_compiled_rules":      {},
	"reference_fixture_enforced_cgroups":    {},
	"reference_fixture_agent_enforcing":     {},
	"reference_fixture_status":              {},
	"reference_total_compiled_rules":        {},
	"reference_total_enforced_cgroups":      {},
	"retained_smoke_client_cgroups":         {},
	"retained_smoke_client_rules":           {},
	"sample":                                {},
	"sample_interval_seconds":               {},
	"samples":                               {},
	"scope":                                 {},
}

var hostedRollingEvidenceKeys = map[string]struct{}{
	"baseline_selected_smoke_client": {},
	"fail_open_end_ns":               {},
	"fail_open_interval_ms":          {},
	"fail_open_start_ns":             {},
	"old_node":                       {},
	"old_namespace":                  {},
	"old_pod":                        {},
	"old_ready":                      {},
	"old_uid":                        {},
	"replacement_created_at":         {},
	"replacement_node":               {},
	"replacement_namespace":          {},
	"replacement_observed_ns":        {},
	"replacement_pod":                {},
	"replacement_ready":              {},
	"replacement_uid":                {},
	"rollout_started_ns":             {},
	"smoke_client_node":              {},
}

var hostedRepeatedEvidenceKeys = map[string]struct{}{
	"sample": {},
}

var referenceMapMemoryShape = []mapMemoryEvidence{
	{Name: "active_config", Type: "ArrayOfMaps", MaxEntries: 1, KeySize: 4, ValueSize: 4, CapacityBounded: true},
	{Name: "agent_status", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 24, CapacityBounded: true},
	{Name: "attached_cgroup", Type: "CGroupStorage", KeySize: 16, ValueSize: 8},
	{Name: "conn_state", Type: "LRUHash", MaxEntries: 65536, KeySize: 32, ValueSize: 8, CapacityBounded: true},
	{Name: "decision_counts", Type: "PerCPUArray", MaxEntries: 48, KeySize: 4, ValueSize: 8, CapacityBounded: true},
	{Name: "decision_epoch_counts", Type: "LRUCPUHash", MaxEntries: 4096, KeySize: 16, ValueSize: 8, CapacityBounded: true},
	{Name: "event_drop_epoch_counts", Type: "LRUCPUHash", MaxEntries: 1024, KeySize: 16, ValueSize: 8, CapacityBounded: true},
	{Name: "event_drops", Type: "PerCPUArray", MaxEntries: 2, KeySize: 4, ValueSize: 8, CapacityBounded: true},
	{Name: "event_limiter", Type: "PerCPUArray", MaxEntries: 1, KeySize: 4, ValueSize: 16, CapacityBounded: true},
	{Name: "flow_events", Type: "RingBuf", MaxEntries: 1 << 20, CapacityBounded: true},
	{Name: "in_flight", Type: "PerCPUArray", MaxEntries: 2, KeySize: 4, ValueSize: 8, CapacityBounded: true},
	{Name: "node_bypass", Type: "Hash", MaxEntries: 32768, KeySize: 8, ValueSize: 1, CapacityBounded: true},
	{Name: "policy_rules", Type: "LPMTrie", MaxEntries: 32768, KeySize: 24, ValueSize: 1, CapacityBounded: true},
	{Name: "self_bypass", Type: "Hash", MaxEntries: 32768, KeySize: 16, ValueSize: 1, CapacityBounded: true},
	{Name: "subject_state", Type: "Hash", MaxEntries: 32768, KeySize: 16, ValueSize: 8, CapacityBounded: true},
}

type referenceEvidence struct {
	TimestampUTC     string              `json:"timestamp_utc"`
	RunID            string              `json:"run_id"`
	GoVersion        string              `json:"go_version"`
	GOOS             string              `json:"goos"`
	GOARCH           string              `json:"goarch"`
	CPUs             int                 `json:"cpus"`
	Subjects         int                 `json:"subjects"`
	Policies         int                 `json:"policies"`
	Rules            int                 `json:"rules"`
	ApplySamplesMS   []float64           `json:"apply_samples_ms"`
	ApplyP95MS       float64             `json:"apply_p95_ms"`
	ApplyBudgetMS    float64             `json:"apply_budget_ms"`
	KernelPathScope  string              `json:"kernel_path_scope"`
	MapMemory        []mapMemoryEvidence `json:"map_memory"`
	MapMemorySamples int                 `json:"map_memory_samples"`
	MapMemoryHistory []mapMemorySnapshot `json:"map_memory_history"`
	MapMemoryStable  bool                `json:"map_memory_stable"`
}

type mapMemoryEvidence struct {
	Name                    string `json:"name"`
	Type                    string `json:"type"`
	MaxEntries              uint32 `json:"max_entries"`
	KeySize                 uint32 `json:"key_size"`
	ValueSize               uint32 `json:"value_size"`
	CapacityBounded         bool   `json:"capacity_bounded"`
	CalculatedCapacityBytes uint64 `json:"calculated_capacity_bytes"`
	ObservedMemlockBytes    uint64 `json:"observed_memlock_bytes"`
	MemlockAvailable        bool   `json:"memlock_available"`
}

type mapMemorySnapshot struct {
	Stage string              `json:"stage"`
	Maps  []mapMemoryEvidence `json:"maps"`
}

type flowEvidence struct {
	TimestampUTC       string  `json:"timestamp_utc"`
	RunID              string  `json:"run_id"`
	GoVersion          string  `json:"go_version"`
	GOOS               string  `json:"goos"`
	GOARCH             string  `json:"goarch"`
	CPUs               int     `json:"cpus"`
	Subjects           int     `json:"subjects"`
	Policies           int     `json:"policies"`
	Rules              int     `json:"rules"`
	RequestedRate      int     `json:"requested_decisions_per_second"`
	TrafficPattern     string  `json:"traffic_pattern"`
	DurationSeconds    float64 `json:"duration_seconds"`
	Decisions          uint64  `json:"decisions"`
	DeliveredEvents    uint64  `json:"delivered_events"`
	RateLimitedEvents  uint64  `json:"rate_limited_events"`
	RingFullEvents     uint64  `json:"ring_full_events"`
	AccountingTotal    uint64  `json:"accounting_total"`
	AccountingBalanced bool    `json:"accounting_balanced"`
	Scope              string  `json:"scope"`
}

type packetEvidence struct {
	TimestampUTC            string    `json:"timestamp_utc"`
	RunID                   string    `json:"run_id"`
	GoVersion               string    `json:"go_version"`
	GOOS                    string    `json:"goos"`
	GOARCH                  string    `json:"goarch"`
	CPUs                    int       `json:"cpus"`
	Subjects                int       `json:"subjects"`
	Policies                int       `json:"policies"`
	Rules                   int       `json:"rules"`
	Samples                 int       `json:"samples"`
	RoundTripsPerSample     int       `json:"round_trips_per_sample"`
	TCPBytesPerSample       int       `json:"tcp_bytes_per_sample"`
	BaselineLatencyP99US    []float64 `json:"baseline_latency_p99_us"`
	EnforcedLatencyP99US    []float64 `json:"enforced_latency_p99_us"`
	LatencyDeltaP99US       float64   `json:"latency_delta_p99_us"`
	LatencyBudgetUS         float64   `json:"latency_budget_us"`
	BaselineTCPMbps         []float64 `json:"baseline_tcp_mbps"`
	EnforcedTCPMbps         []float64 `json:"enforced_tcp_mbps"`
	MaxThroughputRegression float64   `json:"max_throughput_regression_percent"`
	ThroughputBudgetPercent float64   `json:"throughput_budget_percent"`
	Scope                   string    `json:"scope"`
}

type activationEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	CPUs          int       `json:"cpus"`
	KernelRelease string    `json:"kernel_release"`
	CgroupRoot    string    `json:"cgroup_root"`
	BPFFSRoot     string    `json:"bpffs_root"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	ActivationMS  []float64 `json:"activation_samples_ms"`
	ActivationP95 float64   `json:"activation_p95_ms"`
	BudgetMS      float64   `json:"activation_budget_ms"`
	Scope         string    `json:"scope"`
}

type reconciliationEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	CPUs          int       `json:"cpus"`
	KernelRelease string    `json:"kernel_release"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	Samples       int       `json:"samples"`
	ReconcileMS   []float64 `json:"reconcile_samples_ms"`
	ReconcileP95  float64   `json:"reconcile_p95_ms"`
	BudgetMS      float64   `json:"reconcile_budget_ms"`
	Scope         string    `json:"scope"`
}

type eventEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	CPUs          int       `json:"cpus"`
	KernelRelease string    `json:"kernel_release"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	EventMS       []float64 `json:"event_samples_ms"`
	EventP95      float64   `json:"event_p95_ms"`
	BudgetMS      float64   `json:"event_budget_ms"`
	Scope         string    `json:"scope"`
}

type podStartEvidence struct {
	TimestampUTC           string    `json:"timestamp_utc"`
	RunID                  string    `json:"run_id"`
	GoVersion              string    `json:"go_version"`
	GOOS                   string    `json:"goos"`
	GOARCH                 string    `json:"goarch"`
	CPUs                   int       `json:"cpus"`
	KernelRelease          string    `json:"kernel_release"`
	Subjects               int       `json:"subjects"`
	Policies               int       `json:"policies"`
	Rules                  int       `json:"rules"`
	Samples                int       `json:"samples"`
	InitialClassifications int       `json:"initial_classifications"`
	PodStart               []float64 `json:"pod_start_classification_samples_ms"`
	PodStartP95            float64   `json:"pod_start_classification_p95_ms"`
	Scope                  string    `json:"scope"`
}

type restartEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	CPUs          int       `json:"cpus"`
	KernelRelease string    `json:"kernel_release"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	RestartMS     []float64 `json:"restart_samples_ms"`
	RestartP95    float64   `json:"restart_p95_ms"`
	Scope         string    `json:"scope"`
}

type crashEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	CPUs          int       `json:"cpus"`
	KernelRelease string    `json:"kernel_release"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	Samples       int       `json:"samples"`
	CrashGapMS    []float64 `json:"crash_fail_open_samples_ms"`
	CrashGapP95   float64   `json:"crash_fail_open_p95_ms"`
	Scope         string    `json:"scope"`
}

type resourceEvidence struct {
	TimestampUTC   string    `json:"timestamp_utc"`
	RunID          string    `json:"run_id"`
	GoVersion      string    `json:"go_version"`
	GOOS           string    `json:"goos"`
	GOARCH         string    `json:"goarch"`
	CPUs           int       `json:"cpus"`
	KernelRelease  string    `json:"kernel_release"`
	Samples        int       `json:"samples"`
	QuietSeconds   int       `json:"quiet_seconds"`
	Subjects       int       `json:"subjects"`
	Policies       int       `json:"policies"`
	Rules          int       `json:"rules"`
	ClockTicks     int64     `json:"process_clock_ticks_per_second"`
	CPUCoreSamples []float64 `json:"cpu_core_samples"`
	RSSMiBSamples  []float64 `json:"rss_mib_samples"`
	MaxCPUCore     float64   `json:"max_cpu_cores"`
	MaxRSSMiB      float64   `json:"max_rss_mib"`
	CPUBudgetCores float64   `json:"cpu_budget_cores"`
	RSSBudgetMiB   float64   `json:"rss_budget_mib"`
	Scope          string    `json:"scope"`
}

type phase5EvidenceEnvironment struct {
	Artifact  string
	RunID     string
	GoVersion string
	GOOS      string
	GOARCH    string
	CPUs      int
}

type phase5AgentProvenance struct {
	Artifact      string
	KernelRelease string
}

func main() {
	directory := flag.String("dir", "dist", "directory containing Phase 5 JSON evidence")
	expectedRunID := flag.String("run-id", "", "expected run ID shared by the Phase 5 artifacts")
	environmentPath := flag.String("environment", "", "optional phase5-environment.txt path to validate")
	expectedMigrationRunID := flag.String("migration-ci-run-id", "", "expected trusted Migration CI workflow run ID")
	expectedCommit := flag.String("commit", "", "expected tagged commit recorded in the environment file")
	expectedReleaseRef := flag.String("release-ref", "", "expected semantic release tag recorded in the environment file")
	expectedEnvironmentArch := flag.String("environment-arch", "", "expected environment GOARCH")
	hostedEBPFDirectory := flag.String("hosted-ebpf-dir", "", "optional directory containing trusted hosted eBPF evidence")
	hostedCapabilityDirectory := flag.String("hosted-capability-dir", "", "optional directory containing trusted hosted capability-agent evidence")
	flag.Parse()
	if err := verifyDirectory(*directory, *expectedRunID); err != nil {
		fmt.Fprintf(os.Stderr, "phase5verify: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(*environmentPath) != "" {
		if err := verifyEnvironmentFile(*environmentPath, *expectedRunID, *expectedMigrationRunID, *expectedCommit, *expectedReleaseRef, *expectedEnvironmentArch); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: environment: %v\n", err)
			os.Exit(1)
		}
		if err := verifyEnvironmentMatchesEvidence(*environmentPath, *directory); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: environment provenance: %v\n", err)
			os.Exit(1)
		}
	}
	if strings.TrimSpace(*hostedEBPFDirectory) != "" || strings.TrimSpace(*hostedCapabilityDirectory) != "" {
		if strings.TrimSpace(*hostedEBPFDirectory) == "" || strings.TrimSpace(*hostedCapabilityDirectory) == "" {
			fmt.Fprintln(os.Stderr, "phase5verify: hosted eBPF and capability-agent directories must be supplied together")
			os.Exit(1)
		}
		if err := verifyHostedEvidence(*hostedEBPFDirectory, *hostedCapabilityDirectory); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: hosted evidence: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("validated Phase 5 evidence in %s\n", *directory)
}

func verifyDirectory(directory, expectedRunID string) error {
	if err := validatePhase5JSONDirectory(directory); err != nil {
		return err
	}
	type evidenceCheck struct {
		name string
		out  any
	}
	checks := make([]evidenceCheck, 0, len(phase5JSONArtifactSpecs))
	for _, spec := range phase5JSONArtifactSpecs {
		checks = append(checks, evidenceCheck{name: spec.name, out: spec.newOutput()})
	}
	for _, check := range checks {
		if err := readEvidence(filepath.Join(directory, check.name), check.out); err != nil {
			return err
		}
	}

	if err := validateReference(*checks[0].out.(*referenceEvidence)); err != nil {
		return fmt.Errorf("phase5-performance.json: %w", err)
	}
	if err := validateFlow(*checks[1].out.(*flowEvidence)); err != nil {
		return fmt.Errorf("phase5-flow.json: %w", err)
	}
	if err := validatePacket(*checks[2].out.(*packetEvidence)); err != nil {
		return fmt.Errorf("phase5-packet.json: %w", err)
	}
	if err := validateActivation(*checks[3].out.(*activationEvidence)); err != nil {
		return fmt.Errorf("phase5-agent.json: %w", err)
	}
	if err := validateReconciliation(*checks[4].out.(*reconciliationEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-reconcile.json: %w", err)
	}
	if err := validateEvent(*checks[5].out.(*eventEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-event.json: %w", err)
	}
	if err := validatePodStart(*checks[6].out.(*podStartEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-pod-start.json: %w", err)
	}
	if err := validateRestart(*checks[7].out.(*restartEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-restart.json: %w", err)
	}
	if err := validateCrash(*checks[8].out.(*crashEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-crash.json: %w", err)
	}
	if err := validateResource(*checks[9].out.(*resourceEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-resource.json: %w", err)
	}
	if err := validateEvidenceSetEnvironment(
		phase5EvidenceEnvironmentFromReference("phase5-performance.json", *checks[0].out.(*referenceEvidence)),
		phase5EvidenceEnvironmentFromFlow("phase5-flow.json", *checks[1].out.(*flowEvidence)),
		phase5EvidenceEnvironmentFromPacket("phase5-packet.json", *checks[2].out.(*packetEvidence)),
		phase5EvidenceEnvironmentFromActivation("phase5-agent.json", *checks[3].out.(*activationEvidence)),
		phase5EvidenceEnvironmentFromReconciliation("phase5-agent-reconcile.json", *checks[4].out.(*reconciliationEvidence)),
		phase5EvidenceEnvironmentFromEvent("phase5-agent-event.json", *checks[5].out.(*eventEvidence)),
		phase5EvidenceEnvironmentFromPodStart("phase5-agent-pod-start.json", *checks[6].out.(*podStartEvidence)),
		phase5EvidenceEnvironmentFromRestart("phase5-agent-restart.json", *checks[7].out.(*restartEvidence)),
		phase5EvidenceEnvironmentFromCrash("phase5-agent-crash.json", *checks[8].out.(*crashEvidence)),
		phase5EvidenceEnvironmentFromResource("phase5-agent-resource.json", *checks[9].out.(*resourceEvidence)),
	); err != nil {
		return fmt.Errorf("evidence environment: %w", err)
	}
	actualRunID := checks[0].out.(*referenceEvidence).RunID
	if strings.TrimSpace(expectedRunID) != "" && actualRunID != expectedRunID {
		return fmt.Errorf("evidence run ID %q does not match expected run ID %q", actualRunID, expectedRunID)
	}
	if err := validateAgentKernelReleases(
		phase5AgentProvenance{Artifact: "phase5-agent.json", KernelRelease: checks[3].out.(*activationEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-reconcile.json", KernelRelease: checks[4].out.(*reconciliationEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-event.json", KernelRelease: checks[5].out.(*eventEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-pod-start.json", KernelRelease: checks[6].out.(*podStartEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-restart.json", KernelRelease: checks[7].out.(*restartEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-crash.json", KernelRelease: checks[8].out.(*crashEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-resource.json", KernelRelease: checks[9].out.(*resourceEvidence).KernelRelease},
	); err != nil {
		return fmt.Errorf("agent provenance: %w", err)
	}
	return nil
}

func validatePhase5JSONDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect Phase 5 evidence directory %q: %w", directory, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("phase 5 evidence directory %q is a symlink", directory)
	}
	if !info.IsDir() {
		return fmt.Errorf("phase 5 evidence path %q is not a directory", directory)
	}
	expected := make(map[string]struct{}, len(phase5JSONArtifactSpecs))
	for _, spec := range phase5JSONArtifactSpecs {
		expected[spec.name] = struct{}{}
	}
	seen := make(map[string]int, len(expected))
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		isPhase5JSON := strings.HasPrefix(lowerName, "phase5-") && strings.HasSuffix(lowerName, ".json")
		if entry.Type()&os.ModeSymlink != 0 {
			if isPhase5JSON {
				return fmt.Errorf("phase 5 JSON artifact %q is a symlink", path)
			}
			return fmt.Errorf("phase 5 evidence tree contains symlink %q", path)
		}
		if entry.IsDir() {
			if isPhase5JSON {
				return fmt.Errorf("phase 5 JSON artifact %q is not a regular file", path)
			}
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect Phase 5 evidence entry %q: %w", path, err)
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("phase 5 evidence entry %q is not a regular file", path)
		}
		if !isPhase5JSON {
			return nil
		}
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected Phase 5 JSON artifact %q", path)
		}
		seen[name]++
		if seen[name] > 1 {
			return fmt.Errorf("phase 5 JSON artifact %q occurs more than once", name)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk Phase 5 evidence directory %q: %w", directory, err)
	}
	for _, spec := range phase5JSONArtifactSpecs {
		if seen[spec.name] != 1 {
			return fmt.Errorf("phase 5 JSON artifact %q occurs %d times", spec.name, seen[spec.name])
		}
	}
	return nil
}

func phase5EvidenceEnvironmentFromReference(artifact string, evidence referenceEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromFlow(artifact string, evidence flowEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromPacket(artifact string, evidence packetEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromActivation(artifact string, evidence activationEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromReconciliation(artifact string, evidence reconciliationEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromEvent(artifact string, evidence eventEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromPodStart(artifact string, evidence podStartEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromRestart(artifact string, evidence restartEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromCrash(artifact string, evidence crashEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromResource(artifact string, evidence resourceEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func validateEvidenceSetEnvironment(entries ...phase5EvidenceEnvironment) error {
	if len(entries) == 0 {
		return errors.New("evidence environment set is empty")
	}
	baseline := entries[0]
	if strings.TrimSpace(baseline.RunID) == "" {
		return fmt.Errorf("%s has empty run ID", baseline.Artifact)
	}
	for _, entry := range entries[1:] {
		if strings.TrimSpace(entry.RunID) == "" {
			return fmt.Errorf("%s has empty run ID", entry.Artifact)
		}
		if entry.RunID != baseline.RunID || entry.GoVersion != baseline.GoVersion || entry.GOOS != baseline.GOOS || entry.GOARCH != baseline.GOARCH || entry.CPUs != baseline.CPUs {
			return fmt.Errorf("%s provenance differs from %s: run_id=%q/%q Go=%q/%q GOOS=%q/%q GOARCH=%q/%q CPUs=%d/%d",
				entry.Artifact, baseline.Artifact, entry.RunID, baseline.RunID, entry.GoVersion, baseline.GoVersion, entry.GOOS, baseline.GOOS,
				entry.GOARCH, baseline.GOARCH, entry.CPUs, baseline.CPUs)
		}
	}
	return nil
}

func validateAgentKernelReleases(entries ...phase5AgentProvenance) error {
	if len(entries) == 0 {
		return errors.New("agent provenance set is empty")
	}
	baseline := entries[0]
	for _, entry := range entries[1:] {
		if entry.KernelRelease != baseline.KernelRelease {
			return fmt.Errorf("%s kernel release %q differs from %s kernel release %q", entry.Artifact, entry.KernelRelease, baseline.Artifact, baseline.KernelRelease)
		}
	}
	return nil
}

func readEvidence(path string, output any) (err error) {
	const maxEvidenceBytes = 4 << 20
	file, err := openRegularFile(path, "evidence")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEvidenceBytes {
		return fmt.Errorf("%s exceeds the 4 MiB evidence limit", path)
	}
	if err := validateStrictJSONKeys(data); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := validateRequiredJSONFields(data, output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: multiple JSON values", path)
		}
		return fmt.Errorf("decode %s: trailing data: %w", path, err)
	}
	return nil
}

func validateRequiredJSONFields(data []byte, output any) error {
	typeOfOutput := reflect.TypeOf(output)
	if typeOfOutput == nil {
		return errors.New("JSON output type is nil")
	}
	return validateRequiredJSONValue(data, typeOfOutput, "$")
}

func validateRequiredJSONValue(data []byte, typeOfValue reflect.Type, path string) error {
	for typeOfValue.Kind() == reflect.Pointer {
		typeOfValue = typeOfValue.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("%s must not be null", path)
	}
	switch typeOfValue.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return fmt.Errorf("%s must be a JSON object: %w", path, err)
		}
		if fields == nil {
			return fmt.Errorf("%s must be a JSON object", path)
		}
		for fieldIndex := 0; fieldIndex < typeOfValue.NumField(); fieldIndex++ {
			field := typeOfValue.Field(fieldIndex)
			if field.PkgPath != "" {
				continue
			}
			name, required := requiredJSONFieldName(field)
			if !required {
				continue
			}
			value, ok := fields[name]
			if !ok {
				return fmt.Errorf("%s is missing JSON field %q", path, name)
			}
			if err := validateRequiredJSONValue(value, field.Type, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("%s must be a JSON array: %w", path, err)
		}
		for index, value := range values {
			if err := validateRequiredJSONValue(value, typeOfValue.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func requiredJSONFieldName(field reflect.StructField) (string, bool) {
	tag, hasTag := field.Tag.Lookup("json")
	if !hasTag {
		return field.Name, true
	}
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return "", false
	}
	if name == "" {
		return field.Name, true
	}
	return name, true
}

func validateStrictJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("invalid or non-strict JSON: %w", err)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxEvidenceJSONDepth {
		return fmt.Errorf("JSON nesting exceeds depth %d", maxEvidenceJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if key != strings.ToLower(key) {
				return fmt.Errorf("object key %q is not lowercase", key)
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil {
			return err
		} else if closing != json.Delim('}') {
			return errors.New("object is missing closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil {
			return err
		} else if closing != json.Delim(']') {
			return errors.New("array is missing closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func readEnvironmentValues(path string) (values map[string]string, err error) {
	file, err := openRegularFile(path, "environment evidence")
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxEnvironmentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEnvironmentBytes {
		return nil, fmt.Errorf("%s exceeds the 1 MiB environment evidence limit", path)
	}

	values = make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("line %d is not a key=value record", lineNumber)
		}
		if _, known := phase5EnvironmentKeys[key]; !known {
			return nil, fmt.Errorf("line %d has unknown key %q", lineNumber, key)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("line %d repeats key %q", lineNumber, key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

func verifyEnvironmentFile(path, expectedRunID, expectedMigrationRunID, expectedCommit, expectedReleaseRef, expectedArch string) error {
	values, err := readEnvironmentValues(path)
	if err != nil {
		return err
	}
	required := []string{
		"timestamp_utc",
		"phase5_run_id",
		"migration_ci_run_id",
		"release_commit",
		"release_ref",
		"release_workflow",
		"release_event",
		"migration_ci_workflow",
		"migration_ci_event",
		"migration_ci_branch",
		"go_version",
		"goos",
		"goarch",
		"nproc",
		"reference_cpu_set",
		"reference_nproc",
		"reference_gomaxprocs",
		"cgroup2",
		"bpffs",
		"getconf_clk_tck",
		"uname",
		"cpu_max",
	}
	for _, key := range required {
		if strings.TrimSpace(values[key]) == "" {
			return fmt.Errorf("missing %q", key)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, values["timestamp_utc"]); err != nil {
		return fmt.Errorf("timestamp_utc %q is not RFC3339: %v", values["timestamp_utc"], err)
	}
	if expectedRunID != "" && values["phase5_run_id"] != expectedRunID {
		return fmt.Errorf("phase5_run_id %q does not match expected %q", values["phase5_run_id"], expectedRunID)
	}
	if expectedMigrationRunID != "" && values["migration_ci_run_id"] != expectedMigrationRunID {
		return fmt.Errorf("migration_ci_run_id %q does not match expected %q", values["migration_ci_run_id"], expectedMigrationRunID)
	}
	migrationRunID, err := strconv.ParseUint(values["migration_ci_run_id"], 10, 64)
	if err != nil || migrationRunID == 0 {
		return fmt.Errorf("migration_ci_run_id %q is not a positive integer", values["migration_ci_run_id"])
	}
	if expectedCommit != "" && values["release_commit"] != expectedCommit {
		return fmt.Errorf("release_commit %q does not match expected %q", values["release_commit"], expectedCommit)
	}
	if !validCommit(values["release_commit"]) {
		return fmt.Errorf("release_commit %q is not a full hexadecimal commit ID", values["release_commit"])
	}
	if expectedReleaseRef != "" && values["release_ref"] != expectedReleaseRef {
		return fmt.Errorf("release_ref %q does not match expected %q", values["release_ref"], expectedReleaseRef)
	}
	if !validReleaseRef(values["release_ref"]) {
		return fmt.Errorf("release_ref %q is not a semantic release tag", values["release_ref"])
	}
	if values["release_workflow"] != "release.yml" || values["release_event"] != "push" {
		return errors.New("release provenance is not release.yml push")
	}
	if strings.TrimSpace(expectedArch) != "" && values["goarch"] != expectedArch {
		return fmt.Errorf("goarch %q does not match expected %q", values["goarch"], expectedArch)
	}
	if values["goos"] != "linux" || values["reference_cpu_set"] != "0,1" || values["reference_nproc"] != "2" || values["reference_gomaxprocs"] != "2" || values["cgroup2"] != "cgroup2fs" || values["bpffs"] != "bpf" {
		return errors.New("environment is not the documented Linux two-CPU reference profile")
	}
	if _, err := recordedGoVersion(values["go_version"], values["goarch"]); err != nil {
		return err
	}
	if !strings.HasPrefix(values["uname"], "Linux ") {
		return fmt.Errorf("uname %q does not report a Linux host", values["uname"])
	}
	if err := validateCPUQuota(values["cpu_max"]); err != nil {
		return err
	}
	if values["migration_ci_workflow"] != "migration-ci.yml" || values["migration_ci_event"] != "push" || values["migration_ci_branch"] != "main" {
		return errors.New("trusted Migration CI provenance is not migration-ci.yml push on main")
	}
	clockTicks, err := strconv.ParseInt(values["getconf_clk_tck"], 10, 64)
	if err != nil || clockTicks <= 0 {
		return fmt.Errorf("getconf_clk_tck %q is not a positive integer", values["getconf_clk_tck"])
	}
	nproc, err := strconv.ParseInt(values["nproc"], 10, 64)
	if err != nil || nproc <= 0 {
		return fmt.Errorf("nproc %q is not a positive integer", values["nproc"])
	}
	referenceNproc, err := strconv.ParseInt(values["reference_nproc"], 10, 64)
	if err != nil || referenceNproc <= 0 {
		return fmt.Errorf("reference_nproc %q is not a positive integer", values["reference_nproc"])
	}
	if nproc < referenceNproc {
		return fmt.Errorf("nproc %d is smaller than the reference CPU count %d", nproc, referenceNproc)
	}
	return nil
}

func validReleaseRef(value string) bool {
	if !strings.HasPrefix(value, "v") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func recordedGoVersion(value, expectedArch string) (string, error) {
	fields := strings.Fields(value)
	version := ""
	if len(fields) == 4 {
		version = fields[2]
	}
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || !validGoVersionToken(version) || fields[3] != "linux/"+expectedArch {
		return "", fmt.Errorf("go_version %q does not report the recorded Linux/%s target", value, expectedArch)
	}
	return version, nil
}

func validGoVersionToken(version string) bool {
	if !strings.HasPrefix(version, "go") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(version, "go"), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func verifyEnvironmentMatchesEvidence(environmentPath, directory string) error {
	values, err := readEnvironmentValues(environmentPath)
	if err != nil {
		return err
	}
	goVersion, err := recordedGoVersion(values["go_version"], values["goarch"])
	if err != nil {
		return err
	}
	var reference referenceEvidence
	if err := readEvidence(filepath.Join(directory, "phase5-performance.json"), &reference); err != nil {
		return err
	}
	if reference.RunID != values["phase5_run_id"] {
		return fmt.Errorf("phase5-performance.json run ID %q does not match environment phase5_run_id %q", reference.RunID, values["phase5_run_id"])
	}
	if reference.GoVersion != goVersion || reference.GOOS != values["goos"] || reference.GOARCH != values["goarch"] {
		return fmt.Errorf("phase5-performance.json producer metadata does not match environment: Go=%q/%q GOOS=%q/%q GOARCH=%q/%q", reference.GoVersion, goVersion, reference.GOOS, values["goos"], reference.GOARCH, values["goarch"])
	}
	referenceNproc, err := strconv.Atoi(values["reference_nproc"])
	if err != nil || referenceNproc <= 0 {
		return fmt.Errorf("reference_nproc %q is not a positive integer", values["reference_nproc"])
	}
	if reference.CPUs != referenceNproc {
		return fmt.Errorf("phase5-performance.json CPU profile %d does not match reference_nproc=%d", reference.CPUs, referenceNproc)
	}
	clockTicks, err := strconv.ParseInt(values["getconf_clk_tck"], 10, 64)
	if err != nil || clockTicks <= 0 {
		return fmt.Errorf("getconf_clk_tck %q is not a positive integer", values["getconf_clk_tck"])
	}
	var resource resourceEvidence
	if err := readEvidence(filepath.Join(directory, "phase5-agent-resource.json"), &resource); err != nil {
		return err
	}
	if resource.ClockTicks != clockTicks {
		return fmt.Errorf("phase5-agent-resource.json clock ticks %d do not match getconf_clk_tck=%d", resource.ClockTicks, clockTicks)
	}
	return nil
}

func validateCPUQuota(value string) error {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return fmt.Errorf("cpu_max %q is not a two-field cgroup CPU quota", value)
	}
	if fields[0] != "max" {
		quota, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || quota == 0 {
			return fmt.Errorf("cpu_max %q has an invalid quota", value)
		}
	}
	period, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return fmt.Errorf("cpu_max %q has an invalid period", value)
	}
	return nil
}

func verifyHostedEvidence(ebpfDirectory, capabilityDirectory string) error {
	ebpfTests, err := findHostedEvidenceFile(ebpfDirectory, "ebpf-engine-tests.txt")
	if err != nil {
		return err
	}
	capabilitySmoke, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-smoke.txt")
	if err != nil {
		return err
	}
	capabilityFixture, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-reference-fixture.txt")
	if err != nil {
		return err
	}
	fixture, err := findHostedEvidenceFile(capabilityDirectory, "phase5-reference-fixture.yaml")
	if err != nil {
		return err
	}
	resource, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-resource.txt")
	if err != nil {
		return err
	}
	rolling, err := findHostedEvidenceFile(capabilityDirectory, "rolling-fail-open-evidence.txt")
	if err != nil {
		return err
	}

	if err := requireHostedExactLine(ebpfTests, "ebpf_engine_runtime_gate=passed"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "capability-only DaemonSet attached and enforced the smoke policy"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "kindnet_networkpolicy_controller=disabled"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "status_endpoints=passed"); err != nil {
		return err
	}
	if err := requireHostedPositiveUintLine(capabilitySmoke, "packet_decisions_blocked_default_deny"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "flow_streaming=passed"); err != nil {
		return err
	}
	if err := validateHostedFlowEvidence(capabilitySmoke); err != nil {
		return err
	}
	if err := validateHostedClusterIPEvidence(capabilitySmoke); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "fixture_shape=pods=250 policies=25 pods_per_policy=10 peers_per_policy=10 compiled_rules=2500"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "fixture_live_shape=verified"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "offline_fixture_shape=pods=250 policies=25 compiled_rules=2500"); err != nil {
		return err
	}
	if err := validateHostedFixture(fixture); err != nil {
		return err
	}
	if err := validateHostedResourceEvidence(resource); err != nil {
		return err
	}
	if err := validateHostedRollingEvidence(rolling); err != nil {
		return err
	}
	return nil
}

type hostedFlowRecord struct {
	Timestamp     string `json:"timestamp"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
	CgroupID      uint64 `json:"cgroup_id"`
	Direction     string `json:"direction"`
	Protocol      string `json:"protocol"`
	SourceIP      string `json:"src_ip"`
	SourcePort    uint16 `json:"src_port"`
	DestIP        string `json:"dst_ip"`
	DestPort      uint16 `json:"dst_port"`
	Action        string `json:"action"`
	Reason        string `json:"reason"`
	SchemaVersion uint8  `json:"schema_version"`
}

func validateHostedFlowEvidence(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	expected := make(map[string]string, 3)
	blockedDefaultDenyEgress := make([]hostedFlowRecord, 0, 1)
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if strings.HasPrefix(line, "flow_expected_") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || value == "" {
				return fmt.Errorf("%s line %d has malformed flow expectation %q", path, lineNumber, line)
			}
			switch key {
			case "flow_expected_src_ip", "flow_expected_dst_ip", "flow_expected_dst_port":
			default:
				return fmt.Errorf("%s line %d has unknown flow expectation %q", path, lineNumber, key)
			}
			if _, exists := expected[key]; exists {
				return fmt.Errorf("%s line %d repeats flow expectation %q", path, lineNumber, key)
			}
			expected[key] = value
			continue
		}
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var record hostedFlowRecord
		if err := decodeHostedFlowRecord(line, &record); err != nil {
			return fmt.Errorf("%s line %d is not a valid flow JSON record: %w", path, lineNumber, err)
		}
		if record.Action == "blocked" && record.Direction == "egress" && record.Reason == "default_deny" {
			blockedDefaultDenyEgress = append(blockedDefaultDenyEgress, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	for _, key := range []string{"flow_expected_src_ip", "flow_expected_dst_ip", "flow_expected_dst_port"} {
		if expected[key] == "" {
			return fmt.Errorf("%s is missing %s", path, key)
		}
	}
	sourceIP := net.ParseIP(expected["flow_expected_src_ip"])
	if sourceIP == nil || sourceIP.To4() == nil {
		return fmt.Errorf("%s has invalid flow_expected_src_ip=%q", path, expected["flow_expected_src_ip"])
	}
	destIP := net.ParseIP(expected["flow_expected_dst_ip"])
	if destIP == nil || destIP.To4() == nil {
		return fmt.Errorf("%s has invalid flow_expected_dst_ip=%q", path, expected["flow_expected_dst_ip"])
	}
	destPort, err := strconv.ParseUint(expected["flow_expected_dst_port"], 10, 16)
	if err != nil || destPort != 8080 {
		return fmt.Errorf("%s has invalid flow_expected_dst_port=%q", path, expected["flow_expected_dst_port"])
	}
	for _, record := range blockedDefaultDenyEgress {
		if record.Protocol == "TCP" && record.SourceIP == sourceIP.String() &&
			record.SourcePort != 0 && record.DestIP == destIP.String() &&
			uint64(record.DestPort) == destPort {
			return nil
		}
	}
	return fmt.Errorf("%s is missing a blocked default-deny TCP egress flow for %s -> %s:%d", path, sourceIP, destIP, destPort)
}

func validateHostedClusterIPEvidence(path string) error {
	for _, marker := range []string{
		"selector_peer_direct_podip=allowed",
		"selector_peer_service_clusterip=blocked",
		"explicit_clusterip_ipblock_service=allowed",
		"explicit_clusterip_ipblock_podip=blocked",
	} {
		if err := requireHostedExactLine(path, marker); err != nil {
			return err
		}
	}
	serviceIPText, err := hostedSingleLineValue(path, "service_cluster_ip")
	if err != nil {
		return err
	}
	serviceIP := net.ParseIP(serviceIPText)
	if serviceIP == nil || serviceIP.To4() == nil || serviceIP.String() != serviceIPText {
		return fmt.Errorf("%s has invalid service_cluster_ip=%q", path, serviceIPText)
	}
	backendIPText, err := hostedSingleLineValue(path, "service_backend_pod_ip")
	if err != nil {
		return err
	}
	backendIP := net.ParseIP(backendIPText)
	if backendIP == nil || backendIP.To4() == nil || backendIP.String() != backendIPText {
		return fmt.Errorf("%s has invalid service_backend_pod_ip=%q", path, backendIPText)
	}
	if serviceIP.Equal(backendIP) {
		return fmt.Errorf("%s records the Service ClusterIP and backend PodIP as the same address", path)
	}
	cidr, err := hostedSingleLineValue(path, "explicit_clusterip_ipblock_cidr")
	if err != nil {
		return err
	}
	if cidr != serviceIPText+"/32" {
		return fmt.Errorf("%s has explicit_clusterip_ipblock_cidr=%q, want %s/32", path, cidr, serviceIPText)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%s has invalid explicit_clusterip_ipblock_cidr=%q", path, cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 32 || !network.IP.Equal(serviceIP) {
		return fmt.Errorf("%s has explicit_clusterip_ipblock_cidr=%q, want the exact IPv4 Service address", path, cidr)
	}
	flowDestinationIP, err := hostedSingleLineValue(path, "flow_expected_dst_ip")
	if err != nil {
		return err
	}
	if flowDestinationIP != backendIPText {
		return fmt.Errorf("%s flow destination %q does not match Service backend PodIP %q", path, flowDestinationIP, backendIPText)
	}
	selectorEpochText, err := hostedSingleLineValue(path, "selector_peer_policy_epoch")
	if err != nil {
		return err
	}
	selectorEpoch, err := strconv.ParseUint(selectorEpochText, 10, 64)
	if err != nil || selectorEpoch == 0 {
		return fmt.Errorf("%s has invalid selector_peer_policy_epoch=%q", path, selectorEpochText)
	}
	explicitEpochText, err := hostedSingleLineValue(path, "explicit_clusterip_policy_epoch")
	if err != nil {
		return err
	}
	explicitEpoch, err := strconv.ParseUint(explicitEpochText, 10, 64)
	if err != nil || explicitEpoch <= selectorEpoch {
		return fmt.Errorf("%s explicit ClusterIP policy epoch %q must exceed selector policy epoch %d", path, explicitEpochText, selectorEpoch)
	}
	return nil
}

func decodeHostedFlowRecord(line string, output *hostedFlowRecord) error {
	if err := validateStrictJSONKeys([]byte(line)); err != nil {
		return err
	}
	if err := validateRequiredJSONFields([]byte(line), output); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return err
	}
	for _, field := range []string{
		"timestamp", "policy_epoch", "cgroup_id", "direction", "protocol", "src_ip",
		"src_port", "dst_ip", "dst_port", "action", "reason", "schema_version",
	} {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing field %q", field)
		}
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	if output.Timestamp == "" {
		return errors.New("timestamp is empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, output.Timestamp); err != nil {
		return fmt.Errorf("timestamp %q is not RFC3339: %w", output.Timestamp, err)
	}
	if output.PolicyEpoch == 0 {
		return errors.New("policy_epoch is zero")
	}
	if output.CgroupID == 0 {
		return errors.New("cgroup_id is zero")
	}
	if output.Direction != "egress" && output.Direction != "ingress" {
		return fmt.Errorf("direction %q is unsupported", output.Direction)
	}
	if output.Action != "blocked" && output.Action != "allowed" {
		return fmt.Errorf("action %q is unsupported", output.Action)
	}
	if output.Protocol != "TCP" && output.Protocol != "UDP" && output.Protocol != "ICMP" {
		return fmt.Errorf("protocol %q is unsupported", output.Protocol)
	}
	if net.ParseIP(output.SourceIP) == nil || net.ParseIP(output.DestIP) == nil {
		return fmt.Errorf("flow addresses %q -> %q are invalid", output.SourceIP, output.DestIP)
	}
	if output.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d is unsupported", output.SchemaVersion)
	}
	if strings.TrimSpace(output.Reason) == "" {
		return errors.New("reason is empty")
	}
	return nil
}

func findHostedEvidenceFile(root, name string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("hosted evidence directory for %s is empty", name)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("open hosted evidence directory %q: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("hosted evidence path %q is a symlink", root)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("hosted evidence path %q is not a directory", root)
	}
	var matches []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("hosted evidence contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("hosted evidence entry %q is not a regular file", path)
		}
		if strings.EqualFold(entry.Name(), name) && entry.Name() != name {
			return fmt.Errorf("hosted evidence file %q has a case-variant duplicate name %q", name, path)
		}
		if entry.Name() == name {
			matches = append(matches, path)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("walk hosted evidence directory %q: %w", root, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("hosted evidence file %q is missing from %s", name, root)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("hosted evidence file %q occurs %d times in %s", name, len(matches), root)
	}
	return matches[0], nil
}

func readHostedEvidence(path string) (content string, err error) {
	const maxHostedEvidenceBytes = 4 << 20
	file, err := openRegularFile(path, "hosted evidence")
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, maxHostedEvidenceBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxHostedEvidenceBytes {
		return "", fmt.Errorf("%s exceeds the 4 MiB hosted evidence limit", path)
	}
	return string(data), nil
}

func requireHostedExactLine(path, expected string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	expectedKey, _, keyedMarker := strings.Cut(expected, "=")
	found := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if keyedMarker && strings.HasPrefix(line, expectedKey+"=") && line != expected {
			return fmt.Errorf("%s contains conflicting evidence line %q for %q", path, line, expectedKey)
		}
		if line == expected {
			if found {
				return fmt.Errorf("%s contains duplicate exact evidence line %q", path, expected)
			}
			found = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if found {
		return nil
	}
	return fmt.Errorf("%s is missing exact evidence line %q", path, expected)
}

func requireHostedPositiveUintLine(path, key string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	count := 0
	var value string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		recordedKey, recordedValue, ok := strings.Cut(line, "=")
		if !ok || recordedKey != key {
			continue
		}
		count++
		value = recordedValue
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if count != 1 {
		return fmt.Errorf("%s must contain exactly one %s= entry", path, key)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return fmt.Errorf("%s must contain a positive unsigned %s value", path, key)
	}
	return nil
}

func hostedSingleLineValue(path, key string) (string, error) {
	text, err := readHostedEvidence(path)
	if err != nil {
		return "", err
	}
	count := 0
	var value string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		recordedKey, recordedValue, ok := strings.Cut(line, "=")
		if !ok || recordedKey != key {
			continue
		}
		count++
		value = strings.TrimSpace(recordedValue)
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", path, err)
	}
	if count != 1 || value == "" {
		return "", fmt.Errorf("%s must contain exactly one non-empty %s value", path, key)
	}
	return value, nil
}

func validateHostedFixture(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	if !strings.Contains(text, "namespace: ztap-performance") {
		return fmt.Errorf("%s is missing the ztap-performance namespace", path)
	}
	if countHostedExactLine(text, "apiVersion: v1") != referenceSubjects+1 {
		return fmt.Errorf("%s contains an unexpected core API object count", path)
	}
	if countHostedExactLine(text, "apiVersion: networking.k8s.io/v1") != referencePolicies {
		return fmt.Errorf("%s contains an unexpected NetworkPolicy API object count", path)
	}
	if countHostedExactLine(text, "namespace: ztap-performance") != referenceSubjects+referencePolicies {
		return fmt.Errorf("%s does not place every workload and policy in ztap-performance", path)
	}
	podCount := countHostedExactLine(text, "kind: Pod")
	if podCount != referenceSubjects {
		return fmt.Errorf("%s contains %d Pod objects, want %d", path, podCount, referenceSubjects)
	}
	policyCount := countHostedExactLine(text, "kind: NetworkPolicy")
	if policyCount != referencePolicies {
		return fmt.Errorf("%s contains %d NetworkPolicy objects, want %d", path, policyCount, referencePolicies)
	}
	if err := validateHostedObjectNames(path, text, "reference-pod-", referenceSubjects, 3); err != nil {
		return err
	}
	if err := validateHostedObjectNames(path, text, "reference-policy-", referencePolicies, 2); err != nil {
		return err
	}
	if countHostedObjectBucketMarkers(text) != referenceSubjects+referencePolicies {
		return fmt.Errorf("%s is missing the documented subject buckets", path)
	}
	if err := validateHostedFixtureDocuments(path, text); err != nil {
		return err
	}
	peerCount := countHostedContainingLine(text, "cidr: 198.18.")
	if peerCount != referenceRules/referenceSubjects*referencePolicies {
		return fmt.Errorf("%s contains an unexpected reference peer count", path)
	}
	return nil
}

func validateHostedObjectNames(path, text, prefix string, expectedCount, width int) error {
	seen := make(map[int]struct{}, expectedCount)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		namePrefix := "name: " + prefix
		if !strings.HasPrefix(line, namePrefix) {
			continue
		}
		suffix := strings.TrimPrefix(line, namePrefix)
		if len(suffix) != width {
			return fmt.Errorf("%s contains malformed %s object name %q", path, prefix, line)
		}
		index, err := strconv.Atoi(suffix)
		if err != nil || index < 0 || index >= expectedCount {
			return fmt.Errorf("%s contains out-of-range %s object name %q", path, prefix, line)
		}
		if _, duplicate := seen[index]; duplicate {
			return fmt.Errorf("%s repeats %s object name %q", path, prefix, line)
		}
		seen[index] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if len(seen) != expectedCount {
		return fmt.Errorf("%s contains %d %s object names, want %d", path, len(seen), prefix, expectedCount)
	}
	return nil
}

func countHostedExactLine(text, expected string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		if strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r")) == expected {
			count++
		}
	}
	return count
}

func countHostedContainingLine(text, fragment string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), fragment) {
			count++
		}
	}
	return count
}

func countHostedObjectBucketMarkers(text string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.HasPrefix(line, "    phase5-bucket:") {
			count++
		}
	}
	return count
}

func validateHostedFixtureDocuments(path, text string) error {
	documents, err := hostedFixtureDocuments(path, text)
	if err != nil {
		return err
	}
	if len(documents) != referenceSubjects+referencePolicies+1 {
		return fmt.Errorf("%s contains %d YAML documents, want %d", path, len(documents), referenceSubjects+referencePolicies+1)
	}
	namespaceCount := 0
	for _, document := range documents {
		object, err := decodeHostedYAMLDocument(path, document)
		if err != nil {
			return err
		}
		apiVersion, apiVersionOK := hostedYAMLStringField(object, "apiVersion")
		kind, kindOK := hostedYAMLStringField(object, "kind")
		metadata, metadataOK := hostedYAMLMappingField(object, "metadata")
		name, nameOK := hostedYAMLStringField(metadata, "name")
		if !apiVersionOK || !kindOK || !metadataOK || !nameOK {
			return fmt.Errorf("%s contains a fixture document with invalid top-level metadata", path)
		}
		switch kind {
		case "Namespace":
			if err := requireHostedYAMLFieldSet(path, object, "Namespace document", "apiVersion", "kind", "metadata"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, "Namespace metadata", "name"); err != nil {
				return err
			}
			namespaceCount++
			if apiVersion != "v1" || name != "ztap-performance" {
				return fmt.Errorf("%s contains an invalid ztap-performance Namespace document", path)
			}
			continue
		case "Pod":
			if err := requireHostedYAMLFieldSet(path, object, fmt.Sprintf("Pod %q", name), "apiVersion", "kind", "metadata", "spec"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, fmt.Sprintf("Pod %q metadata", name), "name", "namespace", "labels"); err != nil {
				return err
			}
			namespace, namespaceOK := hostedYAMLStringField(metadata, "namespace")
			if apiVersion != "v1" || !namespaceOK || namespace != "ztap-performance" {
				return fmt.Errorf("%s Pod %q has an invalid API version or namespace", path, name)
			}
			index, err := parseHostedFixtureIndex(path, name, "reference-pod-", 3, referenceSubjects)
			if err != nil {
				return err
			}
			labels, labelsOK := hostedYAMLMappingField(metadata, "labels")
			if !labelsOK {
				return fmt.Errorf("%s Pod %q is missing metadata labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, labels, index/(referenceSubjects/referencePolicies)); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, labels, fmt.Sprintf("Pod %q labels", name), "phase5-bucket"); err != nil {
				return err
			}
			if err := validateHostedFixturePodSpec(path, object, name); err != nil {
				return err
			}
		case "NetworkPolicy":
			if err := requireHostedYAMLFieldSet(path, object, fmt.Sprintf("NetworkPolicy %q", name), "apiVersion", "kind", "metadata", "spec"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, fmt.Sprintf("NetworkPolicy %q metadata", name), "name", "namespace", "labels"); err != nil {
				return err
			}
			namespace, namespaceOK := hostedYAMLStringField(metadata, "namespace")
			if apiVersion != "networking.k8s.io/v1" || !namespaceOK || namespace != "ztap-performance" {
				return fmt.Errorf("%s NetworkPolicy %q has an invalid API version or namespace", path, name)
			}
			index, err := parseHostedFixtureIndex(path, name, "reference-policy-", 2, referencePolicies)
			if err != nil {
				return err
			}
			labels, labelsOK := hostedYAMLMappingField(metadata, "labels")
			if !labelsOK {
				return fmt.Errorf("%s NetworkPolicy %q is missing metadata labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, labels, index); err != nil {
				return err
			}
			spec, specOK := hostedYAMLMappingField(object, "spec")
			selector, selectorOK := hostedYAMLMappingField(spec, "podSelector")
			selectorLabels, selectorLabelsOK := hostedYAMLMappingField(selector, "matchLabels")
			if !specOK || !selectorOK || !selectorLabelsOK {
				return fmt.Errorf("%s NetworkPolicy %q is missing its pod selector labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, selectorLabels, index); err != nil {
				return err
			}
			if err := validateHostedFixturePeers(path, object, index); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s contains unexpected fixture kind %q", path, kind)
		}
	}
	if namespaceCount != 1 {
		return fmt.Errorf("%s contains %d Namespace documents, want 1", path, namespaceCount)
	}
	return nil
}

func validateHostedFixturePodSpec(path string, object *yaml.Node, name string) error {
	spec, specOK := hostedYAMLMappingField(object, "spec")
	if !specOK {
		return fmt.Errorf("%s Pod %q is missing its spec mapping", path, name)
	}
	if err := requireHostedYAMLFieldSet(path, spec, fmt.Sprintf("Pod %q spec", name), "containers"); err != nil {
		return err
	}
	containers, containersOK := hostedYAMLSequenceField(spec, "containers")
	if !containersOK || len(containers.Content) != 1 {
		count := 0
		if containersOK {
			count = len(containers.Content)
		}
		return fmt.Errorf("%s Pod %q contains %d containers, want 1", path, name, count)
	}
	container := containers.Content[0]
	if err := requireHostedYAMLFieldSet(path, container, fmt.Sprintf("Pod %q workload container", name), "name", "image", "imagePullPolicy", "command"); err != nil {
		return err
	}
	containerName, containerNameOK := hostedYAMLStringField(container, "name")
	image, imageOK := hostedYAMLStringField(container, "image")
	imagePullPolicy, imagePullPolicyOK := hostedYAMLStringField(container, "imagePullPolicy")
	if !containerNameOK || containerName != "workload" || !imageOK || image != "busybox:1.36.1" || !imagePullPolicyOK || imagePullPolicy != "IfNotPresent" {
		return fmt.Errorf("%s Pod %q workload container has unexpected image metadata", path, name)
	}
	command, commandOK := hostedYAMLSequenceField(container, "command")
	wantCommand := []string{"sh", "-c", "sleep 3600"}
	if !commandOK || len(command.Content) != len(wantCommand) {
		return fmt.Errorf("%s Pod %q workload command has an unexpected shape", path, name)
	}
	for index, want := range wantCommand {
		item := command.Content[index]
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || item.Value != want {
			return fmt.Errorf("%s Pod %q workload command item %d is %q, want %q", path, name, index, item.Value, want)
		}
	}
	return nil
}

func decodeHostedYAMLDocument(path string, document []string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(strings.Join(document, "\n") + "\n"))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("%s contains invalid YAML: %w", path, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s contains a fixture document that is not a YAML mapping", path)
	}
	if err := validateStrictYAMLMapping(root.Content[0], 0); err != nil {
		return nil, fmt.Errorf("%s contains invalid or duplicate YAML mapping keys: %w", path, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s contains multiple YAML documents in one fixture document", path)
		}
		return nil, fmt.Errorf("%s contains trailing invalid YAML: %w", path, err)
	}
	return root.Content[0], nil
}

func validateStrictYAMLMapping(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if depth > maxHostedYAMLDepth {
		return fmt.Errorf("YAML nesting exceeds depth %d", maxHostedYAMLDepth)
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return errors.New("YAML anchors and aliases are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return errors.New("mapping has an incomplete key/value pair")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind == yaml.ScalarNode && key.Value == "<<" {
				return errors.New("YAML merge keys are not allowed")
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("mapping key %q is not a string", key.Value)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateStrictYAMLMapping(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateHostedFixturePeers(path string, object *yaml.Node, policyIndex int) error {
	wantPeers := referenceRules / referenceSubjects
	spec, specOK := hostedYAMLMappingField(object, "spec")
	if !specOK {
		return fmt.Errorf("%s policy %q is missing its spec mapping", path, fmt.Sprintf("reference-policy-%02d", policyIndex))
	}
	policyName := fmt.Sprintf("reference-policy-%02d", policyIndex)
	if err := requireHostedYAMLFieldSet(path, spec, fmt.Sprintf("NetworkPolicy %q spec", policyName), "podSelector", "policyTypes", "egress"); err != nil {
		return err
	}
	selector, selectorOK := hostedYAMLMappingField(spec, "podSelector")
	if !selectorOK {
		return fmt.Errorf("%s policy %q is missing its pod selector mapping", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, selector, fmt.Sprintf("NetworkPolicy %q podSelector", policyName), "matchLabels"); err != nil {
		return err
	}
	selectorLabels, selectorLabelsOK := hostedYAMLMappingField(selector, "matchLabels")
	if !selectorLabelsOK {
		return fmt.Errorf("%s policy %q is missing its matchLabels mapping", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, selectorLabels, fmt.Sprintf("NetworkPolicy %q matchLabels", policyName), "phase5-bucket"); err != nil {
		return err
	}
	policyTypes, policyTypesOK := hostedYAMLSequenceField(spec, "policyTypes")
	if !policyTypesOK || len(policyTypes.Content) != 1 || policyTypes.Content[0].Kind != yaml.ScalarNode || policyTypes.Content[0].Tag != "!!str" || policyTypes.Content[0].Value != "Egress" {
		return fmt.Errorf("%s policy %q must contain exactly one Egress policy type", path, policyName)
	}
	egress, egressOK := hostedYAMLSequenceField(spec, "egress")
	if !egressOK || len(egress.Content) != 1 {
		return fmt.Errorf("%s policy %q must contain exactly one egress rule", path, policyName)
	}
	rule := egress.Content[0]
	if err := requireHostedYAMLFieldSet(path, rule, fmt.Sprintf("NetworkPolicy %q egress rule", policyName), "to", "ports"); err != nil {
		return err
	}
	to, toOK := hostedYAMLSequenceField(rule, "to")
	if !toOK || len(to.Content) != wantPeers {
		count := 0
		if toOK {
			count = len(to.Content)
		}
		return fmt.Errorf("%s policy %q contains %d structured peers, want %d", path, policyName, count, wantPeers)
	}
	ports, portsOK := hostedYAMLSequenceField(rule, "ports")
	if !portsOK || len(ports.Content) != 1 {
		return fmt.Errorf("%s policy %q must contain exactly one port rule", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, ports.Content[0], fmt.Sprintf("NetworkPolicy %q port rule", policyName), "protocol", "port"); err != nil {
		return err
	}
	protocol, protocolOK := hostedYAMLStringField(ports.Content[0], "protocol")
	port, portOK := hostedYAMLIntegerField(ports.Content[0], "port")
	if !protocolOK || protocol != "TCP" || !portOK || port != 10000 {
		return fmt.Errorf("%s policy %q must allow only TCP port 10000", path, policyName)
	}
	for peerIndex, peer := range to.Content {
		ipBlock, ok := hostedYAMLMappingField(peer, "ipBlock")
		if ok {
			if err := requireHostedYAMLFieldSet(path, peer, fmt.Sprintf("NetworkPolicy %q peer %d", policyName, peerIndex), "ipBlock"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, ipBlock, fmt.Sprintf("NetworkPolicy %q peer %d ipBlock", policyName, peerIndex), "cidr"); err != nil {
				return err
			}
		}
		cidr, cidrOK := hostedYAMLStringField(ipBlock, "cidr")
		want := fmt.Sprintf("198.18.%d.%d/32", policyIndex, peerIndex)
		if !ok || !cidrOK || cidr != want {
			return fmt.Errorf("%s policy %q peer %d has CIDR %q, want %q", path, policyName, peerIndex, cidr, want)
		}
	}
	return nil
}

func hostedFixtureDocuments(path, text string) ([][]string, error) {
	documents := make([][]string, 0, referenceSubjects+referencePolicies+1)
	current := make([]string, 0, 32)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "---" {
			if len(current) > 0 {
				documents = append(documents, current)
				current = make([]string, 0, 32)
			}
			continue
		}
		if strings.TrimSpace(line) != "" {
			current = append(current, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if len(current) > 0 {
		documents = append(documents, current)
	}
	return documents, nil
}

func parseHostedFixtureIndex(path, name, prefix string, width, count int) (int, error) {
	if !strings.HasPrefix(name, prefix) {
		return 0, fmt.Errorf("%s contains malformed fixture object name %q", path, name)
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != width {
		return 0, fmt.Errorf("%s contains malformed fixture object name %q", path, name)
	}
	index, err := strconv.Atoi(suffix)
	if err != nil || index < 0 || index >= count {
		return 0, fmt.Errorf("%s contains out-of-range fixture object name %q", path, name)
	}
	return index, nil
}

func hostedYAMLField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		keyNode := mapping.Content[index]
		if keyNode.Kind == yaml.ScalarNode && keyNode.Value == key {
			return mapping.Content[index+1], true
		}
	}
	return nil, false
}

func requireHostedYAMLFieldSet(path string, mapping *yaml.Node, context string, expectedFields ...string) error {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("%s has no mapping for %s", path, context)
	}
	expected := make(map[string]struct{}, len(expectedFields))
	for _, field := range expectedFields {
		expected[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(mapping.Content)/2)
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key := mapping.Content[index].Value
		if _, ok := expected[key]; !ok {
			return fmt.Errorf("%s has unexpected YAML field %q in %s", path, key, context)
		}
		seen[key] = struct{}{}
	}
	for _, field := range expectedFields {
		if _, ok := seen[field]; !ok {
			return fmt.Errorf("%s is missing YAML field %q in %s", path, field, context)
		}
	}
	return nil
}

func hostedYAMLStringField(mapping *yaml.Node, key string) (string, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.ScalarNode || field.Tag != "!!str" {
		return "", false
	}
	return field.Value, true
}

func hostedYAMLMappingField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.MappingNode {
		return nil, false
	}
	return field, true
}

func hostedYAMLSequenceField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.SequenceNode {
		return nil, false
	}
	return field, true
}

func hostedYAMLIntegerField(mapping *yaml.Node, key string) (int64, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.ScalarNode || field.Tag != "!!int" {
		return 0, false
	}
	value, err := strconv.ParseInt(field.Value, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func requireHostedYAMLBucket(path string, labels *yaml.Node, expected int) error {
	want := fmt.Sprintf("%02d", expected)
	value, ok := hostedYAMLStringField(labels, "phase5-bucket")
	if !ok {
		return fmt.Errorf("%s is missing a string phase5-bucket marker", path)
	}
	if value != want {
		return fmt.Errorf("%s has bucket %q, want %q", path, value, want)
	}
	return nil
}

func hostedKeyValues(path string) (map[string][]string, error) {
	text, err := readHostedEvidence(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("%s has malformed hosted key/value line %q", path, line)
		}
		values[key] = append(values[key], value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return values, nil
}

func validateHostedKeySet(values map[string][]string, path string, allowed map[string]struct{}) error {
	for key, entries := range values {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s contains unexpected hosted evidence key %q", path, key)
		}
		if _, repeated := hostedRepeatedEvidenceKeys[key]; !repeated && len(entries) != 1 {
			return fmt.Errorf("%s contains duplicate hosted evidence key %q", path, key)
		}
	}
	return nil
}

func requireHostedValue(values map[string][]string, path, key, expected string) error {
	entries := values[key]
	if len(entries) == 1 && entries[0] == expected {
		return nil
	}
	return fmt.Errorf("%s must contain exactly one %s=%s entry", path, key, expected)
}

func hostedSingleValue(values map[string][]string, path, key string) (string, error) {
	entries := values[key]
	if len(entries) != 1 || strings.TrimSpace(entries[0]) == "" {
		return "", fmt.Errorf("%s must contain exactly one non-empty %s value", path, key)
	}
	return entries[0], nil
}

func parseHostedFloat(values map[string][]string, path, key string) (float64, error) {
	value, err := hostedSingleValue(values, path, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 {
		return 0, fmt.Errorf("%s has invalid %s=%q", path, key, value)
	}
	return parsed, nil
}

func parseHostedUint(values map[string][]string, path, key string) (uint64, error) {
	value, err := hostedSingleValue(values, path, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s has invalid %s=%q", path, key, value)
	}
	return parsed, nil
}

func validateHostedResourceEvidence(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	samples, err := parseHostedResourceSamples(path, text)
	if err != nil {
		return err
	}
	values, err := hostedKeyValues(path)
	if err != nil {
		return err
	}
	if err := validateHostedKeySet(values, path, hostedResourceEvidenceKeys); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "scope", "real capability-only DaemonSet in kind with 250 Pods, 25 policies, and 2500 rules"); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "reference_fixture_status", "active_waiting_for_quiet_interval"); err != nil {
		return err
	}
	for _, key := range []string{"agent_pod", "container_id", "cgroup_path"} {
		if _, err := hostedSingleValue(values, path, key); err != nil {
			return err
		}
	}
	if err := requireHostedValue(values, path, "agent_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	agentPod, err := hostedSingleValue(values, path, "agent_pod")
	if err != nil {
		return err
	}
	if !validHostedAgentPodName(agentPod) {
		return fmt.Errorf("%s records agent_pod=%q outside the shipped ztap-agent DaemonSet", path, agentPod)
	}
	containerID, err := hostedSingleValue(values, path, "container_id")
	if err != nil {
		return err
	}
	if !validHostedContainerID(containerID) {
		return fmt.Errorf("%s records a non-64-hex container_id=%q", path, containerID)
	}
	cgroupPath, err := hostedSingleValue(values, path, "cgroup_path")
	if err != nil {
		return err
	}
	if !validHostedContainerCgroupPath(cgroupPath, containerID) {
		return fmt.Errorf("%s records cgroup_path=%q that is not a canonical /sys/fs/cgroup path for container_id=%q", path, cgroupPath, containerID)
	}
	for key, expected := range map[string]string{
		"observed_fixture_pods":             "250",
		"observed_fixture_policies":         "25",
		"reference_cpu_max":                 "200000 100000",
		"reference_fixture_agent_enforcing": "1",
		"reference_fixture_compiled_rules":  "2500",
		"reference_total_compiled_rules":    "2501",
		"reference_total_enforced_cgroups":  "251",
		"retained_smoke_client_cgroups":     "1",
		"retained_smoke_client_rules":       "1",
		"memory_metric":                     "memory.current (conservative cgroup memory upper bound; includes non-RSS charges)",
		"samples":                           "3",
		"quiet_settle_seconds":              "10",
		"sample_interval_seconds":           "5",
		"memory_peak_sample_interval_ms":    "100",
		"cpu_budget_cores":                  "0.10",
		"memory_current_budget_mib":         "200",
		"budget_result":                     "passed",
	} {
		if err := requireHostedValue(values, path, key, expected); err != nil {
			return err
		}
	}
	activePolicyEpoch, err := parseHostedUint(values, path, "reference_fixture_active_policy_epoch")
	if err != nil {
		return err
	}
	if activePolicyEpoch < 1 {
		return fmt.Errorf("%s reports active policy epoch %d, want at least 1", path, activePolicyEpoch)
	}
	enforced, err := parseHostedUint(values, path, "reference_fixture_enforced_cgroups")
	if err != nil {
		return err
	}
	if enforced != referenceSubjects {
		return fmt.Errorf("%s reports %d enforced cgroups, want exactly %d", path, enforced, referenceSubjects)
	}
	totalEnforced, err := parseHostedUint(values, path, "reference_total_enforced_cgroups")
	if err != nil {
		return err
	}
	retainedCgroups, err := parseHostedUint(values, path, "retained_smoke_client_cgroups")
	if err != nil {
		return err
	}
	if totalEnforced != enforced+retainedCgroups {
		return fmt.Errorf("%s reports %d total enforced cgroups, want fixture count %d plus %d retained smoke cgroups", path, totalEnforced, enforced, retainedCgroups)
	}
	compiledRules, err := parseHostedUint(values, path, "reference_fixture_compiled_rules")
	if err != nil {
		return err
	}
	totalRules, err := parseHostedUint(values, path, "reference_total_compiled_rules")
	if err != nil {
		return err
	}
	retainedRules, err := parseHostedUint(values, path, "retained_smoke_client_rules")
	if err != nil {
		return err
	}
	if totalRules != compiledRules+retainedRules {
		return fmt.Errorf("%s reports %d total compiled rules, want fixture count %d plus %d retained smoke rules", path, totalRules, compiledRules, retainedRules)
	}
	maxCPU, err := parseHostedFloat(values, path, "max_cpu_cores")
	if err != nil {
		return err
	}
	maxSampleCPU := 0.0
	maxSampleMemory := 0.0
	for _, sample := range samples {
		if sample.ElapsedNanoseconds < uint64(5*time.Second) {
			return fmt.Errorf("%s resource sample elapsed interval %dns is shorter than the documented five seconds", path, sample.ElapsedNanoseconds)
		}
		if sample.CPUCores > maxSampleCPU {
			maxSampleCPU = sample.CPUCores
		}
		if sample.MemoryCurrentMiB > maxSampleMemory {
			maxSampleMemory = sample.MemoryCurrentMiB
		}
	}
	if !nearlyEqual(maxCPU, maxSampleCPU) {
		return fmt.Errorf("%s reports max_cpu_cores=%.6f, want sample maximum %.6f", path, maxCPU, maxSampleCPU)
	}
	if maxCPU > cpuBudgetCores {
		return fmt.Errorf("%s reports %.6f CPU cores, over %.2f budget", path, maxCPU, cpuBudgetCores)
	}
	maxMemory, err := parseHostedFloat(values, path, "max_memory_current_mib")
	if err != nil {
		return err
	}
	if !nearlyEqual(maxMemory, maxSampleMemory) {
		return fmt.Errorf("%s reports max_memory_current_mib=%.6f, want sample maximum %.6f", path, maxMemory, maxSampleMemory)
	}
	if maxMemory > rssBudgetMiB {
		return fmt.Errorf("%s reports %.3f MiB, over %d MiB budget", path, maxMemory, rssBudgetMiB)
	}
	return nil
}

func validateHostedResourceSamples(path, text string) error {
	_, err := parseHostedResourceSamples(path, text)
	return err
}

type hostedResourceSample struct {
	StartCPUUsec       uint64
	EndCPUUsec         uint64
	StartMemoryBytes   uint64
	EndMemoryBytes     uint64
	PeakMemoryBytes    uint64
	CPUCores           float64
	MemoryCurrentMiB   float64
	ElapsedNanoseconds uint64
}

func parseHostedResourceSamples(path, text string) ([]hostedResourceSample, error) {
	nextSample := 1
	samples := make([]hostedResourceSample, 0, repeatedSamples)
	var previousEndCPUUsec uint64
	havePreviousEndCPU := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if !strings.HasPrefix(line, "sample=") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 9 {
			return nil, fmt.Errorf("%s has malformed resource sample line %q", path, line)
		}
		values := make(map[string]string, len(fields))
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if !ok || key == "" || value == "" {
				return nil, fmt.Errorf("%s has malformed resource sample field %q", path, field)
			}
			if _, exists := values[key]; exists {
				return nil, fmt.Errorf("%s repeats resource sample field %q", path, key)
			}
			values[key] = value
		}
		for _, key := range []string{"sample", "start_cpu_usec", "end_cpu_usec", "start_memory_current_bytes", "end_memory_current_bytes", "peak_memory_current_bytes", "cpu_cores", "memory_current_mib", "elapsed_ns"} {
			if _, ok := values[key]; !ok {
				return nil, fmt.Errorf("%s resource sample is missing %s", path, key)
			}
		}
		if len(values) != 9 {
			return nil, fmt.Errorf("%s has an invalid resource sample field set", path)
		}
		sample, err := strconv.Atoi(values["sample"])
		if err != nil || sample != nextSample {
			return nil, fmt.Errorf("%s resource sample index = %q, want %d", path, values["sample"], nextSample)
		}
		parsedSample := hostedResourceSample{}
		for _, field := range []struct {
			key   string
			value *uint64
		}{
			{key: "start_cpu_usec", value: &parsedSample.StartCPUUsec},
			{key: "end_cpu_usec", value: &parsedSample.EndCPUUsec},
			{key: "start_memory_current_bytes", value: &parsedSample.StartMemoryBytes},
			{key: "end_memory_current_bytes", value: &parsedSample.EndMemoryBytes},
			{key: "peak_memory_current_bytes", value: &parsedSample.PeakMemoryBytes},
		} {
			parsed, parseErr := strconv.ParseUint(values[field.key], 10, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("%s resource sample has invalid %s=%q", path, field.key, values[field.key])
			}
			*field.value = parsed
		}
		if parsedSample.EndCPUUsec < parsedSample.StartCPUUsec {
			return nil, fmt.Errorf("%s resource sample CPU counter decreased from %d to %d", path, parsedSample.StartCPUUsec, parsedSample.EndCPUUsec)
		}
		if havePreviousEndCPU && parsedSample.StartCPUUsec < previousEndCPUUsec {
			return nil, fmt.Errorf("%s resource sample CPU counter reset between samples from %d to %d", path, previousEndCPUUsec, parsedSample.StartCPUUsec)
		}
		if parsedSample.PeakMemoryBytes < parsedSample.StartMemoryBytes || parsedSample.PeakMemoryBytes < parsedSample.EndMemoryBytes {
			return nil, fmt.Errorf("%s resource sample peak memory %d is below start/end readings %d/%d", path, parsedSample.PeakMemoryBytes, parsedSample.StartMemoryBytes, parsedSample.EndMemoryBytes)
		}
		elapsed, err := strconv.ParseUint(values["elapsed_ns"], 10, 64)
		if err != nil || elapsed == 0 {
			return nil, fmt.Errorf("%s resource sample has invalid elapsed_ns=%q", path, values["elapsed_ns"])
		}
		reportedCPU, err := strconv.ParseFloat(values["cpu_cores"], 64)
		if err != nil || math.IsNaN(reportedCPU) || math.IsInf(reportedCPU, 0) || reportedCPU < 0 {
			return nil, fmt.Errorf("%s resource sample has invalid cpu_cores=%q", path, values["cpu_cores"])
		}
		computedCPU := float64(parsedSample.EndCPUUsec-parsedSample.StartCPUUsec) * 1000 / float64(elapsed)
		if !nearlyEqualMeasurement(reportedCPU, computedCPU) {
			return nil, fmt.Errorf("%s resource sample cpu_cores=%.9f does not match raw counters %.9f", path, reportedCPU, computedCPU)
		}
		reportedMemory, err := strconv.ParseFloat(values["memory_current_mib"], 64)
		if err != nil || math.IsNaN(reportedMemory) || math.IsInf(reportedMemory, 0) || reportedMemory < 0 {
			return nil, fmt.Errorf("%s resource sample has invalid memory_current_mib=%q", path, values["memory_current_mib"])
		}
		computedMemory := float64(parsedSample.PeakMemoryBytes) / (1024 * 1024)
		if !nearlyEqualMeasurement(reportedMemory, computedMemory) {
			return nil, fmt.Errorf("%s resource sample memory_current_mib=%.9f does not match raw counters %.9f", path, reportedMemory, computedMemory)
		}
		parsedSample.CPUCores = reportedCPU
		parsedSample.MemoryCurrentMiB = reportedMemory
		parsedSample.ElapsedNanoseconds = elapsed
		samples = append(samples, parsedSample)
		previousEndCPUUsec = parsedSample.EndCPUUsec
		havePreviousEndCPU = true
		nextSample++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if len(samples) != repeatedSamples {
		return nil, fmt.Errorf("%s contains %d measured resource samples, want %d", path, len(samples), repeatedSamples)
	}
	return samples, nil
}

func validHostedHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func validHostedContainerID(value string) bool {
	return len(value) == 64 && validHostedHex(value)
}

func validHostedCgroupPath(value string) bool {
	return strings.HasPrefix(value, "/sys/fs/cgroup/") && filepath.Clean(value) == value
}

func validHostedContainerCgroupPath(value, containerID string) bool {
	if !validHostedCgroupPath(value) || !validHostedContainerID(containerID) ||
		filepath.Base(value) != "cri-containerd-"+strings.ToLower(containerID)+".scope" {
		return false
	}
	return strings.HasPrefix(value, "/sys/fs/cgroup/kubepods.slice/") ||
		strings.HasPrefix(value, "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/")
}

func validHostedAgentPodName(value string) bool {
	if !strings.HasPrefix(value, "ztap-agent-") || len(value) > 253 {
		return false
	}
	suffix := strings.TrimPrefix(value, "ztap-agent-")
	if suffix == "" || suffix[0] == '-' || suffix[len(suffix)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func hostedTimestampResolutionNS(value string) uint64 {
	parts := strings.SplitN(value, "T", 2)
	if len(parts) != 2 || len(parts[1]) <= 8 || parts[1][8] != '.' {
		return uint64(time.Second)
	}
	fraction := parts[1][9:]
	if zoneStart := strings.IndexAny(fraction, "Z+-"); zoneStart >= 0 {
		fraction = fraction[:zoneStart]
	}
	if len(fraction) == 0 || len(fraction) > 9 {
		return 0
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' {
			return 0
		}
	}
	resolution := uint64(1)
	for index := len(fraction); index < 9; index++ {
		resolution *= 10
	}
	return resolution
}

func validateHostedRollingEvidence(path string) error {
	values, err := hostedKeyValues(path)
	if err != nil {
		return err
	}
	if err := validateHostedKeySet(values, path, hostedRollingEvidenceKeys); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "baseline_selected_smoke_client", "blocked"); err != nil {
		return err
	}
	smokeClientNode, err := hostedSingleValue(values, path, "smoke_client_node")
	if err != nil {
		return err
	}
	oldPod, err := hostedSingleValue(values, path, "old_pod")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "old_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	if !validHostedAgentPodName(oldPod) {
		return fmt.Errorf("%s records old_pod=%q outside the shipped ztap-agent DaemonSet", path, oldPod)
	}
	oldUID, err := hostedSingleValue(values, path, "old_uid")
	if err != nil {
		return err
	}
	oldNode, err := hostedSingleValue(values, path, "old_node")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "old_ready", "true"); err != nil {
		return err
	}
	replacementPod, err := hostedSingleValue(values, path, "replacement_pod")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "replacement_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	if !validHostedAgentPodName(replacementPod) {
		return fmt.Errorf("%s records replacement_pod=%q outside the shipped ztap-agent DaemonSet", path, replacementPod)
	}
	replacementUID, err := hostedSingleValue(values, path, "replacement_uid")
	if err != nil {
		return err
	}
	replacementNode, err := hostedSingleValue(values, path, "replacement_node")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "replacement_ready", "true"); err != nil {
		return err
	}
	replacementCreatedAt, err := hostedSingleValue(values, path, "replacement_created_at")
	if err != nil {
		return err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, replacementCreatedAt)
	if err != nil || createdAt.UnixNano() <= 0 {
		return fmt.Errorf("%s records invalid replacement_created_at=%q", path, replacementCreatedAt)
	}
	replacementObserved, err := parseHostedUint(values, path, "replacement_observed_ns")
	if err != nil {
		return err
	}
	if replacementObserved == 0 {
		return fmt.Errorf("%s records a zero replacement observation timestamp", path)
	}
	if oldPod == replacementPod {
		return fmt.Errorf("%s reports the same old and replacement pod %q", path, oldPod)
	}
	if oldUID == replacementUID {
		return fmt.Errorf("%s reports the same old and replacement pod UID %q", path, oldUID)
	}
	if oldNode != replacementNode {
		return fmt.Errorf("%s reports replacement node %q, want the old pod node %q", path, replacementNode, oldNode)
	}
	if oldNode != smokeClientNode {
		return fmt.Errorf("%s reports old pod node %q, want smoke-client node %q", path, oldNode, smokeClientNode)
	}
	rolloutStarted, err := parseHostedUint(values, path, "rollout_started_ns")
	if err != nil {
		return err
	}
	if rolloutStarted == 0 {
		return fmt.Errorf("%s records a zero rollout start timestamp", path)
	}
	start, err := parseHostedUint(values, path, "fail_open_start_ns")
	if err != nil {
		return err
	}
	if start == 0 {
		return fmt.Errorf("%s records a zero fail-open start timestamp", path)
	}
	end, err := parseHostedUint(values, path, "fail_open_end_ns")
	if err != nil {
		return err
	}
	if end == 0 {
		return fmt.Errorf("%s records a zero fail-open end timestamp", path)
	}
	if end <= start {
		return fmt.Errorf("%s records a non-positive fail-open interval", path)
	}
	if rolloutStarted > start {
		return fmt.Errorf("%s records fail-open start before rollout start", path)
	}
	createdAtNS := uint64(createdAt.UnixNano())
	if replacementObserved < createdAtNS {
		return fmt.Errorf("%s records replacement observation at %d before its creation at %d", path, replacementObserved, createdAtNS)
	}
	creationResolution := hostedTimestampResolutionNS(replacementCreatedAt)
	if creationResolution == 0 || createdAtNS > ^uint64(0)-creationResolution ||
		createdAtNS > end || createdAtNS+creationResolution <= rolloutStarted {
		return fmt.Errorf("%s records replacement creation at %d with %d-ns precision outside rollout-to-fail-open interval [%d,%d]", path, createdAtNS, creationResolution, rolloutStarted, end)
	}
	if replacementObserved < rolloutStarted || replacementObserved > end {
		return fmt.Errorf("%s records replacement observation at %d outside rollout-to-fail-open interval [%d,%d]", path, replacementObserved, rolloutStarted, end)
	}
	interval, err := parseHostedUint(values, path, "fail_open_interval_ms")
	if err != nil {
		return err
	}
	expected := (end - start) / 1_000_000
	if expected == 0 {
		return fmt.Errorf("%s records a fail-open interval shorter than one millisecond", path)
	}
	if interval != expected {
		return fmt.Errorf("%s records fail_open_interval_ms=%d, want %d from nanosecond timestamps", path, interval, expected)
	}
	return nil
}

func validateReference(e referenceEvidence) error {
	if err := validateEnvironment("reference", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateExactScope("reference kernel path scope", e.KernelPathScope, referenceKernelPathScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("apply", e.ApplySamplesMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("apply p95", e.ApplySamplesMS, e.ApplyP95MS); err != nil {
		return err
	}
	if err := validateExpectedBudget("apply budget", e.ApplyBudgetMS, applyBudgetMS); err != nil {
		return err
	}
	if err := validateBudget("apply p95", e.ApplyP95MS, e.ApplyBudgetMS); err != nil {
		return err
	}
	if len(e.MapMemory) == 0 || e.MapMemorySamples != len(referenceMapMemoryStages) || len(e.MapMemoryHistory) != e.MapMemorySamples || !e.MapMemoryStable {
		return errors.New("map memory evidence is missing stability samples or is not marked stable")
	}
	if err := validateMapMemoryEntries(e.MapMemory, e.CPUs); err != nil {
		return err
	}
	if err := validateReferenceMapMemoryShape(e.MapMemory, e.CPUs); err != nil {
		return err
	}
	for index, snapshot := range e.MapMemoryHistory {
		if snapshot.Stage != referenceMapMemoryStages[index] {
			return fmt.Errorf("map memory snapshot %d stage = %q, want %q", index+1, snapshot.Stage, referenceMapMemoryStages[index])
		}
		if err := validateMapMemoryEntries(snapshot.Maps, e.CPUs); err != nil {
			return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
		}
		if err := validateReferenceMapMemoryShape(snapshot.Maps, e.CPUs); err != nil {
			return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
		}
		if index > 0 {
			// The first population can allocate map backing pages. Require
			// stable memlock only among the warmed, repeated apply samples.
			if err := compareMapMemory(e.MapMemoryHistory[index-1].Maps, snapshot.Maps, index > 1); err != nil {
				return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
			}
		}
	}
	if err := compareMapMemoryExact(e.MapMemoryHistory[len(e.MapMemoryHistory)-1].Maps, e.MapMemory); err != nil {
		return fmt.Errorf("final map memory snapshot: %w", err)
	}
	return nil
}

func validateReferenceMapMemoryShape(entries []mapMemoryEvidence, cpus int) error {
	expected := make([]mapMemoryEvidence, len(referenceMapMemoryShape))
	copy(expected, referenceMapMemoryShape)
	for index := range expected {
		capacity, err := calculatedMapCapacity(expected[index], cpus)
		if err != nil {
			return fmt.Errorf("calculate expected capacity for map %q: %w", expected[index].Name, err)
		}
		expected[index].CalculatedCapacityBytes = capacity
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("map memory contains %d maps, want the exact %d-map engine inventory", len(entries), len(expected))
	}
	for index, actual := range entries {
		want := expected[index]
		if actual.Name != want.Name || actual.Type != want.Type || actual.MaxEntries != want.MaxEntries ||
			actual.KeySize != want.KeySize || actual.ValueSize != want.ValueSize ||
			actual.CapacityBounded != want.CapacityBounded || actual.CalculatedCapacityBytes != want.CalculatedCapacityBytes {
			return fmt.Errorf("map %d = %#v, want %#v", index+1, actual, want)
		}
	}
	return nil
}

func validateMapMemoryEntries(entries []mapMemoryEvidence, cpus int) error {
	if len(entries) == 0 {
		return errors.New("map memory snapshot is empty")
	}
	if cpus <= 0 {
		return fmt.Errorf("map memory CPU count = %d, want positive", cpus)
	}
	knownTypes := map[string]struct{}{
		"Array": {}, "ArrayOfMaps": {}, "CGroupStorage": {}, "Hash": {},
		"LPMTrie": {}, "LRUHash": {}, "LRUCPUHash": {}, "PerCPUArray": {},
		"PerCPUHash": {}, "PerCPUCGroupStorage": {}, "RingBuf": {},
	}
	for index, memory := range entries {
		if memory.Name == "" || memory.Type == "" {
			return fmt.Errorf("invalid map memory entry %q", memory.Name)
		}
		if _, ok := knownTypes[memory.Type]; !ok {
			return fmt.Errorf("map %q has unknown type %q", memory.Name, memory.Type)
		}
		if index > 0 && memory.Name <= entries[index-1].Name {
			return fmt.Errorf("map entries are not strictly sorted by name at %q", memory.Name)
		}
		if memory.Type == "CGroupStorage" {
			if memory.MaxEntries != 0 || memory.CapacityBounded || memory.CalculatedCapacityBytes != 0 {
				return fmt.Errorf("cgroup-storage map %q must report an unbounded zero capacity", memory.Name)
			}
		} else if !memory.CapacityBounded || memory.MaxEntries == 0 || memory.CalculatedCapacityBytes == 0 {
			return fmt.Errorf("bounded map %q is missing a positive configured capacity", memory.Name)
		}
		if memory.Type != "RingBuf" && (memory.KeySize == 0 || memory.ValueSize == 0) {
			return fmt.Errorf("invalid key/value size for map %q", memory.Name)
		}
		if memory.MemlockAvailable && memory.ObservedMemlockBytes == 0 {
			return fmt.Errorf("map %q reports available memlock but zero observed bytes", memory.Name)
		}
		if !memory.MemlockAvailable && memory.ObservedMemlockBytes != 0 {
			return fmt.Errorf("map %q reports unavailable memlock with observed bytes %d", memory.Name, memory.ObservedMemlockBytes)
		}
		expected, err := calculatedMapCapacity(memory, cpus)
		if err != nil {
			return fmt.Errorf("map %q: %w", memory.Name, err)
		}
		if memory.CalculatedCapacityBytes != expected {
			return fmt.Errorf("map %q calculated capacity = %d, want %d", memory.Name, memory.CalculatedCapacityBytes, expected)
		}
	}
	return nil
}

func calculatedMapCapacity(memory mapMemoryEvidence, cpus int) (uint64, error) {
	if memory.Type == "CGroupStorage" {
		return 0, nil
	}
	if memory.Type == "RingBuf" {
		return uint64(memory.MaxEntries), nil
	}
	unitBytes := uint64(memory.KeySize) + uint64(memory.ValueSize)
	capacity := uint64(memory.MaxEntries)
	switch memory.Type {
	case "PerCPUHash", "PerCPUArray", "LRUCPUHash", "PerCPUCGroupStorage":
		if uint64(cpus) > ^uint64(0)/capacity {
			return 0, errors.New("per-CPU entry count overflows capacity calculation")
		}
		capacity *= uint64(cpus)
	}
	if unitBytes != 0 && capacity > ^uint64(0)/unitBytes {
		return 0, errors.New("map entry size overflows capacity calculation")
	}
	return capacity * unitBytes, nil
}

func compareMapMemory(previous, current []mapMemoryEvidence, compareMemlock bool) error {
	if len(previous) != len(current) {
		return fmt.Errorf("map count changed from %d to %d", len(previous), len(current))
	}
	for index := range previous {
		before := previous[index]
		after := current[index]
		if before.Name != after.Name || before.Type != after.Type ||
			before.MaxEntries != after.MaxEntries || before.KeySize != after.KeySize ||
			before.ValueSize != after.ValueSize || before.CapacityBounded != after.CapacityBounded ||
			before.CalculatedCapacityBytes != after.CalculatedCapacityBytes {
			return fmt.Errorf("map %q capacity changed from %#v to %#v", before.Name, before, after)
		}
		if compareMemlock && before.MemlockAvailable != after.MemlockAvailable {
			return fmt.Errorf("map %q memlock availability changed from %t to %t", before.Name, before.MemlockAvailable, after.MemlockAvailable)
		}
		if compareMemlock && before.MemlockAvailable && after.ObservedMemlockBytes > before.ObservedMemlockBytes {
			return fmt.Errorf("map %q observed memlock grew from %d to %d bytes", before.Name, before.ObservedMemlockBytes, after.ObservedMemlockBytes)
		}
	}
	return nil
}

func compareMapMemoryExact(expected, actual []mapMemoryEvidence) error {
	if err := compareMapMemory(expected, actual, true); err != nil {
		return err
	}
	for index := range expected {
		if expected[index].ObservedMemlockBytes != actual[index].ObservedMemlockBytes {
			return fmt.Errorf("map %q observed memlock changed from %d to %d bytes", expected[index].Name, expected[index].ObservedMemlockBytes, actual[index].ObservedMemlockBytes)
		}
	}
	return nil
}

func validateFlow(e flowEvidence) error {
	if err := validateEnvironment("flow", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return fmt.Errorf("flow %w", err)
	}
	if err := validateExactScope("flow scope", e.Scope, flowScope); err != nil {
		return err
	}
	if strings.TrimSpace(e.TrafficPattern) != flowTrafficPattern {
		return fmt.Errorf("flow traffic pattern = %q, want %q", e.TrafficPattern, flowTrafficPattern)
	}
	if e.RequestedRate != flowRate || math.IsNaN(e.DurationSeconds) || math.IsInf(e.DurationSeconds, 0) || e.DurationSeconds < flowSeconds || e.DurationSeconds > flowMaxSeconds {
		return fmt.Errorf("flow target is %d decisions/s for %.3fs, want %d/s for %d-%ds", e.RequestedRate, e.DurationSeconds, flowRate, flowSeconds, flowMaxSeconds)
	}
	if e.Decisions < uint64(flowRate*flowSeconds) {
		return fmt.Errorf("decisions = %d, want at least %d", e.Decisions, flowRate*flowSeconds)
	}
	maximumDecisions := (e.DurationSeconds + 1) * float64(flowRate)
	if float64(e.Decisions) > maximumDecisions {
		return fmt.Errorf("decisions = %d, exceed %.0f decisions allowed by %.3fs run", e.Decisions, maximumDecisions, e.DurationSeconds)
	}
	accounted := e.DeliveredEvents
	if e.RateLimitedEvents > ^uint64(0)-accounted {
		return errors.New("flow accounting component sum overflows uint64")
	}
	accounted += e.RateLimitedEvents
	if e.RingFullEvents > ^uint64(0)-accounted {
		return errors.New("flow accounting component sum overflows uint64")
	}
	accounted += e.RingFullEvents
	if accounted != e.AccountingTotal || e.AccountingTotal != e.Decisions || !e.AccountingBalanced {
		return fmt.Errorf("accounting is unbalanced: decisions=%d total=%d balanced=%t", e.Decisions, e.AccountingTotal, e.AccountingBalanced)
	}
	return nil
}

func validatePacket(e packetEvidence) error {
	if err := validateEnvironment("packet", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateExactScope("packet scope", e.Scope, packetScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.RoundTripsPerSample != packetRoundTrips || e.TCPBytesPerSample != packetTCPBytes {
		return fmt.Errorf("packet sample shape is %d samples/%d round-trips/%d TCP bytes, want %d/%d/%d", e.Samples, e.RoundTripsPerSample, e.TCPBytesPerSample, repeatedSamples, packetRoundTrips, packetTCPBytes)
	}
	for name, values := range map[string][]float64{
		"baseline latency": e.BaselineLatencyP99US,
		"enforced latency": e.EnforcedLatencyP99US,
		"baseline TCP":     e.BaselineTCPMbps,
		"enforced TCP":     e.EnforcedTCPMbps,
	} {
		if err := validatePositiveSamples(name, values, repeatedSamples); err != nil {
			return err
		}
	}
	if err := validateExpectedBudget("UDP latency budget", e.LatencyBudgetUS, latencyBudgetUS); err != nil {
		return err
	}
	if err := validateBudget("UDP latency delta", e.LatencyDeltaP99US, e.LatencyBudgetUS); err != nil {
		return err
	}
	if err := validateExpectedBudget("TCP throughput budget", e.ThroughputBudgetPercent, throughputBudget); err != nil {
		return err
	}
	if err := validateBudget("TCP throughput regression", e.MaxThroughputRegression, e.ThroughputBudgetPercent); err != nil {
		return err
	}

	latencyDelta := 0.0
	throughputRegression := 0.0
	for index := range e.BaselineLatencyP99US {
		if delta := e.EnforcedLatencyP99US[index] - e.BaselineLatencyP99US[index]; delta > latencyDelta {
			latencyDelta = delta
		}
		if e.BaselineTCPMbps[index] > 0 {
			regression := (e.BaselineTCPMbps[index] - e.EnforcedTCPMbps[index]) / e.BaselineTCPMbps[index] * 100
			if regression > throughputRegression {
				throughputRegression = regression
			}
		}
	}
	if !nearlyEqual(e.LatencyDeltaP99US, latencyDelta) || !nearlyEqual(e.MaxThroughputRegression, throughputRegression) {
		return fmt.Errorf("packet aggregate mismatch: latency delta %.6f/%.6f, throughput regression %.6f/%.6f", e.LatencyDeltaP99US, latencyDelta, e.MaxThroughputRegression, throughputRegression)
	}
	return nil
}

func validateActivation(e activationEvidence) error {
	if err := validateEnvironment("activation", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("activation", e.KernelRelease, e.Scope, activationScope); err != nil {
		return err
	}
	if e.CgroupRoot != "/sys/fs/cgroup" {
		return fmt.Errorf("activation cgroup root = %q, want /sys/fs/cgroup", e.CgroupRoot)
	}
	if e.BPFFSRoot != "/sys/fs/bpf" {
		return fmt.Errorf("activation bpffs root = %q, want /sys/fs/bpf", e.BPFFSRoot)
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("activation", e.ActivationMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("activation p95", e.ActivationMS, e.ActivationP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("activation budget", e.BudgetMS, activationBudget); err != nil {
		return err
	}
	return validateBudget("activation p95", e.ActivationP95, e.BudgetMS)
}

func validateReconciliation(e reconciliationEvidence) error {
	if err := validateEnvironment("reconciliation", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("reconciliation", e.KernelRelease, e.Scope, reconciliationScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples {
		return fmt.Errorf("samples = %d, want %d", e.Samples, repeatedSamples)
	}
	if err := validatePositiveSamples("reconciliation", e.ReconcileMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("reconciliation p95", e.ReconcileMS, e.ReconcileP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("reconciliation budget", e.BudgetMS, reconcileBudget); err != nil {
		return err
	}
	return validateBudget("reconciliation p95", e.ReconcileP95, e.BudgetMS)
}

func validateEvent(e eventEvidence) error {
	if err := validateEnvironment("event", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("event", e.KernelRelease, e.Scope, eventScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("event", e.EventMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("event p95", e.EventMS, e.EventP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("event budget", e.BudgetMS, eventBudget); err != nil {
		return err
	}
	return validateBudget("event p95", e.EventP95, e.BudgetMS)
}

func validatePodStart(e podStartEvidence) error {
	if err := validateEnvironment("Pod-start", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("Pod-start", e.KernelRelease, e.Scope, podStartScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.InitialClassifications != referenceSubjects {
		return fmt.Errorf("pod-start sample shape is %d samples/%d initial classifications, want %d/%d", e.Samples, e.InitialClassifications, repeatedSamples, referenceSubjects)
	}
	if err := validatePositiveSamples("Pod-start", e.PodStart, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("Pod-start p95", e.PodStart, e.PodStartP95)
}

func validateRestart(e restartEvidence) error {
	if err := validateEnvironment("restart", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("restart", e.KernelRelease, e.Scope, restartScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("restart", e.RestartMS, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("restart p95", e.RestartMS, e.RestartP95)
}

func validateCrash(e crashEvidence) error {
	if err := validateEnvironment("crash", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("crash", e.KernelRelease, e.Scope, crashScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples {
		return fmt.Errorf("samples = %d, want %d", e.Samples, repeatedSamples)
	}
	if err := validatePositiveSamples("crash", e.CrashGapMS, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("crash p95", e.CrashGapMS, e.CrashGapP95)
}

func validateResource(e resourceEvidence) error {
	if err := validateEnvironment("resource", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("resource", e.KernelRelease, e.Scope, resourceScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.QuietSeconds != 5 || e.ClockTicks <= 0 {
		return fmt.Errorf("resource sample shape is %d samples/%ds with %d clock ticks, want %d samples/5s and a positive clock rate", e.Samples, e.QuietSeconds, e.ClockTicks, repeatedSamples)
	}
	if err := validateSamples("CPU", e.CPUCoreSamples, repeatedSamples); err != nil {
		return err
	}
	if err := validateSamples("RSS", e.RSSMiBSamples, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("CPU maximum", e.CPUCoreSamples, e.MaxCPUCore); err != nil {
		return err
	}
	if err := validateReportedMaximum("RSS maximum", e.RSSMiBSamples, e.MaxRSSMiB); err != nil {
		return err
	}
	if err := validateExpectedBudget("CPU budget", e.CPUBudgetCores, cpuBudgetCores); err != nil {
		return err
	}
	if err := validateBudget("CPU", e.MaxCPUCore, e.CPUBudgetCores); err != nil {
		return err
	}
	if err := validateExpectedBudget("RSS budget", e.RSSBudgetMiB, rssBudgetMiB); err != nil {
		return err
	}
	return validateBudget("RSS", e.MaxRSSMiB, e.RSSBudgetMiB)
}

func validateEnvironment(name, runID, timestamp, goVersion, goos, goarch string, cpus int) error {
	if strings.TrimSpace(runID) == "" {
		return fmt.Errorf("%s evidence is missing run ID", name)
	}
	if strings.TrimSpace(timestamp) == "" || strings.TrimSpace(goVersion) == "" {
		return fmt.Errorf("%s evidence is missing timestamp or Go version", name)
	}
	if !validGoVersionToken(goVersion) {
		return fmt.Errorf("%s evidence Go version %q is not a dotted release token", name, goVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		return fmt.Errorf("%s evidence timestamp %q is not RFC3339: %v", name, timestamp, err)
	}
	if goos != "linux" {
		return fmt.Errorf("%s evidence GOOS = %q, want linux", name, goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return fmt.Errorf("%s evidence GOARCH = %q, want amd64 or arm64", name, goarch)
	}
	if cpus != referenceCPUs {
		return fmt.Errorf("%s evidence reports %d CPUs, want the documented %d-CPU profile", name, cpus, referenceCPUs)
	}
	return nil
}

func validateAgentMetadata(name, kernelRelease, scope, expectedScope string) error {
	if err := validateNonEmpty(name+" kernel release", kernelRelease); err != nil {
		return err
	}
	return validateExactScope(name+" scope", scope, expectedScope)
}

func validateExactScope(name, actual, expected string) error {
	if actual != expected {
		return fmt.Errorf("%s = %q, want the exact producer scope %q", name, actual, expected)
	}
	return nil
}

func validateNonEmpty(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is missing", name)
	}
	return nil
}

func validateFixture(subjects, policies, rules int) error {
	if subjects != referenceSubjects || policies != referencePolicies || rules != referenceRules {
		return fmt.Errorf("fixture shape is %d subjects/%d policies/%d rules, want %d/%d/%d", subjects, policies, rules, referenceSubjects, referencePolicies, referenceRules)
	}
	return nil
}

func validateSamples(name string, values []float64, want int) error {
	if len(values) != want {
		return fmt.Errorf("%s samples = %d, want %d", name, len(values), want)
	}
	for index, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("%s sample %d is invalid: %v", name, index+1, value)
		}
	}
	return nil
}

func validatePositiveSamples(name string, values []float64, want int) error {
	if err := validateSamples(name, values, want); err != nil {
		return err
	}
	for index, value := range values {
		if value <= 0 {
			return fmt.Errorf("%s sample %d must be positive, got %v", name, index+1, value)
		}
	}
	return nil
}

func validateBudget(name string, value, budget float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.IsNaN(budget) || math.IsInf(budget, 0) || value < 0 || budget <= 0 {
		return fmt.Errorf("%s has invalid value/budget: %v/%v", name, value, budget)
	}
	if value > budget {
		return fmt.Errorf("%s = %.3f exceeds budget %.3f", name, value, budget)
	}
	return nil
}

func validateExpectedBudget(name string, actual, expected float64) error {
	if math.IsNaN(actual) || math.IsInf(actual, 0) || math.Abs(actual-expected) > 1e-9 {
		return fmt.Errorf("%s = %.9f, want documented %.9f", name, actual, expected)
	}
	return nil
}

func validateReportedMaximum(name string, values []float64, reported float64) error {
	if math.IsNaN(reported) || math.IsInf(reported, 0) || reported < 0 {
		return fmt.Errorf("%s is invalid: %v", name, reported)
	}
	maximum := 0.0
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	if !nearlyEqual(reported, maximum) {
		return fmt.Errorf("%s = %.9f, want maximum %.9f", name, reported, maximum)
	}
	return nil
}

func nearlyEqual(left, right float64) bool {
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= 1e-9*scale
}

func nearlyEqualMeasurement(left, right float64) bool {
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= 1e-6*scale
}
