package main

import (
	"github.com/saadshabir/ZTAP/internal/restartproof"
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
	packetRoundTrips         = 10_000
	packetTCPBytes           = 8 << 30
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
	"environment_schema":     {},
	"environment_mode":       {},
	"timestamp_utc":          {},
	"phase5_run_id":          {},
	"migration_ci_run_id":    {},
	"commit":                 {},
	"ref":                    {},
	"workflow_run_id":        {},
	"workflow_event":         {},
	"workflow_path":          {},
	"migration_ci_workflow":  {},
	"migration_ci_event":     {},
	"migration_ci_branch":    {},
	"go_version":             {},
	"goos":                   {},
	"goarch":                 {},
	"nproc":                  {},
	"allowed_cpu_list":       {},
	"reference_cpu_set":      {},
	"reference_nproc":        {},
	"reference_gomaxprocs":   {},
	"getconf_clk_tck":        {},
	"uname":                  {},
	"cgroup2":                {},
	"bpffs":                  {},
	"cgroup_mount_root":      {},
	"cgroup_mount_point":     {},
	"cgroup_membership_path": {},
	"cgroup_process_path":    {},
	"cpu_max_status":         {},
	"cpu_max_path":           {},
	"cpu_max":                {},
	"cpu_max_hierarchy_json": {},
	"capture_errors_json":    {},
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
	{Name: "conn_state", Type: "LRUHash", MaxEntries: 65536, KeySize: 32, ValueSize: 16, CapacityBounded: true},
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
	SchemaVersion int                   `json:"schema_version,omitempty"`
	Continuity    []restartproof.Sample `json:"continuity_samples,omitempty"`
	TimestampUTC  string                `json:"timestamp_utc"`
	RunID         string                `json:"run_id"`
	GoVersion     string                `json:"go_version"`
	GOOS          string                `json:"goos"`
	GOARCH        string                `json:"goarch"`
	CPUs          int                   `json:"cpus"`
	KernelRelease string                `json:"kernel_release"`
	Subjects      int                   `json:"subjects"`
	Policies      int                   `json:"policies"`
	Rules         int                   `json:"rules"`
	RestartMS     []float64             `json:"restart_samples_ms"`
	RestartP95    float64               `json:"restart_p95_ms"`
	Scope         string                `json:"scope"`
}

type crashEvidence struct {
	SchemaVersion int                   `json:"schema_version,omitempty"`
	Continuity    []restartproof.Sample `json:"continuity_samples,omitempty"`
	TimestampUTC  string                `json:"timestamp_utc"`
	RunID         string                `json:"run_id"`
	GoVersion     string                `json:"go_version"`
	GOOS          string                `json:"goos"`
	GOARCH        string                `json:"goarch"`
	CPUs          int                   `json:"cpus"`
	KernelRelease string                `json:"kernel_release"`
	Subjects      int                   `json:"subjects"`
	Policies      int                   `json:"policies"`
	Rules         int                   `json:"rules"`
	Samples       int                   `json:"samples"`
	CrashGapMS    []float64             `json:"crash_fail_open_samples_ms"`
	CrashGapP95   float64               `json:"crash_fail_open_p95_ms"`
	Scope         string                `json:"scope"`
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
