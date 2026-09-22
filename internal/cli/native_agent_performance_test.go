//go:build linux && integration
// +build linux,integration

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	phase5AgentSubjects            = 250
	phase5AgentPolicies            = 25
	phase5AgentRules               = 2500
	phase5AgentSamples             = 3
	phase5AgentReconcileSamples    = 3
	phase5AgentEventSamples        = 3
	phase5AgentPodStartSamples     = 3
	phase5AgentRestartSamples      = 3
	phase5AgentCrashSamples        = 3
	phase5AgentResourceSamples     = 3
	phase5AgentResourceRSSInterval = 100 * time.Millisecond
	phase5AgentCgroupRoot          = "/sys/fs/cgroup"
	phase5AgentBPFFSRoot           = "/sys/fs/bpf"
)

func phase5AgentRunID(t *testing.T) string {
	t.Helper()
	runID := strings.TrimSpace(os.Getenv("ZTAP_PHASE5_RUN_ID"))
	if runID == "" {
		t.Fatal("ZTAP_PHASE5_RUN_ID is required for Phase 5 evidence")
	}
	return runID
}

type phase5AgentActivationEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	KernelRelease string    `json:"kernel_release"`
	CPUs          int       `json:"cpus"`
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

type phase5AgentReconciliationEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	KernelRelease string    `json:"kernel_release"`
	CPUs          int       `json:"cpus"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	Samples       int       `json:"samples"`
	ReconcileMS   []float64 `json:"reconcile_samples_ms"`
	ReconcileP95  float64   `json:"reconcile_p95_ms"`
	BudgetMS      float64   `json:"reconcile_budget_ms"`
	Scope         string    `json:"scope"`
}

type phase5AgentEventEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	KernelRelease string    `json:"kernel_release"`
	CPUs          int       `json:"cpus"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	EventMS       []float64 `json:"event_samples_ms"`
	EventP95      float64   `json:"event_p95_ms"`
	BudgetMS      float64   `json:"event_budget_ms"`
	Scope         string    `json:"scope"`
}

type phase5AgentPodStartEvidence struct {
	TimestampUTC           string    `json:"timestamp_utc"`
	RunID                  string    `json:"run_id"`
	GoVersion              string    `json:"go_version"`
	GOOS                   string    `json:"goos"`
	GOARCH                 string    `json:"goarch"`
	KernelRelease          string    `json:"kernel_release"`
	CPUs                   int       `json:"cpus"`
	Subjects               int       `json:"subjects"`
	Policies               int       `json:"policies"`
	Rules                  int       `json:"rules"`
	Samples                int       `json:"samples"`
	InitialClassifications int       `json:"initial_classifications"`
	PodStartMS             []float64 `json:"pod_start_classification_samples_ms"`
	PodStartP95            float64   `json:"pod_start_classification_p95_ms"`
	Scope                  string    `json:"scope"`
}

type phase5AgentRestartEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	KernelRelease string    `json:"kernel_release"`
	CPUs          int       `json:"cpus"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	RestartMS     []float64 `json:"restart_samples_ms"`
	RestartP95    float64   `json:"restart_p95_ms"`
	Scope         string    `json:"scope"`
}

type phase5AgentCrashEvidence struct {
	TimestampUTC  string    `json:"timestamp_utc"`
	RunID         string    `json:"run_id"`
	GoVersion     string    `json:"go_version"`
	GOOS          string    `json:"goos"`
	GOARCH        string    `json:"goarch"`
	KernelRelease string    `json:"kernel_release"`
	CPUs          int       `json:"cpus"`
	Subjects      int       `json:"subjects"`
	Policies      int       `json:"policies"`
	Rules         int       `json:"rules"`
	Samples       int       `json:"samples"`
	CrashGapMS    []float64 `json:"crash_fail_open_samples_ms"`
	CrashGapP95   float64   `json:"crash_fail_open_p95_ms"`
	Scope         string    `json:"scope"`
}

type phase5AgentResourceEvidence struct {
	TimestampUTC   string    `json:"timestamp_utc"`
	RunID          string    `json:"run_id"`
	GoVersion      string    `json:"go_version"`
	GOOS           string    `json:"goos"`
	GOARCH         string    `json:"goarch"`
	KernelRelease  string    `json:"kernel_release"`
	CPUs           int       `json:"cpus"`
	Subjects       int       `json:"subjects"`
	Policies       int       `json:"policies"`
	Rules          int       `json:"rules"`
	Samples        int       `json:"samples"`
	QuietSeconds   int       `json:"quiet_seconds"`
	ClockTicks     int64     `json:"process_clock_ticks_per_second"`
	CPUCoreSamples []float64 `json:"cpu_core_samples"`
	RSSMiBSamples  []float64 `json:"rss_mib_samples"`
	MaxCPUCore     float64   `json:"max_cpu_cores"`
	MaxRSSMiB      float64   `json:"max_rss_mib"`
	CPUBudgetCores float64   `json:"cpu_budget_cores"`
	RSSBudgetMiB   float64   `json:"rss_budget_mib"`
	Scope          string    `json:"scope"`
}

type phase5AgentFixture struct {
	Objects []k8sruntime.Object
}

// TestPhase5AgentActivation measures initial informer-cache synchronization,
// native policy compilation, cgroup resolution, and the first real engine
// apply for the documented fixture. It intentionally does not claim to measure
// a subsequent informer-event p95 or a Kubernetes rollout fail-open interval.
func TestPhase5AgentActivation(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	fixture := newPhase5AgentFixture(t)
	samples := make([]time.Duration, 0, phase5AgentSamples)
	for sample := 0; sample < phase5AgentSamples; sample++ {
		started := time.Now()
		if err := runPhase5AgentActivationSample(t, fixture.Objects); err != nil {
			t.Fatalf("agent activation sample %d: %v", sample+1, err)
		}
		samples = append(samples, time.Since(started))
	}

	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentActivationEvidence{
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         phase5AgentRunID(t),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		KernelRelease: phase5AgentKernelRelease(t),
		CPUs:          runtime.NumCPU(),
		CgroupRoot:    phase5AgentCgroupRoot,
		BPFFSRoot:     phase5AgentBPFFSRoot,
		Subjects:      phase5AgentSubjects,
		Policies:      phase5AgentPolicies,
		Rules:         phase5AgentRules,
		ActivationMS:  phase5AgentDurationsMilliseconds(samples),
		ActivationP95: float64(p95) / float64(time.Millisecond),
		BudgetMS:      3000,
		Scope:         "fake Kubernetes informer cache, exact containerd systemd cgroup resolution, native compilation, and real engine apply",
	}
	if p95 > 3*time.Second {
		t.Fatalf("initial agent activation p95 = %s, want <= 3s", p95)
	}
	writePhase5AgentEvidence(t, evidence)
}

// TestPhase5AgentReconciliation measures the actual native agent
// compile-and-apply path after the synchronized informer cache is ready. It
// excludes Kubernetes list latency and the fixed dirty-event debounce, and is
// kept separate from the user-visible activation and event-to-epoch gates.
func TestPhase5AgentReconciliation(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	fixture := newPhase5AgentFixture(t)
	samples := make([]time.Duration, 0, phase5AgentReconcileSamples)
	for sample := 0; sample < phase5AgentReconcileSamples; sample++ {
		agent := startPhase5Agent(t, fixture.Objects)
		metrics, err := waitPhase5AgentMetrics(agent, func(metrics string) bool {
			return phase5AgentIsActive(metrics) &&
				phase5MetricAtLeast(metrics, "ztap_policy_reconcile_duration_seconds_count", 1)
		}, 30*time.Second)
		if err != nil {
			agent.stop(t)
			t.Fatalf("reconciliation sample %d initial apply: %v", sample+1, err)
		}
		sum, ok := phase5MetricValue(metrics, "ztap_policy_reconcile_duration_seconds_sum")
		if !ok {
			agent.stop(t)
			t.Fatalf("reconciliation sample %d has no duration sum", sample+1)
		}
		count, ok := phase5MetricValue(metrics, "ztap_policy_reconcile_duration_seconds_count")
		if !ok || count != 1 {
			agent.stop(t)
			t.Fatalf("reconciliation sample %d duration count = %v, want exactly 1", sample+1, count)
		}
		if sum <= 0 {
			agent.stop(t)
			t.Fatalf("reconciliation sample %d duration sum = %v, want positive", sample+1, sum)
		}
		samples = append(samples, time.Duration(sum/count*float64(time.Second)))
		agent.stop(t)
	}

	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentReconciliationEvidence{
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         phase5AgentRunID(t),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		KernelRelease: phase5AgentKernelRelease(t),
		CPUs:          runtime.NumCPU(),
		Subjects:      phase5AgentSubjects,
		Policies:      phase5AgentPolicies,
		Rules:         phase5AgentRules,
		Samples:       phase5AgentReconcileSamples,
		ReconcileMS:   phase5AgentDurationsMilliseconds(samples),
		ReconcileP95:  float64(p95) / float64(time.Millisecond),
		BudgetMS:      2000,
		Scope:         "actual native agent compile-and-apply reconciliation after synchronized fake informer cache sync; excludes Kubernetes list latency and fixed dirty-event debounce",
	}
	if p95 > 2*time.Second {
		t.Fatalf("native agent reconciliation p95 = %s, want <= 2s", p95)
	}
	writePhase5AgentReconciliationEvidence(t, evidence)
}

// TestPhase5AgentEventActivation measures the time from a relevant cached
// NetworkPolicy update to the next active policy epoch. The fake client removes
// Kubernetes API and network latency from this synchronized-cache gate; the
// debounce, informer delivery, compilation, and real engine apply remain in
// the measured path.
func TestPhase5AgentEventActivation(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	fixture := newPhase5AgentFixture(t)
	samples := make([]time.Duration, 0, phase5AgentEventSamples)
	for sample := 0; sample < phase5AgentEventSamples; sample++ {
		agent := startPhase5Agent(t, fixture.Objects)
		initialMetrics, err := waitPhase5AgentMetrics(agent, func(metrics string) bool {
			return phase5AgentIsActive(metrics)
		}, 30*time.Second)
		if err != nil {
			agent.stop(t)
			t.Fatalf("event activation sample %d initial activation: %v", sample+1, err)
		}
		baselineEpoch, ok := phase5MetricValue(initialMetrics, "ztap_active_policy_epoch")
		if !ok {
			agent.stop(t)
			t.Fatalf("event activation sample %d has no active policy epoch", sample+1)
		}

		updatedPolicy := phase5UpdatedPolicy(t, fixture.Objects)
		started := time.Now()
		if _, err := agent.client.NetworkingV1().NetworkPolicies(updatedPolicy.Namespace).Update(context.Background(), updatedPolicy, metav1.UpdateOptions{}); err != nil {
			agent.stop(t)
			t.Fatalf("event activation sample %d update policy: %v", sample+1, err)
		}
		wantEpoch := baselineEpoch + 1
		if _, err := waitPhase5AgentMetrics(agent, func(metrics string) bool {
			return phase5AgentIsActive(metrics) &&
				phase5MetricAtLeast(metrics, "ztap_active_policy_epoch", wantEpoch)
		}, 30*time.Second); err != nil {
			agent.stop(t)
			t.Fatalf("event activation sample %d wait for epoch %.0f: %v", sample+1, wantEpoch, err)
		}
		samples = append(samples, time.Since(started))
		agent.stop(t)
	}

	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentEventEvidence{
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         phase5AgentRunID(t),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		KernelRelease: phase5AgentKernelRelease(t),
		CPUs:          runtime.NumCPU(),
		Subjects:      phase5AgentSubjects,
		Policies:      phase5AgentPolicies,
		Rules:         phase5AgentRules,
		EventMS:       phase5AgentDurationsMilliseconds(samples),
		EventP95:      float64(p95) / float64(time.Millisecond),
		BudgetMS:      3000,
		Scope:         "synchronized fake Kubernetes informer event, fixed debounce, native compilation, and real engine apply",
	}
	if p95 > 3*time.Second {
		t.Fatalf("synchronized informer event activation p95 = %s, want <= 3s", p95)
	}
	writePhase5AgentEventEvidence(t, evidence)
}

// TestPhase5AgentPodStartClassification measures the delay from a newly
// observed running Pod to its cgroup appearing in the next active policy. The
// fake client and pre-created cgroup remove API-server and container-runtime
// startup latency; the informer delivery, fixed debounce, snapshot rebuild,
// compilation, and real engine apply remain in the measured path.
func TestPhase5AgentPodStartClassification(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	fixture := newPhase5AgentFixture(t)
	samples := make([]time.Duration, 0, phase5AgentPodStartSamples)
	initialClassifications := 0
	for sample := 0; sample < phase5AgentPodStartSamples; sample++ {
		agent := startPhase5Agent(t, fixture.Objects)
		initialMetrics, err := waitPhase5AgentMetrics(agent, phase5AgentIsActive, 30*time.Second)
		if err != nil {
			agent.stop(t)
			t.Fatalf("Pod-start sample %d initial activation: %v", sample+1, err)
		}
		baseline, ok := phase5MetricValue(initialMetrics, "ztap_pod_start_classification_delay_seconds_count")
		if !ok {
			agent.stop(t)
			t.Fatalf("Pod-start sample %d has no classification histogram count", sample+1)
		}
		if sample == 0 {
			initialClassifications = int(baseline)
		}

		pod := newPhase5AgentPodStartFixture(t, 900+sample)
		started := time.Now()
		if _, err := agent.client.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			agent.stop(t)
			t.Fatalf("Pod-start sample %d create Pod: %v", sample+1, err)
		}
		if _, err := waitPhase5AgentMetrics(agent, func(metrics string) bool {
			return phase5MetricAtLeast(metrics, "ztap_pod_start_classification_delay_seconds_count", baseline+1) &&
				phase5AgentIsActiveFor(
					phase5AgentSubjects+1,
					phase5AgentRules+phase5AgentRules/phase5AgentSubjects,
				)(metrics)
		}, 30*time.Second); err != nil {
			agent.stop(t)
			t.Fatalf("Pod-start sample %d wait for classification: %v", sample+1, err)
		}
		samples = append(samples, time.Since(started))
		agent.stop(t)
	}

	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentPodStartEvidence{
		TimestampUTC:           time.Now().UTC().Format(time.RFC3339Nano),
		RunID:                  phase5AgentRunID(t),
		GoVersion:              runtime.Version(),
		GOOS:                   runtime.GOOS,
		GOARCH:                 runtime.GOARCH,
		KernelRelease:          phase5AgentKernelRelease(t),
		CPUs:                   runtime.NumCPU(),
		Subjects:               phase5AgentSubjects,
		Policies:               phase5AgentPolicies,
		Rules:                  phase5AgentRules,
		Samples:                phase5AgentPodStartSamples,
		InitialClassifications: initialClassifications,
		PodStartMS:             phase5AgentDurationsMilliseconds(samples),
		PodStartP95:            float64(p95) / float64(time.Millisecond),
		Scope:                  "new running Pod added to a synchronized fake informer cache with a pre-created exact containerd systemd cgroup; excludes API-server and container-runtime startup",
	}
	writePhase5AgentPodStartEvidence(t, evidence)
}

// TestPhase5AgentRestartGap records the process-owned enforcement gap after an
// orderly agent stop and replacement startup. It intentionally does not claim
// to measure a SIGKILL crash or a Kubernetes DaemonSet rolling update.
func TestPhase5AgentRestartGap(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	fixture := newPhase5AgentFixture(t)
	samples := make([]time.Duration, 0, phase5AgentRestartSamples)
	for sample := 0; sample < phase5AgentRestartSamples; sample++ {
		current := startPhase5Agent(t, fixture.Objects)
		if _, err := waitPhase5AgentMetrics(current, phase5AgentIsActive, 30*time.Second); err != nil {
			current.stop(t)
			t.Fatalf("restart gap sample %d initial activation: %v", sample+1, err)
		}
		stoppedAt := current.stopAt(t)

		replacement := startPhase5Agent(t, fixture.Objects)
		if _, err := waitPhase5AgentMetrics(replacement, phase5AgentIsActive, 30*time.Second); err != nil {
			replacement.stop(t)
			t.Fatalf("restart gap sample %d replacement activation: %v", sample+1, err)
		}
		samples = append(samples, time.Since(stoppedAt))
		replacement.stop(t)
	}

	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentRestartEvidence{
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         phase5AgentRunID(t),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		KernelRelease: phase5AgentKernelRelease(t),
		CPUs:          runtime.NumCPU(),
		Subjects:      phase5AgentSubjects,
		Policies:      phase5AgentPolicies,
		Rules:         phase5AgentRules,
		RestartMS:     phase5AgentDurationsMilliseconds(samples),
		RestartP95:    float64(p95) / float64(time.Millisecond),
		Scope:         "orderly process-owned engine shutdown followed by replacement startup and initial native policy apply; crash and DaemonSet rollout are excluded",
	}
	writePhase5AgentRestartEvidence(t, evidence)
}

// TestPhase5AgentCrashGap measures the packet-level fail-open interval after
// SIGKILL terminates a process that owns the native engine links. A separate
// helper continuously sends an allowed UDP packet only after the kill, so the
// first received packet is the first observable point after link detachment.
func TestPhase5AgentCrashGap(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	samples := make([]time.Duration, 0, phase5AgentCrashSamples)
	for sample := 0; sample < phase5AgentCrashSamples; sample++ {
		samples = append(samples, runPhase5AgentCrashSample(t, sample))
	}
	sorted := append([]time.Duration(nil), samples...)
	sortPhase5Durations(sorted)
	p95 := sorted[len(sorted)-1]
	evidence := phase5AgentCrashEvidence{
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         phase5AgentRunID(t),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		KernelRelease: phase5AgentKernelRelease(t),
		CPUs:          runtime.NumCPU(),
		Subjects:      phase5AgentSubjects,
		Policies:      phase5AgentPolicies,
		Rules:         phase5AgentRules,
		Samples:       phase5AgentCrashSamples,
		CrashGapMS:    phase5AgentDurationsMilliseconds(samples),
		CrashGapP95:   float64(p95) / float64(time.Millisecond),
		Scope:         "SIGKILL of a child process owning the real engine links after applying the full 250-Pod/25-policy/2,500-rule fixture, followed by an allowed UDP sender in one selected cgroup; Kubernetes restart scheduling and DaemonSet rollout are excluded",
	}
	writePhase5AgentCrashEvidence(t, evidence)
}

func runPhase5AgentCrashSample(t *testing.T, sample int) time.Duration {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen crash-gap UDP target: %v", err)
	}
	defer listener.Close()
	index := sample + 100
	cgroup := createPhase5AgentCrashCgroup(t, index)
	runDir := t.TempDir()
	// The helper creates the remaining fixture cgroups in a child process that
	// is intentionally SIGKILLed. Register cleanup in the parent, whose test
	// cleanup handlers still run after the child and sender have exited. The
	// parent also owns the helper run directory and stable engine-pin cleanup.
	registerPhase5AgentCrashFixtureCleanup(t, index)
	address := listener.LocalAddr().String()
	agentStatusListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve crash-gap agent status listener: %v", err)
	}
	agentStatusAddress := agentStatusListener.Addr().String()
	tcpListener, ok := agentStatusListener.(*net.TCPListener)
	if !ok {
		_ = agentStatusListener.Close()
		t.Fatalf("crash-gap agent status listener type = %T, want *net.TCPListener", agentStatusListener)
	}
	agentStatusListenerFile, err := tcpListener.File()
	if err != nil {
		_ = agentStatusListener.Close()
		t.Fatalf("export crash-gap agent status listener: %v", err)
	}

	agentStatusReader, agentStatusWriter, err := os.Pipe()
	if err != nil {
		_ = agentStatusListenerFile.Close()
		_ = agentStatusListener.Close()
		t.Fatalf("create crash-gap agent status pipe: %v", err)
	}
	agentCmd := exec.Command(os.Args[0], "-test.run", "^TestPhase5AgentCrashHelper$")
	agentCmd.Env = append(os.Environ(),
		"ZTAP_PHASE5_AGENT_CRASH_HELPER=1",
		"ZTAP_PHASE5_AGENT_CRASH_INDEX="+strconv.Itoa(index),
		"ZTAP_PHASE5_AGENT_CRASH_LISTEN="+address,
		"ZTAP_PHASE5_AGENT_CRASH_HTTP_LISTEN="+agentStatusAddress,
		"ZTAP_PHASE5_AGENT_RUN_DIR="+runDir,
	)
	agentCmd.ExtraFiles = []*os.File{agentStatusWriter, agentStatusListenerFile}
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr
	if err := agentCmd.Start(); err != nil {
		_ = agentStatusReader.Close()
		_ = agentStatusWriter.Close()
		_ = agentStatusListenerFile.Close()
		_ = agentStatusListener.Close()
		t.Fatalf("start crash-gap agent: %v", err)
	}
	if err := agentStatusListenerFile.Close(); err != nil {
		_ = agentStatusListener.Close()
		t.Fatalf("close parent crash-gap agent status listener file: %v", err)
	}
	if err := agentStatusListener.Close(); err != nil {
		t.Fatalf("release parent crash-gap agent status listener: %v", err)
	}
	t.Cleanup(func() {
		if agentCmd.ProcessState == nil {
			_ = agentCmd.Process.Kill()
			_ = agentCmd.Wait()
		}
		_ = agentStatusReader.Close()
	})
	_ = agentStatusWriter.Close()
	if got := readPhase5AgentStatusLine(t, agentStatusReader); strings.TrimSpace(got) != "ready" {
		t.Fatalf("crash-gap agent status = %q, want ready", got)
	}

	preReader, preWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create crash-gap sender pre-signal pipe: %v", err)
	}
	crashReader, crashWriter, err := os.Pipe()
	if err != nil {
		_ = preReader.Close()
		_ = preWriter.Close()
		t.Fatalf("create crash-gap sender kill-signal pipe: %v", err)
	}
	senderStatusReader, senderStatusWriter, err := os.Pipe()
	if err != nil {
		_ = preReader.Close()
		_ = preWriter.Close()
		_ = crashReader.Close()
		_ = crashWriter.Close()
		t.Fatalf("create crash-gap sender status pipe: %v", err)
	}
	senderCmd := exec.Command(os.Args[0], "-test.run", "^TestPhase5AgentCrashUDPSender$")
	senderCmd.Env = append(os.Environ(),
		"ZTAP_PHASE5_AGENT_CRASH_UDP_SENDER=1",
		"ZTAP_PHASE5_AGENT_CRASH_LISTEN="+address,
	)
	senderCmd.ExtraFiles = []*os.File{preReader, crashReader, senderStatusWriter}
	senderCmd.Stdout = os.Stdout
	senderCmd.Stderr = os.Stderr
	if err := senderCmd.Start(); err != nil {
		_ = preReader.Close()
		_ = preWriter.Close()
		_ = crashReader.Close()
		_ = crashWriter.Close()
		_ = senderStatusReader.Close()
		_ = senderStatusWriter.Close()
		t.Fatalf("start crash-gap UDP sender: %v", err)
	}
	t.Cleanup(func() {
		if senderCmd.ProcessState == nil {
			_ = senderCmd.Process.Kill()
			_ = senderCmd.Wait()
		}
		_ = senderStatusReader.Close()
	})
	_ = preReader.Close()
	_ = crashReader.Close()
	_ = senderStatusWriter.Close()
	movePhase5AgentProcessToCgroup(t, senderCmd, cgroup)
	if _, err := preWriter.Write([]byte{'1'}); err != nil {
		t.Fatalf("release crash-gap UDP sender: %v", err)
	}
	_ = preWriter.Close()
	if got := readPhase5AgentStatusLine(t, senderStatusReader); strings.TrimSpace(got) != "pre" {
		t.Fatalf("crash-gap sender pre-status = %q, want pre", got)
	}
	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set crash-gap pre-packet deadline: %v", err)
	}
	var packet [32]byte
	if _, _, err := listener.ReadFromUDP(packet[:]); err != nil {
		t.Fatalf("read allowed pre-crash packet: %v", err)
	}

	crashStarted := time.Now()
	if err := agentCmd.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL crash-gap agent: %v", err)
	}
	if err := agentCmd.Wait(); err == nil {
		t.Fatal("crash-gap agent exited cleanly; want SIGKILL termination")
	}
	if _, err := crashWriter.Write([]byte{'1'}); err != nil {
		t.Fatalf("release crash-gap sender after SIGKILL: %v", err)
	}
	_ = crashWriter.Close()
	if err := listener.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set crash-gap post-kill deadline: %v", err)
	}
	for {
		n, _, readErr := listener.ReadFromUDP(packet[:])
		if readErr != nil {
			t.Fatalf("read first post-crash packet: %v", readErr)
		}
		if string(packet[:n]) == "crash" {
			_ = senderCmd.Process.Kill()
			_ = senderCmd.Wait()
			return time.Since(crashStarted)
		}
	}
}

func TestPhase5AgentCrashHelper(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_AGENT_CRASH_HELPER") != "1" {
		t.Skip("helper")
	}
	status := os.NewFile(uintptr(3), "status")
	if status == nil {
		t.Fatal("crash-gap agent status pipe is missing")
	}
	defer status.Close()
	listenerFile := os.NewFile(uintptr(4), "status-listener")
	if listenerFile == nil {
		t.Fatal("crash-gap agent status listener is missing")
	}
	statusListener, err := net.FileListener(listenerFile)
	closeErr := listenerFile.Close()
	if err != nil {
		t.Fatalf("open crash-gap agent status listener: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close crash-gap agent status listener file: %v", closeErr)
	}
	defer statusListener.Close()
	index, err := strconv.Atoi(os.Getenv("ZTAP_PHASE5_AGENT_CRASH_INDEX"))
	if err != nil {
		t.Fatalf("parse crash-gap fixture index: %v", err)
	}
	listen := os.Getenv("ZTAP_PHASE5_AGENT_CRASH_LISTEN")
	if listen == "" {
		t.Fatal("ZTAP_PHASE5_AGENT_CRASH_LISTEN is required")
	}
	statusListen := os.Getenv("ZTAP_PHASE5_AGENT_CRASH_HTTP_LISTEN")
	if statusListen == "" {
		t.Fatal("ZTAP_PHASE5_AGENT_CRASH_HTTP_LISTEN is required")
	}
	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatalf("parse crash-gap listener: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse crash-gap listener port: %v", err)
	}
	agent := startPhase5AgentWithListen(t, newPhase5AgentCrashObjects(t, index, port), statusListen, statusListener)
	if _, err := waitPhase5AgentMetrics(agent, phase5AgentIsActive, 30*time.Second); err != nil {
		agent.stop(t)
		t.Fatalf("crash-gap agent activation: %v", err)
	}
	if _, err := fmt.Fprintln(status, "ready"); err != nil {
		t.Fatalf("signal crash-gap agent readiness: %v", err)
	}
	select {}
}

func TestPhase5AgentCrashUDPSender(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_AGENT_CRASH_UDP_SENDER") != "1" {
		t.Skip("helper")
	}
	pre := os.NewFile(uintptr(3), "pre")
	crash := os.NewFile(uintptr(4), "crash")
	status := os.NewFile(uintptr(5), "status")
	if pre == nil || crash == nil || status == nil {
		t.Fatal("crash-gap UDP sender pipes are missing")
	}
	defer pre.Close()
	defer crash.Close()
	defer status.Close()
	listen := os.Getenv("ZTAP_PHASE5_AGENT_CRASH_LISTEN")
	connection, err := net.DialTimeout("udp4", listen, 2*time.Second)
	if err != nil {
		t.Fatalf("dial crash-gap UDP target: %v", err)
	}
	defer connection.Close()
	if _, err := io.ReadFull(pre, make([]byte, 1)); err != nil {
		t.Fatalf("read crash-gap pre-signal: %v", err)
	}
	if _, err := connection.Write([]byte("pre")); err != nil {
		t.Fatalf("write pre-crash packet: %v", err)
	}
	if _, err := fmt.Fprintln(status, "pre"); err != nil {
		t.Fatalf("signal pre-crash packet: %v", err)
	}
	if _, err := io.ReadFull(crash, make([]byte, 1)); err != nil {
		t.Fatalf("read crash-gap post-kill signal: %v", err)
	}
	for attempt := 0; attempt < 10000; attempt++ {
		if _, err := connection.Write([]byte("crash")); err != nil {
			t.Fatalf("write post-crash packet: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	_, _ = fmt.Fprintln(status, "done")
}

// TestPhase5AgentResourceUsage samples a dedicated helper process after the
// real agent reaches the active state. The helper contains only the agent,
// fake Kubernetes client, and the test binary runtime; it is supporting data,
// not a claim about a quiet production cluster with a real API server.
func TestPhase5AgentResourceUsage(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup agent harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("agent performance harness requires root privileges")
	}

	cpuSamples := make([]float64, 0, phase5AgentResourceSamples)
	rssSamples := make([]float64, 0, phase5AgentResourceSamples)
	clockTicks := phase5ProcessClockTicks(t)
	for sample := 0; sample < phase5AgentResourceSamples; sample++ {
		cpuCores, rssMiB := runPhase5AgentResourceSample(t, clockTicks)
		cpuSamples = append(cpuSamples, cpuCores)
		rssSamples = append(rssSamples, rssMiB)
	}
	maxCPU := 0.0
	maxRSS := 0.0
	for index := range cpuSamples {
		if cpuSamples[index] > maxCPU {
			maxCPU = cpuSamples[index]
		}
		if rssSamples[index] > maxRSS {
			maxRSS = rssSamples[index]
		}
	}
	evidence := phase5AgentResourceEvidence{
		TimestampUTC:   time.Now().UTC().Format(time.RFC3339Nano),
		RunID:          phase5AgentRunID(t),
		GoVersion:      runtime.Version(),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		KernelRelease:  phase5AgentKernelRelease(t),
		CPUs:           runtime.NumCPU(),
		Subjects:       phase5AgentSubjects,
		Policies:       phase5AgentPolicies,
		Rules:          phase5AgentRules,
		Samples:        phase5AgentResourceSamples,
		QuietSeconds:   phase5AgentResourceQuietSeconds,
		ClockTicks:     clockTicks,
		CPUCoreSamples: cpuSamples,
		RSSMiBSamples:  rssSamples,
		MaxCPUCore:     maxCPU,
		MaxRSSMiB:      maxRSS,
		CPUBudgetCores: 0.10,
		RSSBudgetMiB:   200,
		Scope:          "dedicated helper process running the native agent with a fake Kubernetes client and the 250-Pod/25-policy/2,500-rule fixture; kernel-map memory is excluded",
	}
	if maxCPU > evidence.CPUBudgetCores {
		t.Fatalf("quiet agent CPU = %.3f cores, want <= %.2f", maxCPU, evidence.CPUBudgetCores)
	}
	if maxRSS > evidence.RSSBudgetMiB {
		t.Fatalf("quiet agent RSS = %.1f MiB, want <= %.0f MiB", maxRSS, evidence.RSSBudgetMiB)
	}
	writePhase5AgentResourceEvidence(t, evidence)
}

const phase5AgentResourceQuietSeconds = 5

func TestPhase5AgentResourceHelper(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_AGENT_RESOURCE_HELPER") != "1" {
		t.Skip("helper")
	}
	status := os.NewFile(uintptr(3), "status")
	if status == nil {
		t.Fatal("resource helper status pipe is missing")
	}
	defer status.Close()
	listenerFile := os.NewFile(uintptr(4), "status-listener")
	if listenerFile == nil {
		t.Fatal("resource helper status listener is missing")
	}
	statusListener, err := net.FileListener(listenerFile)
	closeErr := listenerFile.Close()
	if err != nil {
		t.Fatalf("open resource helper status listener: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close resource helper status listener file: %v", closeErr)
	}
	defer statusListener.Close()
	listen := os.Getenv("ZTAP_PHASE5_AGENT_RESOURCE_LISTEN")
	if listen == "" {
		t.Fatal("ZTAP_PHASE5_AGENT_RESOURCE_LISTEN is required")
	}
	fixture := newPhase5AgentFixture(t)
	agent := startPhase5AgentWithListen(t, fixture.Objects, listen, statusListener)
	if _, err := waitPhase5AgentMetrics(agent, phase5AgentIsActive, 30*time.Second); err != nil {
		agent.stop(t)
		t.Fatalf("resource helper activation: %v", err)
	}
	if _, err := fmt.Fprintln(status, "ready"); err != nil {
		agent.stop(t)
		t.Fatalf("signal resource helper readiness: %v", err)
	}
	time.Sleep(time.Duration(phase5AgentResourceQuietSeconds+5) * time.Second)
	agent.stop(t)
}

func startPhase5AgentWithListen(t *testing.T, objects []k8sruntime.Object, listen string, supplied ...net.Listener) *phase5AgentProcess {
	t.Helper()
	if len(supplied) > 1 {
		t.Fatal("received more than one status listener")
	}
	var statusListener net.Listener
	if len(supplied) == 1 {
		statusListener = supplied[0]
	}
	client := fake.NewSimpleClientset(objects...)
	ctx, cancel := context.WithCancel(context.Background())
	agent := &phase5AgentProcess{
		client:  client,
		address: listen,
		cancel:  cancel,
		done:    make(chan error, 1),
	}
	runDir := strings.TrimSpace(os.Getenv("ZTAP_PHASE5_AGENT_RUN_DIR"))
	if runDir == "" {
		runDir = t.TempDir()
	} else {
		ensurePhase5AgentRunDirectory(t, runDir)
	}
	go func() {
		agent.done <- runNativeKubernetesAgent(ctx, client, NativeAgentOptions{
			NodeName:       "node-a",
			CgroupRoot:     phase5AgentCgroupRoot,
			BPFFSRoot:      phase5AgentBPFFSRoot,
			RunDir:         runDir,
			Listen:         listen,
			StatusListener: statusListener,
		})
	}()
	return agent
}

func runPhase5AgentResourceSample(t *testing.T, clockTicks int64) (float64, float64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve resource helper listener: %v", err)
	}
	address := listener.Addr().String()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		t.Fatalf("resource helper listener type = %T, want *net.TCPListener", listener)
	}
	listenerFile, err := tcpListener.File()
	if err != nil {
		_ = listener.Close()
		t.Fatalf("export resource helper listener: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = listenerFile.Close()
		_ = listener.Close()
		t.Fatalf("create resource helper status pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestPhase5AgentResourceHelper$")
	cmd.Env = append(os.Environ(), "ZTAP_PHASE5_AGENT_RESOURCE_HELPER=1", "ZTAP_PHASE5_AGENT_RESOURCE_LISTEN="+address)
	cmd.ExtraFiles = []*os.File{statusWriter, listenerFile}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = statusReader.Close()
		_ = statusWriter.Close()
		_ = listenerFile.Close()
		_ = listener.Close()
		t.Fatalf("start resource helper: %v", err)
	}
	if err := listenerFile.Close(); err != nil {
		_ = listener.Close()
		t.Fatalf("close parent resource helper listener file: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("release parent resource helper listener: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = statusReader.Close()
	})
	_ = statusWriter.Close()
	if got := readPhase5AgentStatusLine(t, statusReader); strings.TrimSpace(got) != "ready" {
		t.Fatalf("resource helper status = %q, want ready", got)
	}
	startUsage, err := readPhase5ProcessUsage(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("read resource helper start usage: %v", err)
	}
	rssBytes := phase5MaxRSSBytes(startUsage.rssBytes)
	started := time.Now()
	sampleTicker := time.NewTicker(phase5AgentResourceRSSInterval)
	sampleTimer := time.NewTimer(phase5AgentResourceQuietSeconds * time.Second)
	sampling := true
	for sampling {
		select {
		case <-sampleTicker.C:
			usage, sampleErr := readPhase5ProcessUsage(cmd.Process.Pid)
			if sampleErr != nil {
				sampleTicker.Stop()
				sampleTimer.Stop()
				t.Fatalf("read resource helper RSS sample: %v", sampleErr)
			}
			rssBytes = phase5MaxRSSBytes(rssBytes, usage.rssBytes)
		case <-sampleTimer.C:
			sampling = false
		}
	}
	sampleTicker.Stop()
	endUsage, err := readPhase5ProcessUsage(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("read resource helper end usage: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("resource helper: %v", err)
	}
	elapsed := time.Since(started)
	if elapsed <= 0 {
		t.Fatal("resource helper sample duration is not positive")
	}
	cpuCores, err := phase5CPUCoreUsage(startUsage.cpuTicks, endUsage.cpuTicks, clockTicks, elapsed)
	if err != nil {
		t.Fatalf("calculate resource helper CPU usage: %v", err)
	}
	rssBytes = phase5MaxRSSBytes(rssBytes, endUsage.rssBytes)
	rssMiB := float64(rssBytes) / (1024 * 1024)
	return cpuCores, rssMiB
}

func phase5CPUCoreUsage(startTicks, endTicks uint64, clockTicks int64, elapsed time.Duration) (float64, error) {
	if clockTicks <= 0 {
		return 0, fmt.Errorf("clock ticks per second must be positive, got %d", clockTicks)
	}
	if elapsed <= 0 {
		return 0, fmt.Errorf("elapsed duration must be positive, got %s", elapsed)
	}
	if endTicks < startTicks {
		return 0, fmt.Errorf("end CPU ticks %d precede start CPU ticks %d", endTicks, startTicks)
	}
	return float64(endTicks-startTicks) / (float64(clockTicks) * elapsed.Seconds()), nil
}

func TestPhase5AgentCPUCoreUsage(t *testing.T) {
	got, err := phase5CPUCoreUsage(100, 150, 100, time.Second)
	if err != nil {
		t.Fatalf("calculate positive CPU usage: %v", err)
	}
	if got != 0.5 {
		t.Fatalf("CPU usage = %v, want 0.5", got)
	}
	got, err = phase5CPUCoreUsage(100, 100, 100, time.Second)
	if err != nil {
		t.Fatalf("calculate zero CPU usage: %v", err)
	}
	if got != 0 {
		t.Fatalf("zero CPU usage = %v, want 0", got)
	}
	for _, test := range []struct {
		name       string
		start      uint64
		end        uint64
		clockTicks int64
		elapsed    time.Duration
	}{
		{name: "decreasing ticks", start: 2, end: 1, clockTicks: 100, elapsed: time.Second},
		{name: "zero clock", start: 1, end: 2, clockTicks: 0, elapsed: time.Second},
		{name: "zero elapsed", start: 1, end: 2, clockTicks: 100, elapsed: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := phase5CPUCoreUsage(test.start, test.end, test.clockTicks, test.elapsed); err == nil {
				t.Fatal("phase5CPUCoreUsage accepted invalid measurement inputs")
			}
		})
	}
}

func phase5ProcessClockTicks(t *testing.T) int64 {
	t.Helper()
	output, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		t.Fatalf("read process clock ticks: %v", err)
	}
	clockTicks, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || clockTicks <= 0 {
		t.Fatalf("invalid process clock ticks %q: %v", strings.TrimSpace(string(output)), err)
	}
	return clockTicks
}

func readPhase5ProcessUsage(pid int) (phase5ProcessStats, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return phase5ProcessStats{}, err
	}
	closeParen := strings.LastIndex(string(stat), ")")
	if closeParen < 0 || closeParen+2 >= len(stat) {
		return phase5ProcessStats{}, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(stat[closeParen+2:]))
	if len(fields) <= 12 {
		return phase5ProcessStats{}, errors.New("process stat is missing CPU fields")
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return phase5ProcessStats{}, fmt.Errorf("parse process user ticks: %w", err)
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return phase5ProcessStats{}, fmt.Errorf("parse process system ticks: %w", err)
	}
	statm, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return phase5ProcessStats{}, err
	}
	statmFields := strings.Fields(string(statm))
	if len(statmFields) < 2 {
		return phase5ProcessStats{}, errors.New("process statm is missing resident pages")
	}
	residentPages, err := strconv.ParseUint(statmFields[1], 10, 64)
	if err != nil {
		return phase5ProcessStats{}, fmt.Errorf("parse resident pages: %w", err)
	}
	return phase5ProcessStatsFromCounters(userTicks, systemTicks, residentPages, os.Getpagesize())
}

func readPhase5AgentStatusLine(t *testing.T, reader *os.File) string {
	t.Helper()
	result := make(chan struct {
		line string
		err  error
	}, 1)
	go func() {
		line, err := bufio.NewReader(reader).ReadString('\n')
		result <- struct {
			line string
			err  error
		}{line: line, err: err}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatalf("read resource helper status: %v", value.err)
		}
		return value.line
	case <-time.After(40 * time.Second):
		_ = reader.Close()
		t.Fatal("timed out reading resource helper status")
		return ""
	}
}

func phase5AgentIsActive(metrics string) bool {
	return phase5AgentIsActiveFor(phase5AgentSubjects, phase5AgentRules)(metrics)
}

func TestPhase5AgentMetricPredicatesRequireExactFixtureState(t *testing.T) {
	base := strings.Join([]string{
		"ztap_agent_enforcing 1",
		"ztap_enforced_cgroups 250",
		"ztap_compiled_rules 2500",
		"ztap_active_policy_epoch 1",
	}, "\n")
	if !phase5AgentIsActive(base) {
		t.Fatal("exact Phase 5 fixture metrics were rejected")
	}
	for name, values := range map[string][2]string{
		"ztap_enforced_cgroups": {"250", "251"},
		"ztap_compiled_rules":   {"2500", "2501"},
	} {
		metrics := strings.Replace(base, name+" "+values[0], name+" "+values[1], 1)
		if phase5AgentIsActive(metrics) {
			t.Fatalf("extra %s state was accepted: %s", name, values[1])
		}
	}
	for name, value := range map[string]string{
		"ztap_agent_enforcing":     "1",
		"ztap_enforced_cgroups":    "250",
		"ztap_compiled_rules":      "2500",
		"ztap_active_policy_epoch": "1",
	} {
		metrics := base + "\n" + name + " " + value
		if phase5AgentIsActive(metrics) {
			t.Fatalf("duplicate %s metric sample was accepted", name)
		}
	}
	for name, value := range map[string]string{
		"ztap_agent_enforcing":     "1",
		"ztap_enforced_cgroups":    "250",
		"ztap_compiled_rules":      "2500",
		"ztap_active_policy_epoch": "1",
	} {
		metrics := base + "\n" + name + `{unexpected="label"} ` + value
		if phase5AgentIsActive(metrics) {
			t.Fatalf("labelled %s metric sample was accepted", name)
		}
	}
	for _, value := range []string{"NaN", "+Inf", "-Inf"} {
		metrics := strings.Replace(base, "ztap_active_policy_epoch 1", "ztap_active_policy_epoch "+value, 1)
		if phase5AgentIsActive(metrics) {
			t.Fatalf("non-finite active policy epoch was accepted: %s", value)
		}
	}
	podStartRules := phase5AgentRules + phase5AgentRules/phase5AgentSubjects
	podStart := strings.Join([]string{
		"ztap_agent_enforcing 1",
		fmt.Sprintf("ztap_enforced_cgroups %d", phase5AgentSubjects+1),
		fmt.Sprintf("ztap_compiled_rules %d", podStartRules),
		"ztap_active_policy_epoch 2",
	}, "\n")
	if !phase5AgentIsActiveFor(phase5AgentSubjects+1, podStartRules)(podStart) {
		t.Fatal("exact Pod-start fixture metrics were rejected")
	}
	for name, values := range map[string][2]string{
		"ztap_enforced_cgroups": {"251", "250"},
		"ztap_compiled_rules":   {strconv.Itoa(podStartRules), strconv.Itoa(phase5AgentRules)},
	} {
		metrics := strings.Replace(podStart, name+" "+values[0], name+" "+values[1], 1)
		if phase5AgentIsActiveFor(phase5AgentSubjects+1, podStartRules)(metrics) {
			t.Fatalf("incomplete Pod-start %s state was accepted: %s", name, values[1])
		}
	}
}

func phase5AgentIsActiveFor(subjects, rules int) func(string) bool {
	return func(metrics string) bool {
		return phase5MetricEquals(metrics, "ztap_agent_enforcing", 1) &&
			phase5MetricEquals(metrics, "ztap_enforced_cgroups", float64(subjects)) &&
			phase5MetricEquals(metrics, "ztap_compiled_rules", float64(rules)) &&
			phase5MetricAtLeast(metrics, "ztap_active_policy_epoch", 1)
	}
}

func phase5UpdatedPolicy(t *testing.T, objects []k8sruntime.Object) *networkingv1.NetworkPolicy {
	t.Helper()
	for _, object := range objects {
		policyObject, ok := object.(*networkingv1.NetworkPolicy)
		if !ok {
			continue
		}
		updated := policyObject.DeepCopy()
		if len(updated.Spec.Egress) == 0 || len(updated.Spec.Egress[0].Ports) == 0 || updated.Spec.Egress[0].Ports[0].Port == nil {
			t.Fatalf("reference policy %s/%s has no numeric egress port", updated.Namespace, updated.Name)
		}
		updated.Generation++
		port := intstr.FromInt(int(updated.Spec.Egress[0].Ports[0].Port.IntVal) + 1)
		updated.Spec.Egress[0].Ports[0].Port = &port
		return updated
	}
	t.Fatal("reference fixture has no NetworkPolicy")
	return nil
}

func newPhase5AgentFixture(t *testing.T) phase5AgentFixture {
	t.Helper()
	qosRoot := filepath.Join(phase5AgentCgroupRoot, "kubepods.slice", "kubepods-burstable.slice")
	ensurePhase5CgroupDir(t, filepath.Dir(qosRoot))
	ensurePhase5CgroupDir(t, qosRoot)

	objects := make([]k8sruntime.Object, 0, phase5AgentSubjects+phase5AgentPolicies+2)
	objects = append(objects,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
				Type:    corev1.NodeInternalIP,
				Address: "192.0.2.10",
			}}},
		},
	)
	for index := 0; index < phase5AgentSubjects; index++ {
		uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
		containerID := fmt.Sprintf("%064x", index+1)
		podName := fmt.Sprintf("reference-pod-%03d", index)
		bucket := fmt.Sprintf("%02d", index/(phase5AgentSubjects/phase5AgentPolicies))
		podSlice := filepath.Join(qosRoot, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
		cgroupPath := filepath.Join(podSlice, "cri-containerd-"+containerID+".scope")
		createPhase5CgroupDir(t, podSlice)
		createPhase5CgroupDir(t, cgroupPath)
		objects = append(objects, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: "default",
				UID:       types.UID(uid),
				Labels:    map[string]string{"reference-bucket": bucket},
			},
			Spec: corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				Phase:    corev1.PodRunning,
				PodIP:    fmt.Sprintf("10.0.1.%d", index+1),
				PodIPs:   []corev1.PodIP{{IP: fmt.Sprintf("10.0.1.%d", index+1)}},
				QOSClass: corev1.PodQOSBurstable,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:        "agent-test",
					ContainerID: "containerd://" + containerID,
					State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}},
			},
		})
	}

	protocol := corev1.ProtocolTCP
	for policyIndex := 0; policyIndex < phase5AgentPolicies; policyIndex++ {
		bucket := fmt.Sprintf("%02d", policyIndex)
		port := intstr.FromInt(10000 + policyIndex)
		peers := make([]networkingv1.NetworkPolicyPeer, 0, phase5AgentRules/phase5AgentPolicies/(phase5AgentSubjects/phase5AgentPolicies))
		for peerIndex := 0; peerIndex < 10; peerIndex++ {
			peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{
				CIDR: fmt.Sprintf("203.0.113.%d/32", policyIndex*10+peerIndex+1),
			}})
		}
		objects = append(objects, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "reference-policy-" + bucket, Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"reference-bucket": bucket}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To:    peers,
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
				}},
			},
		})
	}
	validatePhase5AgentFixtureShape(t, objects)
	return phase5AgentFixture{Objects: objects}
}

func newPhase5AgentPodStartFixture(t *testing.T, index int) *corev1.Pod {
	t.Helper()
	uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
	containerID := fmt.Sprintf("%064x", index+1)
	qosRoot := filepath.Join(phase5AgentCgroupRoot, "kubepods.slice", "kubepods-burstable.slice")
	podSlice := filepath.Join(qosRoot, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	cgroupPath := filepath.Join(podSlice, "cri-containerd-"+containerID+".scope")
	createPhase5CgroupDir(t, podSlice)
	createPhase5CgroupDir(t, cgroupPath)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("phase5-pod-start-%03d", index),
			Namespace: "default",
			UID:       types.UID(uid),
			Labels:    map[string]string{"reference-bucket": "00"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			Phase:    corev1.PodRunning,
			PodIP:    "10.0.2.1",
			PodIPs:   []corev1.PodIP{{IP: "10.0.2.1"}},
			QOSClass: corev1.PodQOSBurstable,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "agent-test",
				ContainerID: "containerd://" + containerID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
}

func createPhase5AgentCrashCgroup(t *testing.T, index int) string {
	t.Helper()
	qosRoot := filepath.Join(phase5AgentCgroupRoot, "kubepods.slice", "kubepods-burstable.slice")
	ensurePhase5CgroupDir(t, filepath.Dir(qosRoot))
	ensurePhase5CgroupDir(t, qosRoot)
	uid := phase5AgentCrashUID(index)
	containerID := fmt.Sprintf("%064x", index+1)
	podSlice := filepath.Join(qosRoot, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	cgroupPath := filepath.Join(podSlice, "cri-containerd-"+containerID+".scope")
	createPhase5CgroupDir(t, podSlice)
	createPhase5CgroupDir(t, cgroupPath)
	return cgroupPath
}

func phase5AgentCrashUID(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
}

func newPhase5AgentCrashObjects(t *testing.T, index, port int) []k8sruntime.Object {
	t.Helper()
	qosRoot := filepath.Join(phase5AgentCgroupRoot, "kubepods.slice", "kubepods-burstable.slice")
	ensurePhase5CgroupDir(t, filepath.Dir(qosRoot))
	ensurePhase5CgroupDir(t, qosRoot)
	objects := make([]k8sruntime.Object, 0, phase5AgentSubjects+phase5AgentPolicies+2)
	objects = append(objects,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
				Type:    corev1.NodeInternalIP,
				Address: "192.0.2.10",
			}}},
		},
	)
	for subjectIndex := 0; subjectIndex < phase5AgentSubjects; subjectIndex++ {
		uid, containerID := phase5CrashFixtureIdentity(index, subjectIndex)
		if subjectIndex != 0 {
			podSlice := filepath.Join(qosRoot, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
			createPhase5CgroupDir(t, podSlice)
			createPhase5CgroupDir(t, filepath.Join(podSlice, "cri-containerd-"+containerID+".scope"))
		}
		bucket := fmt.Sprintf("%02d", subjectIndex/(phase5AgentSubjects/phase5AgentPolicies))
		objects = append(objects, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("reference-pod-%03d", subjectIndex),
				Namespace: "default",
				UID:       types.UID(uid),
				Labels:    map[string]string{"reference-bucket": bucket},
			},
			Spec: corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				Phase:    corev1.PodRunning,
				PodIP:    fmt.Sprintf("10.0.4.%d", subjectIndex+1),
				PodIPs:   []corev1.PodIP{{IP: fmt.Sprintf("10.0.4.%d", subjectIndex+1)}},
				QOSClass: corev1.PodQOSBurstable,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:        "agent-test",
					ContainerID: "containerd://" + containerID,
					State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}},
			},
		})
	}

	for policyIndex := 0; policyIndex < phase5AgentPolicies; policyIndex++ {
		bucket := fmt.Sprintf("%02d", policyIndex)
		protocol := corev1.ProtocolTCP
		portValue := intstr.FromInt(10000 + policyIndex)
		peers := make([]networkingv1.NetworkPolicyPeer, 0, 10)
		for peerIndex := 0; peerIndex < 10; peerIndex++ {
			cidr := fmt.Sprintf("203.0.113.%d/32", policyIndex*10+peerIndex+1)
			if policyIndex == 0 && peerIndex == 0 {
				cidr = "127.0.0.0/8"
				protocol = corev1.ProtocolUDP
				portValue = intstr.FromInt(port)
			}
			peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
		}
		objects = append(objects, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "reference-policy-" + bucket, Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"reference-bucket": bucket}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To:    peers,
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &portValue}},
				}},
			},
		})
	}
	validatePhase5AgentFixtureShape(t, objects)
	return objects
}

func validatePhase5AgentFixtureShape(t *testing.T, objects []k8sruntime.Object) {
	t.Helper()
	if phase5AgentSubjects%phase5AgentPolicies != 0 || phase5AgentRules%phase5AgentSubjects != 0 {
		t.Fatalf("Phase 5 fixture constants do not describe an integral policy shape: subjects=%d policies=%d rules=%d", phase5AgentSubjects, phase5AgentPolicies, phase5AgentRules)
	}
	wantPodsPerBucket := phase5AgentSubjects / phase5AgentPolicies
	wantPeersPerPolicy := phase5AgentRules / phase5AgentSubjects
	wantObjects := phase5AgentSubjects + phase5AgentPolicies + 2
	if len(objects) != wantObjects {
		t.Fatalf("Phase 5 agent fixture object count = %d, want %d", len(objects), wantObjects)
	}

	namespaces := 0
	nodes := 0
	pods := 0
	policies := 0
	podsByBucket := make(map[string]int, phase5AgentPolicies)
	peersByBucket := make(map[string]int, phase5AgentPolicies)
	podNames := make(map[string]struct{}, phase5AgentSubjects)
	podUIDs := make(map[types.UID]struct{}, phase5AgentSubjects)
	policyNames := make(map[string]struct{}, phase5AgentPolicies)
	for _, object := range objects {
		switch typed := object.(type) {
		case *corev1.Namespace:
			namespaces++
			if typed.Name != "default" {
				t.Fatalf("Phase 5 agent fixture namespace = %q, want default", typed.Name)
			}
		case *corev1.Node:
			nodes++
			if typed.Name != "node-a" {
				t.Fatalf("Phase 5 agent fixture node = %q, want node-a", typed.Name)
			}
		case *corev1.Pod:
			pods++
			if typed.Namespace != "default" || typed.Spec.NodeName != "node-a" {
				t.Fatalf("Phase 5 agent fixture Pod %s/%s is not on default/node-a", typed.Namespace, typed.Name)
			}
			podIndex := phase5AgentFixtureIndex(t, typed.Name, "reference-pod-", 3, phase5AgentSubjects)
			podKey := typed.Namespace + "/" + typed.Name
			if _, duplicate := podNames[podKey]; duplicate {
				t.Fatalf("Phase 5 agent fixture repeats Pod %s", podKey)
			}
			podNames[podKey] = struct{}{}
			if typed.UID == "" {
				t.Fatalf("Phase 5 agent fixture Pod %s has an empty UID", podKey)
			}
			if _, duplicate := podUIDs[typed.UID]; duplicate {
				t.Fatalf("Phase 5 agent fixture repeats Pod UID %q", typed.UID)
			}
			podUIDs[typed.UID] = struct{}{}
			if typed.Status.Phase != corev1.PodRunning || len(typed.Status.ContainerStatuses) != 1 {
				t.Fatalf("Phase 5 agent fixture Pod %s has phase %q and %d container statuses, want Running and one status", podKey, typed.Status.Phase, len(typed.Status.ContainerStatuses))
			}
			bucket, ok := typed.Labels["reference-bucket"]
			wantBucket := fmt.Sprintf("%02d", podIndex/wantPodsPerBucket)
			if len(typed.Labels) != 1 || !ok || bucket != wantBucket {
				t.Fatalf("Phase 5 agent fixture Pod %s/%s has no reference bucket", typed.Namespace, typed.Name)
			}
			podsByBucket[bucket]++
		case *networkingv1.NetworkPolicy:
			policies++
			if typed.Namespace != "default" {
				t.Fatalf("Phase 5 agent fixture policy %s/%s is not in default", typed.Namespace, typed.Name)
			}
			policyIndex := phase5AgentFixtureIndex(t, typed.Name, "reference-policy-", 2, phase5AgentPolicies)
			policyKey := typed.Namespace + "/" + typed.Name
			if _, duplicate := policyNames[policyKey]; duplicate {
				t.Fatalf("Phase 5 agent fixture repeats policy %s", policyKey)
			}
			policyNames[policyKey] = struct{}{}
			bucket, ok := typed.Spec.PodSelector.MatchLabels["reference-bucket"]
			wantBucket := fmt.Sprintf("%02d", policyIndex)
			if len(typed.Spec.PodSelector.MatchLabels) != 1 || !ok || bucket != wantBucket {
				t.Fatalf("Phase 5 agent fixture policy %s/%s has no reference bucket selector", typed.Namespace, typed.Name)
			}
			if len(typed.Spec.PolicyTypes) != 1 || typed.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress || len(typed.Spec.Egress) != 1 {
				t.Fatalf("Phase 5 agent fixture policy %s has unexpected directional shape", policyKey)
			}
			if len(typed.Spec.Egress[0].To) != wantPeersPerPolicy || len(typed.Spec.Egress[0].Ports) != 1 {
				t.Fatalf("Phase 5 agent fixture policy %s has %d peers and %d ports, want %d and one", policyKey, len(typed.Spec.Egress[0].To), len(typed.Spec.Egress[0].Ports), wantPeersPerPolicy)
			}
			for peerIndex, peer := range typed.Spec.Egress[0].To {
				if peer.IPBlock == nil || peer.IPBlock.CIDR == "" || len(peer.IPBlock.Except) != 0 {
					t.Fatalf("Phase 5 agent fixture policy %s peer %d has an invalid IP block", policyKey, peerIndex)
				}
			}
			peersByBucket[bucket] += len(typed.Spec.Egress[0].To)
		default:
			t.Fatalf("unexpected Phase 5 agent fixture object type %T", object)
		}
	}
	if namespaces != 1 || nodes != 1 || pods != phase5AgentSubjects || policies != phase5AgentPolicies {
		t.Fatalf("Phase 5 agent fixture counts = namespaces %d, nodes %d, Pods %d, policies %d; want 1, 1, %d, %d", namespaces, nodes, pods, policies, phase5AgentSubjects, phase5AgentPolicies)
	}

	rules := 0
	for policyIndex := 0; policyIndex < phase5AgentPolicies; policyIndex++ {
		bucket := fmt.Sprintf("%02d", policyIndex)
		if podsByBucket[bucket] != wantPodsPerBucket {
			t.Fatalf("Phase 5 agent fixture bucket %s has %d Pods, want %d", bucket, podsByBucket[bucket], wantPodsPerBucket)
		}
		if peersByBucket[bucket] != wantPeersPerPolicy {
			t.Fatalf("Phase 5 agent fixture bucket %s has %d policy peers, want %d", bucket, peersByBucket[bucket], wantPeersPerPolicy)
		}
		rules += podsByBucket[bucket] * peersByBucket[bucket]
	}
	if len(podsByBucket) != phase5AgentPolicies || len(peersByBucket) != phase5AgentPolicies {
		t.Fatalf("Phase 5 agent fixture bucket sets have %d Pod buckets and %d policy buckets, want %d each", len(podsByBucket), len(peersByBucket), phase5AgentPolicies)
	}
	if rules != phase5AgentRules {
		t.Fatalf("Phase 5 agent fixture projected rules = %d, want %d", rules, phase5AgentRules)
	}
}

func phase5AgentFixtureIndex(t *testing.T, name, prefix string, width, count int) int {
	t.Helper()
	if !strings.HasPrefix(name, prefix) {
		t.Fatalf("Phase 5 agent fixture object name %q does not use prefix %q", name, prefix)
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != width {
		t.Fatalf("Phase 5 agent fixture object name %q has suffix width %d, want %d", name, len(suffix), width)
	}
	index, err := strconv.Atoi(suffix)
	if err != nil || index < 0 || index >= count || fmt.Sprintf("%0*d", width, index) != suffix {
		t.Fatalf("Phase 5 agent fixture object name %q has invalid index", name)
	}
	return index
}

func phase5CrashFixtureIdentity(index, subjectIndex int) (string, string) {
	if subjectIndex == 0 {
		return phase5AgentCrashUID(index), fmt.Sprintf("%064x", index+1)
	}
	identity := (index+1)*phase5AgentSubjects + subjectIndex + 1
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", identity), fmt.Sprintf("%064x", identity)
}

func registerPhase5AgentCrashFixtureCleanup(t *testing.T, index int) {
	t.Helper()
	qosRoot := filepath.Join(phase5AgentCgroupRoot, "kubepods.slice", "kubepods-burstable.slice")
	t.Cleanup(func() {
		if err := enforcer.RemoveStalePins(phase5AgentBPFFSRoot); err != nil {
			t.Errorf("remove crash fixture engine pins: %v", err)
		}
		for subjectIndex := phase5AgentSubjects - 1; subjectIndex >= 0; subjectIndex-- {
			uid, containerID := phase5CrashFixtureIdentity(index, subjectIndex)
			podSlice := filepath.Join(qosRoot, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
			cgroupPath := filepath.Join(podSlice, "cri-containerd-"+containerID+".scope")
			if err := removePhase5CgroupDir(cgroupPath); err != nil {
				t.Errorf("remove crash fixture cgroup %s: %v", cgroupPath, err)
			}
			if err := removePhase5CgroupDir(podSlice); err != nil {
				t.Errorf("remove crash fixture pod slice %s: %v", podSlice, err)
			}
		}
	})
}

func ensurePhase5CgroupDir(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() {
			t.Fatalf("cgroup path is not a directory: %s", path)
		}
		fd, openErr := phase5CgroupDirectoryFD(path)
		if openErr != nil {
			t.Fatalf("inspect cgroup directory %s without following symlinks: %v", path, openErr)
		}
		_ = unix.Close(fd)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect cgroup directory %s: %v", path, err)
	}
	if err := createPhase5CgroupDirNoFollow(path); err != nil {
		t.Fatalf("create cgroup directory %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := removePhase5CgroupDir(path); err != nil {
			t.Errorf("remove cgroup directory %s: %v", path, err)
		}
	})
}

func createPhase5CgroupDir(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Fatalf("reference cgroup path already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect reference cgroup path %s: %v", path, err)
	}
	if err := createPhase5CgroupDirNoFollow(path); err != nil {
		t.Fatalf("create reference cgroup %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := removePhase5CgroupDir(path); err != nil {
			t.Errorf("remove reference cgroup %s: %v", path, err)
		}
	})
}

func phase5CgroupDirectoryFD(path string) (int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return -1, fmt.Errorf("resolve cgroup directory %q: %w", path, err)
	}
	return openExistingDirectory(filepath.Clean(absPath), "Phase 5 cgroup")
}

func createPhase5CgroupDirNoFollow(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve cgroup directory %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)
	name := filepath.Base(absPath)
	if name == "." || name == string(filepath.Separator) {
		return fmt.Errorf("invalid cgroup directory path %q", path)
	}
	parentFD, err := phase5CgroupDirectoryFD(filepath.Dir(absPath))
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, name, 0o755); err != nil {
		return fmt.Errorf("create cgroup directory %q: %w", absPath, err)
	}
	return nil
}

func removePhase5CgroupDir(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve cgroup directory %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)
	name := filepath.Base(absPath)
	if name == "." || name == string(filepath.Separator) {
		return fmt.Errorf("invalid cgroup directory path %q", path)
	}
	parentFD, err := phase5CgroupDirectoryFD(filepath.Dir(absPath))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var info unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect cgroup directory %q: %w", absPath, err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("cgroup path %q is not a directory", absPath)
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove cgroup directory %q: %w", absPath, err)
	}
	return nil
}

func phase5AgentKernelRelease(t *testing.T) string {
	t.Helper()
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("read kernel release: %v", err)
	}
	return strings.TrimSpace(string(release))
}

type phase5AgentProcess struct {
	client   kubernetes.Interface
	address  string
	cancel   context.CancelFunc
	done     chan error
	finished bool
}

func startPhase5Agent(t *testing.T, objects []k8sruntime.Object) *phase5AgentProcess {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve metrics listener: %v", err)
	}
	address := listener.Addr().String()

	client := fake.NewSimpleClientset(objects...)
	ctx, cancel := context.WithCancel(context.Background())
	agent := &phase5AgentProcess{
		client:  client,
		address: address,
		cancel:  cancel,
		done:    make(chan error, 1),
	}
	runDir := t.TempDir()
	go func() {
		agent.done <- runNativeKubernetesAgent(ctx, client, NativeAgentOptions{
			NodeName:       "node-a",
			CgroupRoot:     phase5AgentCgroupRoot,
			BPFFSRoot:      phase5AgentBPFFSRoot,
			RunDir:         runDir,
			Listen:         address,
			StatusListener: listener,
		})
	}()
	return agent
}

func (agent *phase5AgentProcess) stop(t *testing.T) {
	t.Helper()
	_ = agent.stopAt(t)
}

func (agent *phase5AgentProcess) stopAt(t *testing.T) time.Time {
	t.Helper()
	agent.cancel()
	if agent.finished {
		return time.Now()
	}
	select {
	case agentErr := <-agent.done:
		agent.finished = true
		if agentErr != nil {
			t.Errorf("native agent shutdown: %v", agentErr)
		}
		return time.Now()
	case <-time.After(30 * time.Second):
		t.Errorf("native agent did not stop after cancellation")
		return time.Now()
	}
}

func movePhase5AgentProcessToCgroup(t *testing.T, cmd *exec.Cmd, cgroup string) {
	t.Helper()
	file, err := openPhase5CgroupProcs(cgroup)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open crash-gap cgroup %s control file: %v", cgroup, err)
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", cmd.Process.Pid)
	_ = file.Close()
	if writeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("move crash-gap process to cgroup: %v", writeErr)
	}
}

func openPhase5CgroupProcs(cgroup string) (*os.File, error) {
	directoryFD, err := phase5CgroupDirectoryFD(cgroup)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	fd, err := unix.Openat(directoryFD, "cgroup.procs", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup.procs relative to %q: %w", cgroup, err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(cgroup, "cgroup.procs"))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open cgroup.procs relative to %q returned no file handle", cgroup)
	}
	return file, nil
}

func waitPhase5AgentMetrics(agent *phase5AgentProcess, predicate func(string) bool, timeout time.Duration) (string, error) {
	clientHTTP := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, requestErr := clientHTTP.Get("http://" + agent.address + "/metrics")
		if requestErr != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
		} else {
			metrics, ok, readErr := readPhase5MetricsResponse(response)
			if readErr != nil {
				return "", fmt.Errorf("read agent metrics: %w", readErr)
			}
			if ok && predicate(metrics) {
				return metrics, nil
			}
		}
		select {
		case agentErr := <-agent.done:
			agent.finished = true
			if agentErr == nil {
				return "", errors.New("native agent exited before the requested metrics state")
			}
			return "", fmt.Errorf("native agent exited before the requested metrics state: %w", agentErr)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for requested native agent metrics state after %s", timeout)
}

func runPhase5AgentActivationSample(t *testing.T, objects []k8sruntime.Object) error {
	t.Helper()
	agent := startPhase5Agent(t, objects)
	defer agent.stop(t)
	if _, err := waitPhase5AgentMetrics(agent, phase5AgentIsActive, 30*time.Second); err != nil {
		return fmt.Errorf("initial native agent activation: %w", err)
	}
	return nil
}

func phase5MetricAtLeast(metrics, name string, want float64) bool {
	value, ok := phase5MetricValue(metrics, name)
	return ok && value >= want
}

func phase5MetricEquals(metrics, name string, want float64) bool {
	value, ok := phase5MetricValue(metrics, name)
	return ok && value == want
}

func phase5MetricValue(metrics, name string) (float64, bool) {
	var value float64
	found := false
	for _, line := range strings.Split(metrics, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		metricName := fields[0]
		baseName := metricName
		if brace := strings.IndexByte(baseName, '{'); brace >= 0 {
			baseName = baseName[:brace]
		}
		if baseName != name {
			continue
		}
		// A Phase 5 predicate represents one exact, unlabelled gauge or
		// counter sample. A same-family labelled series must not be ignored
		// beside the canonical sample.
		if metricName != name || len(fields) != 2 {
			return 0, false
		}
		if found {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		value = parsed
		found = true
	}
	return value, found
}

func sortPhase5Durations(values []time.Duration) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func phase5AgentDurationsMilliseconds(values []time.Duration) []float64 {
	result := make([]float64, len(values))
	for i, value := range values {
		result[i] = float64(value) / float64(time.Millisecond)
	}
	return result
}

func writePhase5AgentEvidence(t *testing.T, evidence phase5AgentActivationEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent performance evidence: %v", err)
	}
	t.Logf("agent activation evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent performance evidence to %s", output)
}

func writePhase5AgentReconciliationEvidence(t *testing.T, evidence phase5AgentReconciliationEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent reconciliation evidence: %v", err)
	}
	t.Logf("agent reconciliation evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_RECONCILE_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent reconciliation evidence to %s", output)
}

func writePhase5AgentEventEvidence(t *testing.T, evidence phase5AgentEventEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent event performance evidence: %v", err)
	}
	t.Logf("agent event activation evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_EVENT_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent event performance evidence to %s", output)
}

func writePhase5AgentPodStartEvidence(t *testing.T, evidence phase5AgentPodStartEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent Pod-start evidence: %v", err)
	}
	t.Logf("agent Pod-start classification evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_POD_START_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent Pod-start evidence to %s", output)
}

func writePhase5AgentRestartEvidence(t *testing.T, evidence phase5AgentRestartEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent restart performance evidence: %v", err)
	}
	t.Logf("agent restart gap evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_RESTART_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent restart performance evidence to %s", output)
}

func writePhase5AgentCrashEvidence(t *testing.T, evidence phase5AgentCrashEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent crash evidence: %v", err)
	}
	t.Logf("agent crash fail-open evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_CRASH_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent crash evidence to %s", output)
}

func writePhase5AgentResourceEvidence(t *testing.T, evidence phase5AgentResourceEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode agent resource evidence: %v", err)
	}
	t.Logf("agent resource evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_AGENT_RESOURCE_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote agent resource evidence to %s", output)
}
