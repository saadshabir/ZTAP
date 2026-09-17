//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"ztap/internal/enforcer"
	"ztap/internal/policy"
)

func TestNativeNetworkPolicyFromKubePreservesSupportedFields(t *testing.T) {
	protocol := corev1.ProtocolUDP
	port := intstr.FromInt(53)
	endPort := int32(55)
	object := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "dns-egress",
			Namespace:   "apps",
			Generation:  7,
			Labels:      map[string]string{"team": "edge"},
			Annotations: map[string]string{"owner": "platform"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "shared"}}},
					{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}},
				},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port, EndPort: &endPort}},
			}},
		},
	}

	got, err := nativeNetworkPolicyFromKube(object)
	if err != nil {
		t.Fatalf("nativeNetworkPolicyFromKube returned error: %v", err)
	}
	if got.APIVersion != policy.NativeNetworkPolicyAPIVersion || got.Kind != policy.NativeNetworkPolicyKind {
		t.Fatalf("identity = %s/%s, want %s/%s", got.APIVersion, got.Kind, policy.NativeNetworkPolicyAPIVersion, policy.NativeNetworkPolicyKind)
	}
	if got.Metadata == nil || got.Metadata.Namespace != "apps" || got.Metadata.Name != "dns-egress" {
		t.Fatalf("metadata = %#v", got.Metadata)
	}
	if got.Metadata.Generation != 7 {
		t.Fatalf("metadata generation = %d, want 7", got.Metadata.Generation)
	}
	if got.Spec == nil || got.Spec.PodSelector == nil || got.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Fatalf("pod selector = %#v", got.Spec)
	}
	if got.Spec.PolicyTypes == nil || len(*got.Spec.PolicyTypes) != 1 || (*got.Spec.PolicyTypes)[0] != "Egress" {
		t.Fatalf("policy types = %#v", got.Spec.PolicyTypes)
	}
	if len(got.Spec.Egress) != 1 || len(got.Spec.Egress[0].To) != 2 || got.Spec.Egress[0].To[1].IPBlock == nil {
		t.Fatalf("egress peers = %#v", got.Spec.Egress)
	}
	nativePort := got.Spec.Egress[0].Ports[0]
	if nativePort.Protocol != "UDP" || nativePort.Port != 53 || !nativePort.HasEndPort {
		t.Fatalf("native port = %#v", nativePort)
	}
}

func TestNativePolicySnapshotRejectsNilResolver(t *testing.T) {
	_, _, _, err := nativePolicySnapshot("node-a", nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "resolver is required") {
		t.Fatalf("nil resolver error = %v, want resolver validation", err)
	}
}

func TestAcquireNativeAgentLockIsExclusiveAndReleases(t *testing.T) {
	runDir := t.TempDir()
	unlock, err := acquireNativeAgentLock(runDir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := acquireNativeAgentLock(runDir); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("second lock error = %v, want already-held error", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("repeat unlock: %v", err)
	}
	second, err := acquireNativeAgentLock(runDir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := second(); err != nil {
		t.Fatalf("second unlock: %v", err)
	}
}

func TestNativeDryRunEngineHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (nativeDryRunEngine{}).Apply(ctx, policy.PolicySet{}); err == nil {
		t.Fatal("dry-run Apply succeeded with canceled context")
	}
	if err := (nativeDryRunEngine{}).Close(); err != nil {
		t.Fatalf("dry-run Close: %v", err)
	}
}

func TestNativeAgentHTTPHealthAndReadinessLifecycle(t *testing.T) {
	status := &nativeAgentHTTP{reason: "starting"}
	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		switch path {
		case "/healthz":
			status.handleHealth(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		case "/readyz":
			status.handleReady(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		default:
			t.Fatalf("unexpected test path %q", path)
		}
		return recorder
	}

	health := request("/healthz")
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", health.Code)
	}
	var healthBody nativeAgentHealthResponse
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if healthBody.Status != "ok" || healthBody.Version == "" {
		t.Fatalf("health response = %+v, want ok status and version", healthBody)
	}

	ready := request("/readyz")
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("starting readiness status = %d, want 503", ready.Code)
	}

	status.markApplied(policy.CompileResult{}, true)
	ready = request("/readyz")
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "dry_run") {
		t.Fatalf("dry-run readiness = %d %s, want 503/dry_run", ready.Code, ready.Body.String())
	}

	status.markApplied(policy.CompileResult{PolicySet: policy.PolicySet{Subjects: []policy.Subject{{Quarantined: policy.DirectionIngress}}}}, false)
	ready = request("/readyz")
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "quarantined") {
		t.Fatalf("quarantined readiness = %d %s, want 503/quarantined", ready.Code, ready.Body.String())
	}

	status.markApplied(policy.CompileResult{}, false)
	ready = request("/readyz")
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ready"`) {
		t.Fatalf("healthy readiness = %d %s, want 200/ready", ready.Code, ready.Body.String())
	}

	status.markApplyFailure()
	ready = request("/readyz")
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "apply_error") {
		t.Fatalf("failed readiness = %d %s, want 503/apply_error", ready.Code, ready.Body.String())
	}

	status.markApplied(policy.CompileResult{}, false)
	status.markStopping()
	ready = request("/readyz")
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "stopping") {
		t.Fatalf("stopping readiness = %d %s, want 503/stopping", ready.Code, ready.Body.String())
	}
}

func TestNativeAgentMetricsUsePrivateRegistry(t *testing.T) {
	status, err := startNativeAgentHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start status server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := status.close(ctx); err != nil {
			t.Errorf("close status server: %v", err)
		}
	}()

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	status.server.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "ztap_agent_ready 0") {
		t.Fatalf("metrics body does not contain initial readiness gauge: %s", recorder.Body.String())
	}

	status.markApplied(policy.CompileResult{}, false)
	recorder = httptest.NewRecorder()
	status.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(recorder.Body.String(), "ztap_agent_ready 1") || !strings.Contains(recorder.Body.String(), "ztap_agent_enforcing 1") {
		t.Fatalf("metrics body does not contain applied state: %s", recorder.Body.String())
	}
}

type staticEngineMetricsProvider struct {
	snapshot enforcer.EngineMetricsSnapshot
}

func (p *staticEngineMetricsProvider) MetricsSnapshot(context.Context) (enforcer.EngineMetricsSnapshot, error) {
	return p.snapshot, nil
}

func TestNativeAgentPublishesReconciliationAndEngineMetrics(t *testing.T) {
	status, err := startNativeAgentHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start status server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := status.close(ctx); err != nil {
			t.Errorf("close status server: %v", err)
		}
	}()

	status.recordReconciliation(3, policy.CompileResult{
		PolicySet: policy.PolicySet{Subjects: []policy.Subject{{CgroupID: 7}, {CgroupID: 8, Quarantined: policy.DirectionIngress}}},
		Rejected:  []policy.RejectedPolicy{{Namespace: "apps", Name: "bad"}},
	}, nil, 250*time.Millisecond, false)
	status.recordReconciliation(0, policy.CompileResult{}, context.Canceled, 50*time.Millisecond, false)
	provider := &staticEngineMetricsProvider{snapshot: enforcer.EngineMetricsSnapshot{
		ActivePolicyEpoch:   9,
		Decisions:           []enforcer.EngineDecisionMetric{{Action: "blocked", Direction: "ingress", Reason: "rule", Count: 4}},
		EventDrops:          []enforcer.EngineEventDropMetric{{Reason: "ring_full", Count: 2}},
		SlotCleanupFailures: 1,
	}}
	status.setEngineMetricsProvider(provider)
	status.refreshEngineMetrics()
	provider.snapshot.Decisions[0].Count = 6
	provider.snapshot.EventDrops[0].Count = 3
	provider.snapshot.SlotCleanupFailures = 3
	status.refreshEngineMetrics()

	recorder := httptest.NewRecorder()
	status.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "ztap_anomaly_score") || strings.Contains(body, "ztap_flows_allowed_total") {
		t.Fatalf("native agent metrics leaked legacy process metrics: %s", body)
	}
	for _, want := range []string{
		`ztap_network_policies{state="observed"} 3`,
		`ztap_network_policies{state="accepted"} 2`,
		`ztap_network_policies{state="rejected"} 1`,
		`ztap_policy_reconciliations_total{result="rejected"} 1`,
		`ztap_policy_reconciliations_total{result="error"} 1`,
		`ztap_compiled_rules 0`,
		`ztap_enforced_cgroups 2`,
		`ztap_quarantined_cgroups 1`,
		`ztap_active_policy_epoch 9`,
		`ztap_packet_decisions_total{action="blocked",direction="ingress",reason="rule"} 6`,
		`ztap_flow_events_dropped_total{reason="ring_full"} 3`,
		`ztap_policy_slot_cleanup_failures_total 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}

func TestNativeAgentReportsClassificationDelayAndUnresolvedContainers(t *testing.T) {
	status, err := startNativeAgentHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start status server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := status.close(ctx); err != nil {
			t.Errorf("close status server: %v", err)
		}
	}()

	installedAt := time.Now()
	status.recordResolutionTelemetry(2)
	report := status.recordClassification(map[uint64]time.Time{
		7: installedAt.Add(-3 * time.Second),
		8: installedAt.Add(-time.Second),
	}, policy.PolicySet{Subjects: []policy.Subject{{CgroupID: 7}, {CgroupID: 8}}}, installedAt, false)
	if report.count != 2 || report.maxDelay < 3*time.Second {
		t.Fatalf("classification report = %+v, want two samples and a three-second maximum", report)
	}
	// A policy-only update keeps existing subjects classified and must not
	// inflate the watcher-gap histogram.
	report = status.recordClassification(map[uint64]time.Time{7: installedAt.Add(-10 * time.Second)}, policy.PolicySet{Subjects: []policy.Subject{{CgroupID: 7}, {CgroupID: 8}}}, installedAt, false)
	if report.count != 0 {
		t.Fatalf("repeat classification report = %+v, want no new samples", report)
	}
	// If the resolver has not published an observation yet, keep the subject
	// pending so the first later observation is still measured.
	report = status.recordClassification(nil, policy.PolicySet{Subjects: []policy.Subject{{CgroupID: 9}}}, installedAt, false)
	if report.count != 0 {
		t.Fatalf("pending classification report = %+v, want no sample", report)
	}
	report = status.recordClassification(map[uint64]time.Time{9: installedAt.Add(-2 * time.Second)}, policy.PolicySet{Subjects: []policy.Subject{{CgroupID: 9}}}, installedAt, false)
	if report.count != 1 || report.maxDelay < 2*time.Second {
		t.Fatalf("late classification report = %+v, want one two-second sample", report)
	}

	recorder := httptest.NewRecorder()
	status.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"ztap_unresolved_running_containers 2",
		"ztap_pod_start_classification_delay_seconds_count 2",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}

func TestNativeAgentLogsRejectedPolicyOncePerGeneration(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))

	options := NativeAgentOptions{NodeName: "node-a"}
	state := newNativeDiagnosticLogState()
	rejected := []policy.RejectedPolicy{{
		Document:   1,
		Namespace:  "apps",
		Name:       "bad",
		Generation: 3,
		Field:      "spec.egress",
		Message:    "unsupported protocol",
	}}
	result := policy.CompileResult{Rejected: rejected}
	logNativeReconcile(options, "reconcile-1", 1, time.Millisecond, result, 0, nativeClassificationReport{}, state)
	// An apply retry with the same rejection must not duplicate the policy
	// diagnostic, even though the aggregate failure is logged again.
	logNativeReconcileFailure(options, "reconcile-2", 1, time.Millisecond, result, 0, errors.New("transient apply failure"), false, state)
	logNativeReconcile(options, "reconcile-3", 1, time.Millisecond, result, 0, nativeClassificationReport{}, state)
	rejected[0].Message = "the same resource is still unsupported"
	logNativeReconcile(options, "reconcile-3b", 1, time.Millisecond, policy.CompileResult{Rejected: rejected}, 0, nativeClassificationReport{}, state)
	if got := strings.Count(output.String(), "native policy rejected"); got != 1 {
		t.Fatalf("rejected diagnostic count for one generation = %d, want 1; logs:\n%s", got, output.String())
	}

	// A new Kubernetes generation is a new diagnostic, even when the field
	// error text is unchanged.
	rejected[0].Generation = 4
	logNativeReconcile(options, "reconcile-4", 1, time.Millisecond, policy.CompileResult{Rejected: rejected}, 0, nativeClassificationReport{}, state)
	if got := strings.Count(output.String(), "native policy rejected"); got != 2 {
		t.Fatalf("rejected diagnostic count after generation change = %d, want 2; logs:\n%s", got, output.String())
	}
}

func TestRunNativeKubernetesAgentDryRunLifecycle(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"}}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runNativeKubernetesAgent(ctx, client, NativeAgentOptions{
			NodeName:   "node-a",
			CgroupRoot: t.TempDir(),
			BPFFSRoot:  t.TempDir(),
			RunDir:     t.TempDir(),
			Listen:     "127.0.0.1:0",
			DryRun:     true,
		})
	}()
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("agent shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not shut down")
	}
}
