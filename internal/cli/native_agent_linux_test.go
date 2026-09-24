//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/policy"
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

func TestNextNativeAgentRetryDelayUsesCappedExponentialBackoff(t *testing.T) {
	if got := nextNativeAgentRetryDelay(0); got != time.Second {
		t.Fatalf("initial retry delay = %s, want 1s", got)
	}
	previous := time.Second
	for _, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute} {
		got := nextNativeAgentRetryDelay(previous)
		if got != want {
			t.Fatalf("retry delay after %s = %s, want %s", previous, got, want)
		}
		previous = got
	}
	if got := nextNativeAgentRetryDelay(time.Minute); got != time.Minute {
		t.Fatalf("capped retry delay = %s, want 1m", got)
	}
}

func TestWaitForNativeAgentCacheSyncTimesOut(t *testing.T) {
	err := waitForNativeAgentCacheSync(context.Background(), 10*time.Millisecond, func() bool { return false })
	if err == nil || !strings.Contains(err.Error(), "failed to sync within") {
		t.Fatalf("cache sync error = %v, want bounded timeout failure", err)
	}
}

func TestWaitForNativeAgentCacheSyncPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForNativeAgentCacheSync(ctx, time.Minute, func() bool { return false })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cache sync cancellation error = %v, want context.Canceled", err)
	}
}

func TestWaitForNativeAgentCacheSyncRechecksCancellationAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := waitForNativeAgentCacheSync(ctx, time.Minute, func() bool {
		cancel()
		return true
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cache sync cancellation after success = %v, want context.Canceled", err)
	}
}

func TestWaitForNativeAgentCacheSyncRejectsMissingOrNilInformers(t *testing.T) {
	if err := waitForNativeAgentCacheSync(context.Background(), time.Second); err == nil || !strings.Contains(err.Error(), "at least one informer") {
		t.Fatalf("missing informer error = %v, want explicit validation", err)
	}
	if err := waitForNativeAgentCacheSync(context.Background(), time.Second, nil); err == nil || !strings.Contains(err.Error(), "informer 0 is nil") {
		t.Fatalf("nil informer error = %v, want explicit validation", err)
	}
}

func TestSignalNativeAgentDirtyCoalescesEventBurst(t *testing.T) {
	dirty := make(chan struct{}, 1)
	for i := 0; i < 1000; i++ {
		signalNativeAgentDirty(dirty)
	}
	if got := len(dirty); got != 1 {
		t.Fatalf("dirty queue length after burst = %d, want one coalesced signal", got)
	}
	<-dirty
	signalNativeAgentDirty(dirty)
	if got := len(dirty); got != 1 {
		t.Fatalf("dirty queue length after next signal = %d, want one", got)
	}
}

func TestDrainNativeAgentDirtyClearsCacheSyncSignals(t *testing.T) {
	dirty := make(chan struct{}, 1)
	dirty <- struct{}{}
	drainNativeAgentDirty(dirty)
	if got := len(dirty); got != 0 {
		t.Fatalf("dirty queue after drain = %d, want empty", got)
	}
	drainNativeAgentDirty(nil)
}

func TestNativeAgentReconciliationDrainsInitialDirtySignal(t *testing.T) {
	dirty := make(chan struct{}, 1)
	dirty <- struct{}{}
	entered := make(chan struct{}, 2)
	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		entered <- struct{}{}
		return policy.CompileResult{}, 0, nativeSnapshotTelemetry{}, nil
	}
	status := &nativeAgentHTTP{reason: "starting"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runNativeAgentReconciliation(ctx, dirty, nil, status, NativeAgentOptions{NodeName: "node-a"}, reconcile)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial reconciliation did not start")
	}
	select {
	case <-entered:
		t.Fatal("cache-sync dirty signal triggered a redundant reconciliation")
	case <-time.After(2 * nativeAgentDebounce):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconciliation loop shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not shut down")
	}
}

func TestNativeAgentReconciliationDoesNotPublishReadinessAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	status := &nativeAgentHTTP{reason: "starting"}
	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		cancel()
		return policy.CompileResult{}, 0, nativeSnapshotTelemetry{}, nil
	}
	if err := runNativeAgentReconciliation(ctx, make(chan struct{}), nil, status, NativeAgentOptions{}, reconcile); err != nil {
		t.Fatalf("reconciliation returned error after cancellation: %v", err)
	}
	status.stateMu.RLock()
	ready, enforcing, reason := status.ready, status.enforcing, status.reason
	status.stateMu.RUnlock()
	if ready || enforcing || reason != "starting" {
		t.Fatalf("post-cancellation status = ready=%t enforcing=%t reason=%q, want unchanged starting state", ready, enforcing, reason)
	}
}

func TestNativeAgentStatusErrorHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := nativeAgentStatusError(ctx, errors.New("listener stopped")); err != nil {
		t.Fatalf("status error after cancellation = %v, want clean shutdown", err)
	}

	activeErr := nativeAgentStatusError(context.Background(), errors.New("listener failed"))
	if activeErr == nil || !strings.Contains(activeErr.Error(), "listener failed") {
		t.Fatalf("active status error = %v, want wrapped listener failure", activeErr)
	}
}

func TestWaitNativeAgentDebounceConvergesDuringContinuousEvents(t *testing.T) {
	dirty := make(chan struct{}, 1)
	stopEvents := make(chan struct{})
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopEvents:
				return
			case <-ticker.C:
				signalNativeAgentDirty(dirty)
			}
		}
	}()
	defer func() {
		close(stopEvents)
		<-eventsDone
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- waitNativeAgentDebounce(ctx, dirty) }()
	select {
	case completed := <-result:
		if !completed {
			t.Fatal("debounce exited without reconciliation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("continuous informer events postponed reconciliation")
	}
}

func TestNativeAgentReconciliationLoopClearsQuarantineAfterCorrection(t *testing.T) {
	bad := policy.CompileResult{
		PolicySet: policy.PolicySet{Subjects: []policy.Subject{
			{CgroupID: 1, Isolated: policy.DirectionIngress, Quarantined: policy.DirectionIngress},
			{CgroupID: 2, Isolated: policy.DirectionEgress},
		}},
		Rejected: []policy.RejectedPolicy{{Namespace: "apps", Name: "bad", Generation: 1}},
	}
	corrected := policy.CompileResult{PolicySet: policy.PolicySet{Subjects: []policy.Subject{
		{CgroupID: 1, Isolated: policy.DirectionIngress},
		{CgroupID: 2, Isolated: policy.DirectionEgress},
	}}}
	deleted := policy.CompileResult{PolicySet: policy.PolicySet{Subjects: []policy.Subject{
		{CgroupID: 2, Isolated: policy.DirectionEgress},
	}}}
	steps := []policy.CompileResult{bad, corrected, deleted}
	entered := make(chan int, len(steps))
	release := make(chan struct{})
	step := 0
	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		if step >= len(steps) {
			return policy.CompileResult{}, 0, nativeSnapshotTelemetry{}, errors.New("unexpected reconciliation")
		}
		current := step
		step++
		entered <- current
		<-release
		return steps[current], len(steps[current].Rejected) + 1, nativeSnapshotTelemetry{}, nil
	}

	status := &nativeAgentHTTP{reason: "starting"}
	dirty := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runNativeAgentReconciliation(ctx, dirty, nil, status, NativeAgentOptions{NodeName: "node-a"}, reconcile)
	}()

	waitForStep := func(want int) {
		t.Helper()
		select {
		case got := <-entered:
			if got != want {
				t.Fatalf("reconciliation step = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for reconciliation step %d", want)
		}
	}
	waitForReady := func(wantStatus int, wantReason string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			recorder := httptest.NewRecorder()
			status.handleReady(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if recorder.Code == wantStatus && strings.Contains(recorder.Body.String(), `"reason":"`+wantReason+`"`) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		recorder := httptest.NewRecorder()
		status.handleReady(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		t.Fatalf("readiness = %d %s, want %d with reason %q", recorder.Code, recorder.Body.String(), wantStatus, wantReason)
	}

	waitForStep(0)
	release <- struct{}{}
	waitForReady(http.StatusServiceUnavailable, "quarantined")

	dirty <- struct{}{}
	waitForStep(1)
	release <- struct{}{}
	waitForReady(http.StatusOK, "ok")

	dirty <- struct{}{}
	waitForStep(2)
	release <- struct{}{}
	waitForReady(http.StatusOK, "ok")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconciliation loop shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not shut down")
	}
}

type lastKnownGoodTestEngine struct {
	applied policy.PolicySet
	fail    error
}

func (e *lastKnownGoodTestEngine) Apply(_ context.Context, set policy.PolicySet) error {
	if e.fail != nil {
		return e.fail
	}
	e.applied = set
	return nil
}

func (*lastKnownGoodTestEngine) Close() error { return nil }

func TestNativeAgentReconciliationRetainsLastKnownGoodAfterApplyFailure(t *testing.T) {
	policyTypes := []string{"Ingress"}
	nativePolicy := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata: &policy.NativeObjectMeta{
			Namespace: "default",
			Name:      "deny-api-ingress",
		},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: &policyTypes,
		},
	}
	input := policy.ResolutionInput{
		NodeIPs:    []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Namespaces: []policy.ResolvedNamespace{{Name: "default"}},
		Pods: []policy.ResolvedPod{{
			Namespace: "default",
			Name:      "api",
			Labels:    map[string]string{"app": "api"},
			CgroupIDs: []uint64{42},
			Local:     true,
		}},
	}
	engine := &lastKnownGoodTestEngine{}
	applyErr := errors.New("injected kernel apply failure")
	entered := make(chan int, 3)
	release := make(chan struct{})
	step := 0
	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		current := step
		step++
		policies := []policy.NativeNetworkPolicy{nativePolicy}
		if current == 2 {
			policies = nil
		}
		if current == 1 {
			engine.fail = applyErr
		} else {
			engine.fail = nil
		}
		result, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
		entered <- current
		<-release
		return result, len(policies), nativeSnapshotTelemetry{}, err
	}

	status := &nativeAgentHTTP{reason: "starting"}
	dirty := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runNativeAgentReconciliation(ctx, dirty, nil, status, NativeAgentOptions{NodeName: "node-a"}, reconcile)
	}()
	waitForStep := func(want int) {
		t.Helper()
		select {
		case got := <-entered:
			if got != want {
				t.Fatalf("reconciliation step = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for reconciliation step %d", want)
		}
	}
	waitForReadiness := func(wantReady bool, wantReason string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			status.stateMu.RLock()
			ready, reason := status.ready, status.reason
			status.stateMu.RUnlock()
			if ready == wantReady && reason == wantReason {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		status.stateMu.RLock()
		ready, reason := status.ready, status.reason
		status.stateMu.RUnlock()
		t.Fatalf("readiness = %t/%q, want %t/%q", ready, reason, wantReady, wantReason)
	}

	waitForStep(0)
	release <- struct{}{}
	waitForReadiness(true, "ok")
	lastGood := engine.applied
	if len(lastGood.Subjects) != 1 || lastGood.Subjects[0].CgroupID != 42 {
		t.Fatalf("initial engine state = %#v, want one applied subject", lastGood)
	}

	dirty <- struct{}{}
	waitForStep(1)
	release <- struct{}{}
	waitForReadiness(false, "apply_error")
	if !reflect.DeepEqual(engine.applied, lastGood) {
		t.Fatalf("engine state after failed apply = %#v, want last-known-good %#v", engine.applied, lastGood)
	}

	dirty <- struct{}{}
	waitForStep(2)
	release <- struct{}{}
	waitForReadiness(true, "ok")
	if len(engine.applied.Subjects) != 0 || len(engine.applied.Rules) != 0 {
		t.Fatalf("engine state after recovery = %#v, want empty corrected policy", engine.applied)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconciliation loop shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not shut down")
	}
}

func TestNativeAgentReconciliationRetriesTransientFailureWithoutDirtyEvent(t *testing.T) {
	applyErr := errors.New("transient kernel apply failure")
	calls := make(chan int, 3)
	step := 0
	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		current := step
		step++
		calls <- current
		if current == 1 {
			return policy.CompileResult{}, 1, nativeSnapshotTelemetry{}, applyErr
		}
		return policy.CompileResult{}, 0, nativeSnapshotTelemetry{}, nil
	}

	status := &nativeAgentHTTP{reason: "starting"}
	dirty := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runNativeAgentReconciliation(ctx, dirty, nil, status, NativeAgentOptions{NodeName: "node-a"}, reconcile)
	}()

	waitForCall := func(want int) {
		t.Helper()
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("reconciliation call = %d, want %d", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for reconciliation call %d", want)
		}
	}
	waitForReadiness := func(wantReady bool, wantReason string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			status.stateMu.RLock()
			ready, reason := status.ready, status.reason
			status.stateMu.RUnlock()
			if ready == wantReady && reason == wantReason {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		status.stateMu.RLock()
		ready, reason := status.ready, status.reason
		status.stateMu.RUnlock()
		t.Fatalf("readiness = %t/%q, want %t/%q", ready, reason, wantReady, wantReason)
	}

	waitForCall(0)
	waitForReadiness(true, "ok")
	dirty <- struct{}{}
	waitForCall(1)
	waitForReadiness(false, "apply_error")
	// No additional dirty signal is sent. The one-second retry timer must
	// drive the successful recovery.
	waitForCall(2)
	waitForReadiness(true, "ok")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconciliation loop shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not shut down")
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
	status.stateMu.RLock()
	enforcing := status.enforcing
	status.stateMu.RUnlock()
	if enforcing {
		t.Fatal("dry-run marked the native agent as enforcing")
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

func TestNativeAgentHTTPStatusEndpointsRequireGET(t *testing.T) {
	status, err := startNativeAgentHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start status server: %v", err)
	}
	defer func() {
		if err := status.close(context.Background()); err != nil {
			t.Errorf("close status server: %v", err)
		}
	}()

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		recorder := httptest.NewRecorder()
		status.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d, want 405", path, recorder.Code)
		}
		if recorder.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("POST %s Allow = %q, want GET", path, recorder.Header().Get("Allow"))
		}
	}
}

func TestNativeAgentHTTPCloseMarksStopping(t *testing.T) {
	status, err := startNativeAgentHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start status server: %v", err)
	}
	status.markApplied(policy.CompileResult{}, false)
	if err := status.close(context.Background()); err != nil {
		t.Fatalf("close status server: %v", err)
	}
	recorder := httptest.NewRecorder()
	status.handleReady(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"reason":"stopping"`) {
		t.Fatalf("closed readiness = %d %s, want 503/stopping", recorder.Code, recorder.Body.String())
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
		"ztap_pod_start_classification_delay_seconds_count 3",
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for dry-run status: %v", err)
	}
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runNativeKubernetesAgent(ctx, client, NativeAgentOptions{
			NodeName:       "node-a",
			CgroupRoot:     t.TempDir(),
			BPFFSRoot:      t.TempDir(),
			RunDir:         t.TempDir(),
			StatusListener: listener,
			DryRun:         true,
		})
	}()
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	var dryRunReady nativeAgentHealthResponse
	observedDryRun := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr := httpClient.Get("http://" + address + "/readyz")
		if requestErr == nil {
			decodeErr := json.NewDecoder(response.Body).Decode(&dryRunReady)
			closeErr := response.Body.Close()
			if decodeErr != nil {
				t.Fatalf("decode dry-run readiness: %v", decodeErr)
			}
			if closeErr != nil {
				t.Fatalf("close dry-run readiness response: %v", closeErr)
			}
			if dryRunReady.Reason == "dry_run" {
				if response.StatusCode != http.StatusServiceUnavailable || dryRunReady.Ready || dryRunReady.Enforcing {
					t.Fatalf("dry-run readiness = status=%d body=%+v, want 503 and not ready/enforcing", response.StatusCode, dryRunReady)
				}
				observedDryRun = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !observedDryRun {
		t.Fatal("dry-run agent never published dry_run readiness")
	}
	metricsResponse, err := httpClient.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatalf("read dry-run metrics: %v", err)
	}
	metrics, readErr := io.ReadAll(metricsResponse.Body)
	closeErr := metricsResponse.Body.Close()
	if readErr != nil {
		t.Fatalf("read dry-run metrics body: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("close dry-run metrics response: %v", closeErr)
	}
	if metricsResponse.StatusCode != http.StatusOK || !strings.Contains(string(metrics), "ztap_agent_enforcing 0") {
		t.Fatalf("dry-run metrics = status=%d body=%s, want HTTP 200 and ztap_agent_enforcing 0", metricsResponse.StatusCode, metrics)
	}
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

func TestStartNativeAgentHTTPUsesSuppliedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for supplied status listener: %v", err)
	}
	status, err := startNativeAgentHTTPWithListener("127.0.0.1:1", listener)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("start HTTP status server with supplied listener: %v", err)
	}
	if status.listener != listener {
		_ = status.close(context.Background())
		t.Fatalf("status listener = %p, want supplied listener %p", status.listener, listener)
	}
	if err := status.close(context.Background()); err != nil {
		t.Fatalf("close HTTP status server: %v", err)
	}
}

func TestRunNativeKubernetesAgentClosesSuppliedListenerOnValidationFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for validation-failure listener: %v", err)
	}
	address := listener.Addr().String()
	err = runNativeKubernetesAgent(context.Background(), fake.NewSimpleClientset(), NativeAgentOptions{
		StatusListener: listener,
	})
	if err == nil || !strings.Contains(err.Error(), "node name is required") {
		t.Fatalf("validation error = %v, want missing node name", err)
	}
	replacement, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("supplied listener remained open after validation failure: %v", err)
	}
	_ = replacement.Close()
}

func TestRunNativeKubernetesAgentCancellationBeforeStartupIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runNativeKubernetesAgent(ctx, fake.NewSimpleClientset(), NativeAgentOptions{
		NodeName:   "node-a",
		CgroupRoot: t.TempDir(),
		BPFFSRoot:  t.TempDir(),
		RunDir:     t.TempDir(),
		Listen:     "127.0.0.1:0",
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("agent cancellation during cache sync = %v, want clean exit", err)
	}
}

func TestRunNativeKubernetesAgentCancellationBeforeStartupHasNoSideEffects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for canceled-agent listener: %v", err)
	}
	address := listener.Addr().String()
	runDir := filepath.Join(t.TempDir(), "run")
	err = runNativeKubernetesAgent(ctx, fake.NewSimpleClientset(), NativeAgentOptions{
		NodeName:       "node-a",
		RunDir:         runDir,
		StatusListener: listener,
	})
	if err != nil {
		t.Fatalf("canceled agent returned error: %v", err)
	}
	replacement, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("canceled agent retained supplied listener: %v", err)
	}
	_ = replacement.Close()
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("canceled agent created run directory or stat failed: %v", err)
	}
}

type observedStatusListener struct {
	net.Listener
	accepted chan struct{}
	once     sync.Once
}

func (l *observedStatusListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.accepted) })
	return nil, errors.New("status listener accept observed")
}

type cancelAfterErrContext struct {
	context.Context
	done  chan struct{}
	once  sync.Once
	calls atomic.Int32
}

func newCancelAfterErrContext(parent context.Context) *cancelAfterErrContext {
	return &cancelAfterErrContext{Context: parent, done: make(chan struct{})}
}

func (c *cancelAfterErrContext) Done() <-chan struct{} { return c.done }

func (c *cancelAfterErrContext) Err() error {
	if c.calls.Add(1) >= 2 {
		c.once.Do(func() { close(c.done) })
		return context.Canceled
	}
	return nil
}

func TestRunNativeKubernetesAgentCancellationAfterLockHasNoHTTPStartup(t *testing.T) {
	runDir := t.TempDir()
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for canceled-agent startup: %v", err)
	}
	listener := &observedStatusListener{Listener: baseListener, accepted: make(chan struct{})}
	ctx := newCancelAfterErrContext(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- runNativeKubernetesAgent(ctx, fake.NewSimpleClientset(), NativeAgentOptions{
			NodeName:       "node-a",
			RunDir:         runDir,
			StatusListener: listener,
			DryRun:         true,
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled agent returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled agent did not exit after lock acquisition")
	}
	select {
	case <-listener.accepted:
		t.Fatal("canceled agent started the HTTP listener after lock acquisition")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRunNativeKubernetesAgentInitialFailureStopsInformers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := NativeAgentOptions{
		NodeName:   "missing-node",
		CgroupRoot: t.TempDir(),
		BPFFSRoot:  t.TempDir(),
		RunDir:     t.TempDir(),
		Listen:     "127.0.0.1:0",
		DryRun:     true,
	}
	done := make(chan error, 1)
	go func() { done <- runNativeKubernetesAgent(ctx, fake.NewSimpleClientset(), options) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "get local node") {
			t.Fatalf("initial reconciliation error = %v, want missing local node", err)
		}
		if ctx.Err() != nil {
			t.Fatal("agent returned only after its caller context was cancelled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not return after initial reconciliation failed")
	}
}

func TestRunNativeKubernetesAgentFiltersLocalNodeList(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
				Type: corev1.NodeInternalIP, Address: "192.0.2.10",
			}}},
		},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
	)
	fieldSelectors := make(chan string, 1)
	client.PrependReactor("list", "nodes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if ok {
			fieldSelectors <- listAction.GetListRestrictions().Fields.String()
		}
		return false, nil, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	select {
	case selector := <-fieldSelectors:
		if selector != "metadata.name=node-a" {
			t.Fatalf("Node informer field selector = %q, want metadata.name=node-a", selector)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Node informer did not issue a filtered list request")
	}

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
