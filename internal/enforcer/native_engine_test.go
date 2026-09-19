package enforcer

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/saadshabir/ZTAP/internal/policy"
)

type recordingNativeEngine struct {
	applyCalls int
	applied    policy.PolicySet
	err        error
}

func (e *recordingNativeEngine) Apply(_ context.Context, set policy.PolicySet) error {
	e.applyCalls++
	e.applied = set
	return e.err
}

func (*recordingNativeEngine) Close() error { return nil }

func TestReconcileNativePolicySnapshotCompilesAndAppliesCompleteSet(t *testing.T) {
	engine := &recordingNativeEngine{}
	policies := []policy.NativeNetworkPolicy{nativeDefaultDenyPolicy()}
	input := policy.ResolutionInput{
		NodeIPs:    []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Namespaces: []policy.ResolvedNamespace{{Name: "default"}},
		Pods: []policy.ResolvedPod{{
			Namespace: "default",
			Name:      "api",
			Labels:    map[string]string{"app": "api"},
			PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			CgroupIDs: []uint64{42},
			Local:     true,
		}},
	}

	result, err := ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
	if err != nil {
		t.Fatalf("ReconcileNativePolicySnapshot failed: %v", err)
	}
	if engine.applyCalls != 1 {
		t.Fatalf("engine Apply calls = %d, want 1", engine.applyCalls)
	}
	if !reflect.DeepEqual(engine.applied, result.PolicySet) {
		t.Fatalf("applied set = %#v, compile result = %#v", engine.applied, result.PolicySet)
	}
	if len(result.PolicySet.Subjects) != 1 || result.PolicySet.Subjects[0].CgroupID != 42 || result.PolicySet.Subjects[0].Isolated != policy.DirectionIngress {
		t.Fatalf("compiled default-deny subject = %#v", result.PolicySet.Subjects)
	}
	if len(result.PolicySet.Rules) != 0 {
		t.Fatalf("default-deny policy emitted allow rules: %#v", result.PolicySet.Rules)
	}
}

func TestReconcileNativePolicySnapshotDoesNotApplyIncompleteResolution(t *testing.T) {
	engine := &recordingNativeEngine{}
	input := policy.ResolutionInput{
		NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Pods: []policy.ResolvedPod{{
			Namespace: "default",
			Name:      "api",
			Labels:    map[string]string{"app": "api"},
			CgroupIDs: []uint64{42},
			Local:     true,
		}},
	}

	_, err := ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativeDefaultDenyPolicy()}, input)
	if err == nil {
		t.Fatal("ReconcileNativePolicySnapshot accepted missing namespace facts")
	}
	if engine.applyCalls != 0 {
		t.Fatalf("engine Apply calls = %d, want 0 after compilation failure", engine.applyCalls)
	}
}

func TestReconcileNativePolicySnapshotReturnsCandidateWhenApplyFails(t *testing.T) {
	applyErr := errors.New("injected engine failure")
	engine := &recordingNativeEngine{err: applyErr}
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

	result, err := ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativeDefaultDenyPolicy()}, input)
	if !errors.Is(err, applyErr) {
		t.Fatalf("error = %v, want wrapped engine failure", err)
	}
	if len(result.PolicySet.Subjects) != 1 || engine.applyCalls != 1 {
		t.Fatalf("result = %#v, Apply calls = %d; want compiled candidate and one Apply", result, engine.applyCalls)
	}
}

func TestReconcileNativePolicySnapshotRejectsMissingInputs(t *testing.T) {
	//nolint:staticcheck // Intentionally exercise defensive handling of a nil context.
	if _, err := ReconcileNativePolicySnapshot(nil, &recordingNativeEngine{}, nil, policy.ResolutionInput{}); err == nil {
		t.Fatal("ReconcileNativePolicySnapshot accepted a nil context")
	}
	if _, err := ReconcileNativePolicySnapshot(context.Background(), nil, nil, policy.ResolutionInput{}); err == nil {
		t.Fatal("ReconcileNativePolicySnapshot accepted a nil engine")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := &recordingNativeEngine{}
	if _, err := ReconcileNativePolicySnapshot(ctx, engine, nil, policy.ResolutionInput{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconciliation error = %v, want context.Canceled", err)
	}
	if engine.applyCalls != 0 {
		t.Fatalf("engine Apply calls = %d, want 0 for a canceled context", engine.applyCalls)
	}
}

func nativeDefaultDenyPolicy() policy.NativeNetworkPolicy {
	policyTypes := []string{"Ingress"}
	return policy.NativeNetworkPolicy{
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
}
