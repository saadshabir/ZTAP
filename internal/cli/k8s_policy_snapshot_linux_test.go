//go:build linux

package cli

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"ztap/internal/enforcer"
	"ztap/internal/policy"
)

type snapshotCapturingEngine struct {
	calls int
	set   policy.PolicySet
}

func (e *snapshotCapturingEngine) Apply(_ context.Context, set policy.PolicySet) error {
	e.calls++
	e.set = set
	return nil
}

func (*snapshotCapturingEngine) Close() error { return nil }

func TestBuildResolutionSnapshotProducesCompilerFactsAndCgroupPaths(t *testing.T) {
	cgroupRoot := t.TempDir()
	containerID := strings.Repeat("a", 64)
	podUID := types.UID("2b6a3c84-291d-4c16-9ca1-709384c3a4b2")
	uidToken := strings.ReplaceAll(string(podUID), "-", "_")
	cgroupPath := filepath.Join(
		cgroupRoot,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+uidToken+".slice",
		"cri-containerd-"+containerID+".scope",
	)
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("create cgroup fixture: %v", err)
	}

	resolver := newK8sSubjectResolver(fake.NewClientset(), cgroupRoot).(*k8sSubjectResolver)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
			{Type: corev1.NodeHostName, Address: "node-a"},
			{Type: corev1.NodeInternalIP, Address: "192.0.2.10"},
			{Type: corev1.NodeInternalIP, Address: "2001:db8::10"},
			{Type: corev1.NodeInternalIP, Address: "192.0.2.10"},
		}},
	}
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "trusted", Labels: map[string]string{"tenant": "trusted"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "local", Labels: map[string]string{"tenant": "local"}}},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "local", Name: "api", UID: podUID, Labels: map[string]string{"app": "api"}},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				QOSClass: corev1.PodQOSBurstable,
				PodIP:    "10.0.0.11",
				PodIPs:   []corev1.PodIP{{IP: "10.0.0.11"}, {IP: "2001:db8::11"}},
				ContainerStatuses: []corev1.ContainerStatus{{
					ContainerID: "containerd://" + containerID,
					State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "trusted", Name: "dns", Labels: map[string]string{"role": "dns"}},
			Spec:       corev1.PodSpec{NodeName: "node-b"},
			Status:     corev1.PodStatus{PodIP: "10.1.0.53"},
		},
	}

	input, err := resolver.BuildResolutionSnapshot("node-a", node, namespaces, pods)
	if err != nil {
		t.Fatalf("BuildResolutionSnapshot failed: %v", err)
	}
	if got, want := input.NodeIPs, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("203.0.113.10")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node IPs = %v, want %v", got, want)
	}
	if got := []string{input.Namespaces[0].Name, input.Namespaces[1].Name}; !reflect.DeepEqual(got, []string{"local", "trusted"}) {
		t.Fatalf("namespace order = %v", got)
	}
	if input.Namespaces[0].Labels["tenant"] != "local" {
		t.Fatalf("namespace labels = %#v", input.Namespaces[0].Labels)
	}
	if len(input.Pods) != 2 || input.Pods[0].Name != "api" || input.Pods[1].Name != "dns" {
		t.Fatalf("pods are not in stable namespace/name order: %#v", input.Pods)
	}
	localPod := input.Pods[0]
	if !localPod.Local || localPod.HostNetwork {
		t.Fatalf("local pod facts = %#v", localPod)
	}
	if got, want := localPod.PodIPs, []netip.Addr{netip.MustParseAddr("10.0.0.11"), netip.MustParseAddr("2001:db8::11")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pod IPs = %v, want %v", got, want)
	}
	if len(localPod.CgroupIDs) != 1 {
		t.Fatalf("local cgroup IDs = %v, want one", localPod.CgroupIDs)
	}
	wantID, err := cgroupIDFromPath(cgroupPath)
	if err != nil {
		t.Fatalf("stat cgroup fixture: %v", err)
	}
	if localPod.CgroupIDs[0] != wantID {
		t.Fatalf("local cgroup ID = %d, want %d", localPod.CgroupIDs[0], wantID)
	}
	gotPath, err := resolver.ResolveCgroupPath(context.Background(), wantID)
	if err != nil {
		t.Fatalf("ResolveCgroupPath failed: %v", err)
	}
	if gotPath != cgroupPath {
		t.Fatalf("cgroup path = %q, want %q", gotPath, cgroupPath)
	}
	if got := len(resolver.cgroupCache); got != 1 {
		t.Fatalf("cgroup cache entries = %d, want one", got)
	}
	observedAt, unresolved := resolver.classificationObservations()
	if unresolved != 0 {
		t.Fatalf("unresolved running containers = %d, want zero", unresolved)
	}
	if observedAt[wantID].IsZero() {
		t.Fatalf("missing first-observed timestamp for cgroup %d: %v", wantID, observedAt)
	}

	// A deleted scope invalidates the cached filesystem identity and is
	// reported as unresolved on the next immutable snapshot.
	if err := os.RemoveAll(cgroupPath); err != nil {
		t.Fatalf("remove cgroup fixture: %v", err)
	}
	invalidated, err := resolver.BuildResolutionSnapshot("node-a", node, namespaces, pods[:1])
	if err != nil {
		t.Fatalf("BuildResolutionSnapshot after cgroup removal failed: %v", err)
	}
	if got := invalidated.Pods[0].CgroupResolutionFailure; got != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("cgroup resolution failure after removal = %d, want not found", got)
	}
	if got := len(resolver.cgroupCache); got != 0 {
		t.Fatalf("cgroup cache entries after removal = %d, want zero", got)
	}
	observedAt, unresolved = resolver.classificationObservations()
	if unresolved != 1 || len(observedAt) != 0 {
		t.Fatalf("observations after removal = %v unresolved=%d, want no resolved entries and one unresolved container", observedAt, unresolved)
	}

	policyTypes := []string{"Ingress"}
	nativePolicy := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata:   &policy.NativeObjectMeta{Namespace: "local", Name: "deny-api-ingress"},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: &policyTypes,
		},
	}
	engine := &snapshotCapturingEngine{}
	compiled, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativePolicy}, input)
	if err != nil {
		t.Fatalf("ReconcileNativePolicySnapshot failed: %v", err)
	}
	if engine.calls != 1 || !reflect.DeepEqual(engine.set, compiled.PolicySet) {
		t.Fatalf("engine calls=%d set=%#v, compile result=%#v", engine.calls, engine.set, compiled.PolicySet)
	}
	if len(engine.set.Subjects) != 1 || engine.set.Subjects[0].CgroupID != wantID || engine.set.Subjects[0].Isolated != policy.DirectionIngress || engine.set.Subjects[0].Quarantined != policy.DirectionIngress {
		t.Fatalf("engine subject = %#v, want local dual-stack pod quarantined for ingress", engine.set.Subjects)
	}

	// A replacement snapshot drops paths for subjects no longer present.
	if _, err := resolver.BuildResolutionSnapshot("node-a", node, namespaces, pods[1:]); err != nil {
		t.Fatalf("BuildResolutionSnapshot after pod removal failed: %v", err)
	}
	if _, err := resolver.ResolveCgroupPath(context.Background(), wantID); err == nil {
		t.Fatal("ResolveCgroupPath found an ID removed from the latest snapshot")
	}
}

func TestBuildResolutionSnapshotRequiresMatchingLocalNode(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir()).(*k8sSubjectResolver)
	if _, err := resolver.BuildResolutionSnapshot("node-a", nil, nil, nil); err == nil {
		t.Fatal("BuildResolutionSnapshot accepted a missing node")
	}
	if _, err := resolver.BuildResolutionSnapshot("node-a", &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}}, nil, nil); err == nil {
		t.Fatal("BuildResolutionSnapshot accepted a different node")
	}
	if _, err := resolver.BuildResolutionSnapshot("", &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}, nil, nil); err == nil {
		t.Fatal("BuildResolutionSnapshot accepted an empty local node name")
	}
}

func TestBuildResolutionSnapshotMarksUnresolvedRunningContainerAndBlocksApply(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir()).(*k8sSubjectResolver)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type: corev1.NodeInternalIP, Address: "192.0.2.10",
		}}},
	}
	pods := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "api", UID: types.UID("2b6a3c84-291d-4c16-9ca1-709384c3a4b2"), Labels: map[string]string{"app": "api"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: "containerd://" + strings.Repeat("b", 64),
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}}

	input, err := resolver.BuildResolutionSnapshot(
		"node-a",
		node,
		[]corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		pods,
	)
	if err != nil {
		t.Fatalf("BuildResolutionSnapshot failed: %v", err)
	}
	if got := input.Pods[0].CgroupResolutionFailure; got != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("cgroup resolution failure = %d, want not found", got)
	}
	_, unresolved := resolver.classificationObservations()
	if unresolved != 1 {
		t.Fatalf("unresolved running containers = %d, want one", unresolved)
	}

	policyTypes := []string{"Ingress"}
	nativePolicy := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata:   &policy.NativeObjectMeta{Namespace: "default", Name: "deny-api-ingress"},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: &policyTypes,
		},
	}
	engine := &snapshotCapturingEngine{}
	if _, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativePolicy}, input); err == nil {
		t.Fatal("ReconcileNativePolicySnapshot accepted an unresolved selected running container")
	}
	if engine.calls != 0 {
		t.Fatalf("engine Apply calls = %d, want 0", engine.calls)
	}
}

func TestBuildResolutionSnapshotRejectsRunningContainerWithoutID(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir()).(*k8sSubjectResolver)
	input, err := resolver.BuildResolutionSnapshot(
		"node-a",
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
				Type: corev1.NodeInternalIP, Address: "192.0.2.10",
			}}},
		},
		[]corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		[]corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", Labels: map[string]string{"app": "api"}},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}},
		}},
	)
	if err != nil {
		t.Fatalf("BuildResolutionSnapshot failed: %v", err)
	}
	if got := input.Pods[0].CgroupResolutionFailure; got != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("running container without ID failure = %d, want not found", got)
	}
	if _, unresolved := resolver.classificationObservations(); unresolved != 1 {
		t.Fatalf("unresolved running containers = %d, want one", unresolved)
	}

	policyTypes := []string{"Egress"}
	nativePolicy := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata:   &policy.NativeObjectMeta{Namespace: "default", Name: "deny-api-egress"},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: &policyTypes,
		},
	}
	engine := &snapshotCapturingEngine{}
	if _, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativePolicy}, input); err == nil || !strings.Contains(err.Error(), "running container") {
		t.Fatalf("ReconcileNativePolicySnapshot error = %v, want unresolved running container", err)
	}
	if engine.calls != 0 {
		t.Fatalf("engine Apply calls = %d, want 0", engine.calls)
	}
}

func TestExtractRunningContainerdIDsIsStrictAndIgnoresCompletedContainers(t *testing.T) {
	validID := strings.Repeat("c", 64)
	pod := &corev1.Pod{Status: corev1.PodStatus{
		InitContainerStatuses: []corev1.ContainerStatus{{
			ContainerID: "docker://" + strings.Repeat("d", 64),
			State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}},
		}},
		ContainerStatuses: []corev1.ContainerStatus{
			{
				ContainerID: "containerd://" + validID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			},
			{
				ContainerID: "containerd://" + strings.Repeat("e", 64),
				State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}},
			},
		},
	}}

	ids, failure := extractRunningContainerdIDs(pod)
	if failure != policy.CgroupResolutionFailureNone || !reflect.DeepEqual(ids, []string{validID}) {
		t.Fatalf("IDs=%v failure=%d, want one running containerd ID and no failure", ids, failure)
	}
	pending := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}},
	}}}}
	if ids, failure := extractRunningContainerdIDs(pending); len(ids) != 0 || failure != policy.CgroupResolutionFailureNone {
		t.Fatalf("pending IDs=%v failure=%d, want no IDs and no failure", ids, failure)
	}
	runningWithoutID := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}}}
	if ids, failure := extractRunningContainerdIDs(runningWithoutID); len(ids) != 0 || failure != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("running without ID: IDs=%v failure=%d, want no IDs and not-found failure", ids, failure)
	}

	for name, containerID := range map[string]string{
		"docker":     "docker://" + strings.Repeat("a", 64),
		"short":      "containerd://abc123",
		"non-hex":    "containerd://" + strings.Repeat("z", 64),
		"bare ID":    strings.Repeat("a", 64),
		"whitespace": " containerd://" + strings.Repeat("a", 64),
	} {
		t.Run(name, func(t *testing.T) {
			invalid := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: containerID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}}}
			ids, failure := extractRunningContainerdIDs(invalid)
			if len(ids) != 0 || failure != policy.CgroupResolutionFailureUnsupportedRuntime {
				t.Fatalf("IDs=%v failure=%d, want unsupported runtime identity", ids, failure)
			}
		})
	}
}

func TestExtractRunningContainerdIDsRejectsNilPod(t *testing.T) {
	ids, failure := extractRunningContainerdIDs(nil)
	if len(ids) != 0 || failure != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("nil pod IDs=%v failure=%d, want no IDs and not-found failure", ids, failure)
	}
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir()).(*k8sSubjectResolver)
	if cgroups, failure := resolver.resolvePodCgroupsCached(nil); len(cgroups) != 0 || failure != policy.CgroupResolutionFailureNotFound {
		t.Fatalf("nil pod cgroups=%v failure=%d, want no cgroups and not-found failure", cgroups, failure)
	}
}

func TestFindContainerCgroupPathRequiresExactContainerdSystemdLayout(t *testing.T) {
	cgroupRoot := t.TempDir()
	containerID := strings.Repeat("f", 64)
	podUID := types.UID("2b6a3c84-291d-4c16-9ca1-709384c3a4b2")
	uidToken := strings.ReplaceAll(string(podUID), "-", "_")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", UID: podUID},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBurstable},
	}

	legacyPaths := []string{
		filepath.Join(cgroupRoot, "kubepods", "burstable", "pod"+uidToken, containerID),
		filepath.Join(
			cgroupRoot,
			"kubepods.slice",
			"kubepods-burstable.slice",
			"kubepods-burstable-pod"+uidToken+".slice",
			"docker-"+containerID+".scope",
		),
	}
	for _, path := range legacyPaths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create unsupported cgroup fixture: %v", err)
		}
	}
	if path, err := findContainerCgroupPath(cgroupRoot, pod, containerID); err == nil {
		t.Fatalf("findContainerCgroupPath accepted fallback layout %q", path)
	}

	want := filepath.Join(
		cgroupRoot,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+uidToken+".slice",
		"cri-containerd-"+containerID+".scope",
	)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatalf("create exact cgroup fixture: %v", err)
	}
	if got, err := findContainerCgroupPath(cgroupRoot, pod, containerID); err != nil || got != want {
		t.Fatalf("findContainerCgroupPath = %q, %v; want %q", got, err, want)
	}
	if err := os.RemoveAll(want); err != nil {
		t.Fatalf("remove exact cgroup fixture: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, want); err != nil {
		t.Fatalf("create outside cgroup symlink: %v", err)
	}
	if got, err := findContainerCgroupPath(cgroupRoot, pod, containerID); err == nil {
		t.Fatalf("findContainerCgroupPath accepted path outside root %q", got)
	}
}

func TestFindContainerCgroupPathRejectsIncompletePodIdentity(t *testing.T) {
	cgroupRoot := t.TempDir()
	containerID := strings.Repeat("a", 64)

	if path, err := findContainerCgroupPath(cgroupRoot, nil, containerID); err == nil {
		t.Fatalf("findContainerCgroupPath accepted nil pod and returned %q", path)
	}
	if path, err := findContainerCgroupPath(cgroupRoot, &corev1.Pod{}, containerID); err == nil {
		t.Fatalf("findContainerCgroupPath accepted pod without UID and returned %q", path)
	}
}
