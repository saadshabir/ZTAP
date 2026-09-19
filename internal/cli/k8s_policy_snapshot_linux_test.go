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
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	cachetesting "k8s.io/client-go/tools/cache/testing"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/policy"
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

func subjectByCgroupID(t *testing.T, set policy.PolicySet, cgroupID uint64) policy.Subject {
	t.Helper()
	for _, subject := range set.Subjects {
		if subject.CgroupID == cgroupID {
			return subject
		}
	}
	t.Fatalf("policy set has no subject for cgroup %d: %#v", cgroupID, set.Subjects)
	return policy.Subject{}
}

func TestNativePolicySnapshotConvergesAcrossPolicyPodNamespaceAndNodeChanges(t *testing.T) {
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

	policyIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	podIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	namespaceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	policyLister := networkinglisters.NewNetworkPolicyLister(policyIndexer)
	podLister := corelisters.NewPodLister(podIndexer)
	namespaceLister := corelisters.NewNamespaceLister(namespaceIndexer)
	nodeLister := corelisters.NewNodeLister(nodeIndexer)
	resolver := newK8sSubjectResolver(fake.NewClientset(), cgroupRoot)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type: corev1.NodeInternalIP, Address: "192.0.2.10",
		}}},
	}
	defaultNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	peerNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "peer", Labels: map[string]string{"team": "blue"}},
	}
	localPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "api", UID: podUID,
			Labels: map[string]string{"app": "api"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			PodIP:    "10.0.0.2",
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: "containerd://" + containerID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	peerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "peer", Name: "worker", Labels: map[string]string{"role": "worker"}},
		Spec:       corev1.PodSpec{NodeName: "node-b"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.3"},
	}
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(443)
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "allow-peer", Generation: 1},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
			}},
		},
	}
	for name, indexer := range map[string]cache.Indexer{
		"policy":    policyIndexer,
		"pod":       podIndexer,
		"namespace": namespaceIndexer,
		"node":      nodeIndexer,
	} {
		var object any
		switch name {
		case "policy":
			object = networkPolicy
		case "pod":
			if err := indexer.Add(localPod); err != nil {
				t.Fatalf("add local pod: %v", err)
			}
			if err := indexer.Add(peerPod); err != nil {
				t.Fatalf("add peer pod: %v", err)
			}
			continue
		case "namespace":
			if err := indexer.Add(defaultNamespace); err != nil {
				t.Fatalf("add default namespace: %v", err)
			}
			if err := indexer.Add(peerNamespace); err != nil {
				t.Fatalf("add peer namespace: %v", err)
			}
			continue
		case "node":
			object = node
		}
		if err := indexer.Add(object); err != nil {
			t.Fatalf("add %s object: %v", name, err)
		}
	}

	reconcile := func() policy.PolicySet {
		policies, input, _, err := nativePolicySnapshot("node-a", policyLister, podLister, namespaceLister, nodeLister, resolver)
		if err != nil {
			t.Fatalf("nativePolicySnapshot: %v", err)
		}
		engine := &snapshotCapturingEngine{}
		result, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
		if err != nil {
			t.Fatalf("ReconcileNativePolicySnapshot: %v", err)
		}
		if !reflect.DeepEqual(engine.set, result.PolicySet) {
			t.Fatalf("engine received %#v, want %#v", engine.set, result.PolicySet)
		}
		return result.PolicySet
	}

	set := reconcile()
	if len(set.Subjects) != 1 || set.Subjects[0].Isolated != policy.DirectionEgress {
		t.Fatalf("initial subjects = %#v, want one egress-isolated subject", set.Subjects)
	}
	wantRule := policy.Rule{CgroupID: set.Subjects[0].CgroupID, Direction: policy.DirectionEgress, Peer: netip.MustParsePrefix("10.0.0.3/32"), Protocol: policy.ProtocolTCP, Port: 443}
	if len(set.Rules) != 1 || set.Rules[0] != wantRule {
		t.Fatalf("initial rules = %#v, want %#v", set.Rules, []policy.Rule{wantRule})
	}

	peerNamespace = peerNamespace.DeepCopy()
	peerNamespace.Labels = map[string]string{"team": "red"}
	if err := namespaceIndexer.Update(peerNamespace); err != nil {
		t.Fatalf("update peer namespace labels: %v", err)
	}
	set = reconcile()
	if len(set.Subjects) != 1 || len(set.Rules) != 0 {
		t.Fatalf("namespace-label update produced subjects=%#v rules=%#v, want isolated subject with no peer rule", set.Subjects, set.Rules)
	}

	localPod = localPod.DeepCopy()
	localPod.Labels = map[string]string{"app": "worker"}
	if err := podIndexer.Update(localPod); err != nil {
		t.Fatalf("update local pod labels: %v", err)
	}
	set = reconcile()
	if len(set.Subjects) != 0 || len(set.Rules) != 0 {
		t.Fatalf("pod-label update produced subjects=%#v rules=%#v, want empty policy set", set.Subjects, set.Rules)
	}

	localPod = localPod.DeepCopy()
	localPod.Labels = map[string]string{"app": "api"}
	if err := podIndexer.Update(localPod); err != nil {
		t.Fatalf("restore local pod labels: %v", err)
	}
	peerNamespace = peerNamespace.DeepCopy()
	peerNamespace.Labels = map[string]string{"team": "blue"}
	if err := namespaceIndexer.Update(peerNamespace); err != nil {
		t.Fatalf("restore peer namespace labels: %v", err)
	}
	node = node.DeepCopy()
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.11"}}
	if err := nodeIndexer.Update(node); err != nil {
		t.Fatalf("update node address: %v", err)
	}
	set = reconcile()
	if len(set.Subjects) != 1 || len(set.Rules) != 1 {
		t.Fatalf("restored snapshot produced subjects=%#v rules=%#v, want restored policy", set.Subjects, set.Rules)
	}
	policies, input, _, err := nativePolicySnapshot("node-a", policyLister, podLister, namespaceLister, nodeLister, resolver)
	if err != nil {
		t.Fatalf("snapshot after node update: %v", err)
	}
	if len(policies) != 1 || !reflect.DeepEqual(input.NodeIPs, []netip.Addr{netip.MustParseAddr("192.0.2.11")}) {
		t.Fatalf("node update snapshot policies=%d nodeIPs=%v", len(policies), input.NodeIPs)
	}

	if err := policyIndexer.Delete(networkPolicy); err != nil {
		t.Fatalf("delete network policy: %v", err)
	}
	set = reconcile()
	if len(set.Subjects) != 0 || len(set.Rules) != 0 {
		t.Fatalf("policy deletion produced subjects=%#v rules=%#v, want empty policy set", set.Subjects, set.Rules)
	}
}

func TestNativePolicySnapshotCorrectsAndDeletesRejectedPolicyWithoutRestart(t *testing.T) {
	cgroupRoot := t.TempDir()
	fixturePath := func(containerID string, podUID types.UID) string {
		uidToken := strings.ReplaceAll(string(podUID), "-", "_")
		return filepath.Join(
			cgroupRoot,
			"kubepods.slice",
			"kubepods-burstable.slice",
			"kubepods-burstable-pod"+uidToken+".slice",
			"cri-containerd-"+containerID+".scope",
		)
	}
	makeCgroup := func(containerID string, podUID types.UID) {
		path := fixturePath(containerID, podUID)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create cgroup fixture: %v", err)
		}
	}

	badContainerID := strings.Repeat("b", 64)
	goodContainerID := strings.Repeat("c", 64)
	badUID := types.UID("5a6b7c8d-291d-4c16-9ca1-709384c3a4b2")
	goodUID := types.UID("6b7c8d9e-291d-4c16-9ca1-709384c3a4b2")
	makeCgroup(badContainerID, badUID)
	makeCgroup(goodContainerID, goodUID)
	badCgroupID, err := cgroupIDFromPath(fixturePath(badContainerID, badUID))
	if err != nil {
		t.Fatalf("stat bad cgroup fixture: %v", err)
	}
	goodCgroupID, err := cgroupIDFromPath(fixturePath(goodContainerID, goodUID))
	if err != nil {
		t.Fatalf("stat good cgroup fixture: %v", err)
	}

	policyIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	podIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	namespaceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	policyLister := networkinglisters.NewNetworkPolicyLister(policyIndexer)
	podLister := corelisters.NewPodLister(podIndexer)
	namespaceLister := corelisters.NewNamespaceLister(namespaceIndexer)
	nodeLister := corelisters.NewNodeLister(nodeIndexer)
	resolver := newK8sSubjectResolver(fake.NewClientset(), cgroupRoot)

	if err := nodeIndexer.Add(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type: corev1.NodeInternalIP, Address: "192.0.2.10",
		}}},
	}); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if err := namespaceIndexer.Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}); err != nil {
		t.Fatalf("add namespace: %v", err)
	}
	addRunningPod := func(name string, uid types.UID, containerID, label, ip string) {
		t.Helper()
		if err := podIndexer.Add(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, UID: uid, Labels: map[string]string{"role": label}},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				QOSClass: corev1.PodQOSBurstable,
				PodIP:    ip,
				ContainerStatuses: []corev1.ContainerStatus{{
					ContainerID: "containerd://" + containerID,
					State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}},
			},
		}); err != nil {
			t.Fatalf("add pod %s: %v", name, err)
		}
	}
	addRunningPod("bad", badUID, badContainerID, "bad", "10.0.0.2")
	addRunningPod("good", goodUID, goodContainerID, "good", "10.0.0.3")

	protocol := corev1.ProtocolTCP
	namedPort := intstr.FromString("https")
	badPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "bad", Generation: 1},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "bad"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "198.51.100.0/24"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &namedPort}},
			}},
		},
	}
	goodPort := intstr.FromInt(443)
	goodPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "good", Generation: 1},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "good"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "203.0.113.0/24"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &goodPort}},
			}},
		},
	}
	if err := policyIndexer.Add(badPolicy); err != nil {
		t.Fatalf("add bad policy: %v", err)
	}
	if err := policyIndexer.Add(goodPolicy); err != nil {
		t.Fatalf("add good policy: %v", err)
	}

	status := &nativeAgentHTTP{reason: "starting"}
	reconcile := func() policy.CompileResult {
		t.Helper()
		policies, input, telemetry, err := nativePolicySnapshot("node-a", policyLister, podLister, namespaceLister, nodeLister, resolver)
		if err != nil {
			t.Fatalf("nativePolicySnapshot: %v", err)
		}
		engine := &snapshotCapturingEngine{}
		result, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
		if err != nil {
			t.Fatalf("ReconcileNativePolicySnapshot: %v", err)
		}
		status.recordResolutionTelemetry(telemetry.unresolvedRunningContainers)
		status.recordReconciliation(len(policies), result, nil, time.Millisecond, false)
		status.markApplied(result, false)
		return result
	}
	assertReadiness := func(wantReady bool, wantReason string) {
		t.Helper()
		status.stateMu.RLock()
		ready, reason := status.ready, status.reason
		status.stateMu.RUnlock()
		if ready != wantReady || reason != wantReason {
			t.Fatalf("readiness = %t/%q, want %t/%q", ready, reason, wantReady, wantReason)
		}
	}

	result := reconcile()
	if len(result.Rejected) != 1 || result.Rejected[0].Name != "bad" {
		t.Fatalf("initial rejected policies = %#v, want bad policy", result.Rejected)
	}
	badSubject := subjectByCgroupID(t, result.PolicySet, badCgroupID)
	if badSubject.Quarantined != policy.DirectionIngress {
		t.Fatalf("initial bad subject = %#v, want ingress quarantine", badSubject)
	}
	goodSubject := subjectByCgroupID(t, result.PolicySet, goodCgroupID)
	if goodSubject.Quarantined != 0 || goodSubject.Isolated != policy.DirectionEgress {
		t.Fatalf("initial good subject = %#v, want accepted egress isolation", goodSubject)
	}
	assertReadiness(false, "quarantined")

	corrected := badPolicy.DeepCopy()
	corrected.Generation = 2
	corrected.Spec.Ingress[0].Ports[0].Port = &goodPort
	if err := policyIndexer.Update(corrected); err != nil {
		t.Fatalf("correct bad policy: %v", err)
	}
	result = reconcile()
	if len(result.Rejected) != 0 {
		t.Fatalf("corrected rejected policies = %#v, want none", result.Rejected)
	}
	badSubject = subjectByCgroupID(t, result.PolicySet, badCgroupID)
	if badSubject.Quarantined != 0 || badSubject.Isolated != policy.DirectionIngress {
		t.Fatalf("corrected bad subject = %#v, want ingress isolation without quarantine", badSubject)
	}
	goodSubject = subjectByCgroupID(t, result.PolicySet, goodCgroupID)
	if goodSubject.Quarantined != 0 || goodSubject.Isolated != policy.DirectionEgress {
		t.Fatalf("corrected good subject = %#v, want unrelated accepted policy preserved", goodSubject)
	}
	assertReadiness(true, "ok")

	if err := policyIndexer.Delete(corrected); err != nil {
		t.Fatalf("delete corrected policy: %v", err)
	}
	result = reconcile()
	if len(result.Rejected) != 0 || len(result.PolicySet.Subjects) != 1 {
		t.Fatalf("after deletion rejected=%#v subjects=%#v, want only good subject", result.Rejected, result.PolicySet.Subjects)
	}
	goodSubject = subjectByCgroupID(t, result.PolicySet, goodCgroupID)
	if goodSubject.Isolated != policy.DirectionEgress || goodSubject.Quarantined != 0 {
		t.Fatalf("after deletion good subject = %#v, want accepted egress isolation", goodSubject)
	}
	assertReadiness(true, "ok")
}

func TestNativeAgentInformerRelistSignalsDirtyQueue(t *testing.T) {
	source := cachetesting.NewFakeControllerSource()
	informer := cache.NewSharedIndexInformer(source, &corev1.Pod{}, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	dirty := make(chan struct{}, 1)
	if err := replaceNativeAgentHandler(informer, dirty); err != nil {
		t.Fatalf("register informer handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		informer.Run(ctx.Done())
		close(done)
	}()
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("informer cache did not synchronize")
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api", UID: types.UID("pod-1")}}
	source.Add(pod)
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("add event did not signal the dirty queue")
	}

	updated := pod.DeepCopy()
	updated.Labels = map[string]string{"relisted": "true"}
	source.ModifyDropWatch(updated)
	source.ResetWatch()
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("relist update did not signal the dirty queue")
	}
	stored, exists, err := informer.GetStore().GetByKey("apps/api")
	if err != nil {
		t.Fatalf("get relisted pod: %v", err)
	}
	if !exists || stored.(*corev1.Pod).Labels["relisted"] != "true" {
		t.Fatalf("relisted pod = %#v, exists=%t; want updated object", stored, exists)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("informer did not stop")
	}
}

func TestNativeAgentRelistReconcilesUpdatedPodSnapshot(t *testing.T) {
	cgroupRoot := t.TempDir()
	containerID := strings.Repeat("d", 64)
	podUID := types.UID("pod-1")
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

	policyIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	namespaceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	policyLister := networkinglisters.NewNetworkPolicyLister(policyIndexer)
	namespaceLister := corelisters.NewNamespaceLister(namespaceIndexer)
	nodeLister := corelisters.NewNodeLister(nodeIndexer)
	resolver := newK8sSubjectResolver(fake.NewClientset(), cgroupRoot)

	if err := namespaceIndexer.Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}); err != nil {
		t.Fatalf("add namespace: %v", err)
	}
	if err := nodeIndexer.Add(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type: corev1.NodeInternalIP, Address: "192.0.2.10",
		}}},
	}); err != nil {
		t.Fatalf("add node: %v", err)
	}
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(443)
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api-ingress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "198.51.100.0/24"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
			}},
		},
	}
	if err := policyIndexer.Add(networkPolicy); err != nil {
		t.Fatalf("add network policy: %v", err)
	}

	source := cachetesting.NewFakeControllerSource()
	podInformer := cache.NewSharedIndexInformer(source, &corev1.Pod{}, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	dirty := make(chan struct{}, 1)
	if err := replaceNativeAgentHandler(podInformer, dirty); err != nil {
		t.Fatalf("register pod informer handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		podInformer.Run(ctx.Done())
		close(done)
	}()
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		t.Fatal("pod informer cache did not synchronize")
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api", UID: podUID, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			PodIP:    "10.0.0.2",
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: "containerd://" + containerID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	source.Add(pod)
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("initial pod add did not signal the dirty queue")
	}

	reconcile := func() policy.PolicySet {
		t.Helper()
		podLister := corelisters.NewPodLister(podInformer.GetIndexer())
		policies, input, _, err := nativePolicySnapshot("node-a", policyLister, podLister, namespaceLister, nodeLister, resolver)
		if err != nil {
			t.Fatalf("nativePolicySnapshot: %v", err)
		}
		engine := &snapshotCapturingEngine{}
		result, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
		if err != nil {
			t.Fatalf("ReconcileNativePolicySnapshot: %v", err)
		}
		return result.PolicySet
	}

	set := reconcile()
	if len(set.Subjects) != 1 || set.Subjects[0].Isolated != policy.DirectionIngress {
		t.Fatalf("initial relisted snapshot subjects = %#v, want one ingress-isolated subject", set.Subjects)
	}

	updated := pod.DeepCopy()
	updated.Labels = map[string]string{"app": "worker"}
	source.ModifyDropWatch(updated)
	source.ResetWatch()
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("relisted pod update did not signal the dirty queue")
	}
	set = reconcile()
	if len(set.Subjects) != 0 || len(set.Rules) != 0 {
		t.Fatalf("relisted updated snapshot subjects = %#v rules = %#v, want no selected policy subject", set.Subjects, set.Rules)
	}

	// A normal watch update can select the Pod again after the relist. Deleting
	// that selected object must then remove its subject on the next snapshot.
	selectedAgain := updated.DeepCopy()
	selectedAgain.Labels = map[string]string{"app": "api"}
	source.Modify(selectedAgain)
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("watch pod update did not signal the dirty queue")
	}
	set = reconcile()
	if len(set.Subjects) != 1 || set.Subjects[0].Isolated != policy.DirectionIngress {
		t.Fatalf("watch-updated snapshot subjects = %#v, want one ingress-isolated subject", set.Subjects)
	}

	source.Delete(selectedAgain)
	select {
	case <-dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("pod delete did not signal the dirty queue")
	}
	set = reconcile()
	if len(set.Subjects) != 0 || len(set.Rules) != 0 {
		t.Fatalf("deleted snapshot subjects = %#v rules = %#v, want no selected policy subject", set.Subjects, set.Rules)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pod informer did not stop")
	}
}

func TestNativeAgentPolicyInformerConvergesAddUpdateDeleteRelist(t *testing.T) {
	cgroupRoot := t.TempDir()
	containerID := strings.Repeat("e", 64)
	podUID := types.UID("policy-pod-1")
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

	policySource := cachetesting.NewFakeControllerSource()
	policyInformer := cache.NewSharedIndexInformer(
		policySource,
		&networkingv1.NetworkPolicy{},
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	dirty := make(chan struct{}, 1)
	if err := replaceNativeAgentHandler(policyInformer, dirty); err != nil {
		t.Fatalf("register policy informer handler: %v", err)
	}

	policyIndexer := policyInformer.GetIndexer()
	namespaceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	podIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	namespaceLister := corelisters.NewNamespaceLister(namespaceIndexer)
	nodeLister := corelisters.NewNodeLister(nodeIndexer)
	podLister := corelisters.NewPodLister(podIndexer)
	resolver := newK8sSubjectResolver(nil, cgroupRoot)

	if err := namespaceIndexer.Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}); err != nil {
		t.Fatalf("add namespace: %v", err)
	}
	if err := nodeIndexer.Add(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type: corev1.NodeInternalIP, Address: "192.0.2.10",
		}}},
	}); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if err := podIndexer.Add(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "api", UID: podUID,
			Labels: map[string]string{"app": "api"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			PodIP:    "10.0.0.2",
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: "containerd://" + containerID,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}); err != nil {
		t.Fatalf("add pod: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		policyInformer.Run(ctx.Done())
		close(done)
	}()
	if !cache.WaitForCacheSync(ctx.Done(), policyInformer.HasSynced) {
		t.Fatal("policy informer cache did not synchronize")
	}

	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(443)
	policyObject := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api-ingress", Generation: 1},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "198.51.100.0/24"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
			}},
		},
	}
	waitForDirty := func(description string) {
		t.Helper()
		select {
		case <-dirty:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not signal the dirty queue", description)
		}
	}
	reconcile := func() policy.PolicySet {
		t.Helper()
		policies, input, _, err := nativePolicySnapshot(
			"node-a",
			networkinglisters.NewNetworkPolicyLister(policyIndexer),
			podLister,
			namespaceLister,
			nodeLister,
			resolver,
		)
		if err != nil {
			t.Fatalf("nativePolicySnapshot: %v", err)
		}
		engine := &snapshotCapturingEngine{}
		result, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, policies, input)
		if err != nil {
			t.Fatalf("ReconcileNativePolicySnapshot: %v", err)
		}
		return result.PolicySet
	}
	assertPort := func(set policy.PolicySet, want uint16) {
		t.Helper()
		if len(set.Subjects) != 1 || len(set.Rules) != 1 || set.Rules[0].Port != want {
			t.Fatalf("policy set = %#v, want one subject and port %d", set, want)
		}
	}

	policySource.Add(policyObject)
	waitForDirty("policy add")
	set := reconcile()
	assertPort(set, 443)

	updated := policyObject.DeepCopy()
	updated.Generation = 2
	updatedPort := intstr.FromInt(8443)
	updated.Spec.Ingress[0].Ports[0].Port = &updatedPort
	policySource.Modify(updated)
	waitForDirty("policy update")
	set = reconcile()
	assertPort(set, 8443)

	relisted := updated.DeepCopy()
	relisted.Generation = 3
	relistedPort := intstr.FromInt(9443)
	relisted.Spec.Ingress[0].Ports[0].Port = &relistedPort
	policySource.ModifyDropWatch(relisted)
	policySource.ResetWatch()
	waitForDirty("policy relist")
	set = reconcile()
	assertPort(set, 9443)

	policySource.Delete(relisted)
	waitForDirty("policy delete")
	set = reconcile()
	if len(set.Subjects) != 0 || len(set.Rules) != 0 {
		t.Fatalf("deleted policy set = %#v, want no subjects or rules", set)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("policy informer did not stop")
	}
}

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

	resolver := newK8sSubjectResolver(fake.NewClientset(), cgroupRoot)
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
	if got, want := input.NodeIPs, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}; !reflect.DeepEqual(got, want) {
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
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir())
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
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir())
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

func TestBuildResolutionSnapshotTreatsRunningContainerWithoutIDAsPending(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir())
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
	if got := input.Pods[0].CgroupResolutionFailure; got != policy.CgroupResolutionFailureNone {
		t.Fatalf("running container without ID failure = %d, want pending/no failure", got)
	}
	if _, unresolved := resolver.classificationObservations(); unresolved != 0 {
		t.Fatalf("unresolved running containers = %d, want zero for pending container ID", unresolved)
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
	if _, err := enforcer.ReconcileNativePolicySnapshot(context.Background(), engine, []policy.NativeNetworkPolicy{nativePolicy}, input); err != nil {
		t.Fatalf("ReconcileNativePolicySnapshot rejected pending container ID: %v", err)
	}
	if engine.calls != 1 {
		t.Fatalf("engine Apply calls = %d, want one pending-safe apply", engine.calls)
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
	if ids, failure := extractRunningContainerdIDs(runningWithoutID); len(ids) != 0 || failure != policy.CgroupResolutionFailureNone {
		t.Fatalf("running without ID: IDs=%v failure=%d, want no IDs and pending/no failure", ids, failure)
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
	resolver := newK8sSubjectResolver(fake.NewClientset(), t.TempDir())
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
	kubeletWant := filepath.Join(
		cgroupRoot,
		"kubelet.slice",
		"kubelet-kubepods.slice",
		"kubelet-kubepods-burstable.slice",
		"kubelet-kubepods-burstable-pod"+uidToken+".slice",
		"cri-containerd-"+containerID+".scope",
	)
	if err := os.MkdirAll(kubeletWant, 0o755); err != nil {
		t.Fatalf("create kubelet-scoped exact cgroup fixture: %v", err)
	}
	if got, err := findContainerCgroupPath(cgroupRoot, pod, containerID); err != nil || got != kubeletWant {
		t.Fatalf("findContainerCgroupPath = %q, %v; want %q", got, err, kubeletWant)
	}
	if err := os.RemoveAll(kubeletWant); err != nil {
		t.Fatalf("remove kubelet-scoped exact cgroup fixture: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, kubeletWant); err != nil {
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
