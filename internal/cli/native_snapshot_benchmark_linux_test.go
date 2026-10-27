//go:build linux

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/saadshabir/ZTAP/internal/enforcer"
)

// This measures cached snapshot resolution and compilation on Linux, including
// filesystem identity checks. Kernel writes, API latency and debounce are
// measured separately by the integration-tagged Phase 5 agent harness.
func BenchmarkNativeSnapshotReconciliation(b *testing.B) {
	for _, scenario := range []string{"unchanged", "policy-change", "pod-churn", "selectors"} {
		b.Run(scenario, func(b *testing.B) {
			root := b.TempDir()
			indexers := make([]cache.Indexer, 4)
			for i := range indexers {
				indexers[i] = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			}
			add := func(i int, obj any) {
				if err := indexers[i].Add(obj); err != nil {
					b.Fatal(err)
				}
			}
			add(3, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}}}})
			add(2, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "benchmark"}}})
			var changingPod *corev1.Pod
			for i := 0; i < 250; i++ {
				uid := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
				container := fmt.Sprintf("%064x", i+1)
				path := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice", "cri-containerd-"+container+".scope")
				if err := os.MkdirAll(path, 0o755); err != nil {
					b.Fatal(err)
				}
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("pod-%03d", i), Namespace: "apps", UID: types.UID(uid),
						Labels:      map[string]string{"bucket": fmt.Sprintf("%02d", i/10), "peer": fmt.Sprintf("%02d", i%10)},
						Annotations: map[string]string{"unconsumed": strings.Repeat("x", 4096)},
					},
					Spec: corev1.PodSpec{
						NodeName: "node-a",
						Containers: []corev1.Container{{
							Name: "workload", Image: "fixture", SecurityContext: benchmarkSecurityContext(),
							Env: []corev1.EnvVar{{Name: "UNCONSUMED", Value: "fixture"}},
						}},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning, QOSClass: corev1.PodQOSBurstable,
						PodIP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1),
						ContainerStatuses: []corev1.ContainerStatus{{
							ContainerID: "containerd://" + container,
							State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
						}},
					},
				}
				add(1, pod)
				changingPod = pod
			}
			port := intstr.FromInt(10000)
			var changingPolicy *networkingv1.NetworkPolicy
			for i := 0; i < 25; i++ {
				peers := make([]networkingv1.NetworkPolicyPeer, 10)
				for j := range peers {
					peers[j].IPBlock = &networkingv1.IPBlock{CIDR: fmt.Sprintf("198.18.%d.%d/32", i, j)}
					if scenario == "selectors" {
						peers[j] = networkingv1.NetworkPolicyPeer{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "benchmark"}},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"bucket": fmt.Sprintf("%02d", (i+1)%25)},
								MatchExpressions: []metav1.LabelSelectorRequirement{{
									Key: "peer", Operator: metav1.LabelSelectorOpIn, Values: []string{fmt.Sprintf("%02d", j)},
								}},
							},
						}
					}
				}
				p := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("policy-%02d", i), Namespace: "apps", Generation: 1},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"bucket": fmt.Sprintf("%02d", i)}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress:      []networkingv1.NetworkPolicyEgressRule{{To: peers, Ports: []networkingv1.NetworkPolicyPort{{Port: &port}}}},
					},
				}
				add(0, p)
				changingPolicy = p
			}
			resolver := newK8sSubjectResolver(root)
			ctx := context.Background()
			reconcile := func() {
				policies, input, _, err := nativePolicySnapshot("node-a", networkinglisters.NewNetworkPolicyLister(indexers[0]), corelisters.NewPodLister(indexers[1]), corelisters.NewNamespaceLister(indexers[2]), corelisters.NewNodeLister(indexers[3]), resolver)
				if err != nil {
					b.Fatal(err)
				}
				result, err := enforcer.ReconcileNativePolicySnapshot(ctx, nativeDryRunEngine{}, policies, input)
				if err != nil {
					b.Fatal(err)
				}
				if len(result.Rejected) != 0 || len(result.PolicySet.Subjects) != 250 || len(result.PolicySet.Rules) != 2500 {
					b.Fatalf("fixture changed: rejected=%d subjects=%d rules=%d", len(result.Rejected), len(result.PolicySet.Subjects), len(result.PolicySet.Rules))
				}
			}
			reconcile()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if scenario == "policy-change" {
					p := changingPolicy.DeepCopy()
					p.Generation = int64(i + 2)
					p.Spec.Egress[0].To[0].IPBlock.CIDR = fmt.Sprintf("203.0.113.%d/32", i%2+1)
					add(0, p)
				}
				if scenario == "pod-churn" {
					p := changingPod.DeepCopy()
					p.Status.PodIP = fmt.Sprintf("10.1.0.%d", i%2+1)
					add(1, p)
				}
				reconcile()
			}
		})
	}
}

func benchmarkSecurityContext() *corev1.SecurityContext {
	deny := false
	return &corev1.SecurityContext{AllowPrivilegeEscalation: &deny, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}}}
}
