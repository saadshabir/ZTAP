//go:build linux

package cli

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNativePodUpdatesRetainEnforcementFacts(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "apps", UID: "uid", Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "main", SecurityContext: benchmarkSecurityContext()}}, InitContainers: []corev1.Container{{Name: "init", SecurityContext: benchmarkSecurityContext()}}, EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", SecurityContext: benchmarkSecurityContext()}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, QOSClass: corev1.PodQOSBurstable, PodIP: "10.0.0.1", PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}}, ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://main", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}, InitContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://init"}}, EphemeralContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://debug"}}}}
	relevant := map[string]func(*corev1.Pod){
		"uid":              func(p *corev1.Pod) { p.UID = "replacement" },
		"name":             func(p *corev1.Pod) { p.Name = "replacement" },
		"namespace":        func(p *corev1.Pod) { p.Namespace = "peer" },
		"labels":           func(p *corev1.Pod) { p.Labels["app"] = "db" },
		"node":             func(p *corev1.Pod) { p.Spec.NodeName = "node-b" },
		"host-network":     func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"phase":            func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded },
		"qos":              func(p *corev1.Pod) { p.Status.QOSClass = corev1.PodQOSGuaranteed },
		"ip":               func(p *corev1.Pod) { p.Status.PodIP = "10.0.0.2" },
		"ips":              func(p *corev1.Pod) { p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: "2001:db8::1"}) },
		"container-id":     func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "" },
		"running":          func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Running = nil },
		"init-running":     func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].State.Running = &corev1.ContainerStateRunning{} },
		"ephemeral-id":     func(p *corev1.Pod) { p.Status.EphemeralContainerStatuses[0].ContainerID = "replacement" },
		"containers":       func(p *corev1.Pod) { p.Spec.Containers = nil },
		"security-missing": func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext = nil },
		"escalation":       func(p *corev1.Pod) { *p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = true },
		"privileged":       func(p *corev1.Pod) { v := true; p.Spec.Containers[0].SecurityContext.Privileged = &v },
		"capability-drop":  func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Capabilities.Drop = nil },
		"capability-add": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_RAW"}
		},
		"init-security":      func(p *corev1.Pod) { p.Spec.InitContainers[0].SecurityContext = nil },
		"ephemeral-security": func(p *corev1.Pod) { p.Spec.EphemeralContainers[0].SecurityContext = nil },
	}
	for name, mutate := range relevant {
		t.Run(name, func(t *testing.T) {
			updated := pod.DeepCopy()
			mutate(updated)
			if !nativeObjectChanged(pod, updated) {
				t.Fatal("enforcement change was filtered")
			}
		})
	}
	unrelated := pod.DeepCopy()
	unrelated.ResourceVersion = "new"
	unrelated.Annotations = map[string]string{"owner": "new"}
	unrelated.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "new"}}
	unrelated.Spec.Containers[0].Image = "new"
	unrelated.Status.ContainerStatuses[0].Ready = true
	unrelated.Status.ContainerStatuses[0].RestartCount++
	unrelated.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if nativeObjectChanged(pod, unrelated) {
		t.Fatal("unconsumed Pod churn triggered reconciliation")
	}
}

func TestNativeNamespaceNodeAndPolicyUpdateFiltering(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "a"}}}
	otherNS := ns.DeepCopy()
	otherNS.Annotations = map[string]string{"owner": "b"}
	if nativeObjectChanged(ns, otherNS) {
		t.Fatal("namespace annotation triggered reconciliation")
	}
	otherNS.Labels["tenant"] = "b"
	if !nativeObjectChanged(ns, otherNS) {
		t.Fatal("namespace selector update was filtered")
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
	otherNode := node.DeepCopy()
	otherNode.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady}}
	if nativeObjectChanged(node, otherNode) {
		t.Fatal("node condition triggered reconciliation")
	}
	otherNode.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}}
	if !nativeObjectChanged(node, otherNode) {
		t.Fatal("node address update was filtered")
	}
	p := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "apps"}}
	other := p.DeepCopy()
	other.ResourceVersion = "2"
	if nativeObjectChanged(p, other) {
		t.Fatal("policy resource version triggered reconciliation")
	}
	other.Spec.PodSelector.MatchLabels = map[string]string{"app": "web"}
	if !nativeObjectChanged(p, other) {
		t.Fatal("policy spec update was filtered")
	}
	if !nativeObjectChanged(p, nil) {
		t.Fatal("unknown event should trigger reconciliation")
	}
}
