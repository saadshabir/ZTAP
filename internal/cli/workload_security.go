package cli

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// validatePacketSocketIsolation checks existing Pods as well as admission's
// future-Pod contract. AF_PACKET traffic bypasses cgroup_skb hooks entirely.
// Host-network Pods are outside the enforcement contract; terminal Pods no
// longer own their network namespaces or peer addresses.
func validatePacketSocketIsolation(pods []corev1.Pod) error {
	refs := make([]*corev1.Pod, len(pods))
	for i := range pods {
		refs[i] = &pods[i]
	}
	return validatePacketSocketIsolationRefs(refs)
}

func validatePacketSocketIsolationRefs(pods []*corev1.Pod) error {
	for _, pod := range pods {
		if pod.Spec.HostNetwork || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		check := func(name string, security *corev1.SecurityContext) error {
			if security == nil || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation ||
				(security.Privileged != nil && *security.Privileged) || security.Capabilities == nil ||
				(!slices.Contains(security.Capabilities.Drop, corev1.Capability("ALL")) &&
					!slices.Contains(security.Capabilities.Drop, corev1.Capability("NET_RAW"))) ||
				slices.Contains(security.Capabilities.Add, corev1.Capability("NET_RAW")) ||
				slices.Contains(security.Capabilities.Add, corev1.Capability("SYS_ADMIN")) {
				return fmt.Errorf("pod %s/%s container %s can bypass packet enforcement: require drop NET_RAW or ALL, no added NET_RAW or SYS_ADMIN, privileged=false, and allowPrivilegeEscalation=false; recreate existing unsafe Pods after installing the ZTAP admission guard", pod.Namespace, pod.Name, name)
			}
			return nil
		}
		for _, container := range pod.Spec.Containers {
			if err := check(container.Name, container.SecurityContext); err != nil {
				return err
			}
		}
		for _, container := range pod.Spec.InitContainers {
			if err := check(container.Name, container.SecurityContext); err != nil {
				return err
			}
		}
		for _, container := range pod.Spec.EphemeralContainers {
			if err := check(container.Name, container.SecurityContext); err != nil {
				return err
			}
		}
	}
	return nil
}
