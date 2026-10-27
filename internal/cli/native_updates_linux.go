//go:build linux

package cli

import (
	"maps"
	"reflect"
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Compare only facts read by resolution, compilation, identity validation and
// packet-socket isolation. Unknown event types conservatively trigger a retry.
// Resource versions, managed fields, readiness and images do not affect these
// facts. Running transitions and CRI identities do, including init/ephemeral
// containers. No projection or full object copy is allocated on this path.
func nativeObjectChanged(old, current any) bool {
	switch next := current.(type) {
	case *corev1.Pod:
		previous, ok := old.(*corev1.Pod)
		if !ok || previous == nil || next == nil {
			return true
		}
		return previous.UID != next.UID || previous.Name != next.Name || previous.Namespace != next.Namespace ||
			!maps.Equal(previous.Labels, next.Labels) || previous.Spec.NodeName != next.Spec.NodeName ||
			previous.Spec.HostNetwork != next.Spec.HostNetwork || previous.Status.Phase != next.Status.Phase ||
			previous.Status.QOSClass != next.Status.QOSClass || previous.Status.PodIP != next.Status.PodIP ||
			!slices.Equal(previous.Status.PodIPs, next.Status.PodIPs) ||
			!nativeContainerStatusesEqual(previous.Status.ContainerStatuses, next.Status.ContainerStatuses) ||
			!nativeContainerStatusesEqual(previous.Status.InitContainerStatuses, next.Status.InitContainerStatuses) ||
			!nativeContainerStatusesEqual(previous.Status.EphemeralContainerStatuses, next.Status.EphemeralContainerStatuses) ||
			!nativeContainersEqual(previous.Spec.Containers, next.Spec.Containers) ||
			!nativeContainersEqual(previous.Spec.InitContainers, next.Spec.InitContainers) ||
			!slices.EqualFunc(previous.Spec.EphemeralContainers, next.Spec.EphemeralContainers, func(a, b corev1.EphemeralContainer) bool {
				return a.Name == b.Name && nativeSecurityContextsEqual(a.SecurityContext, b.SecurityContext)
			})
	case *corev1.Namespace:
		previous, ok := old.(*corev1.Namespace)
		return !ok || previous == nil || next == nil || previous.UID != next.UID || previous.Name != next.Name || !maps.Equal(previous.Labels, next.Labels)
	case *corev1.Node:
		previous, ok := old.(*corev1.Node)
		return !ok || previous == nil || next == nil || previous.UID != next.UID || previous.Name != next.Name || !slices.Equal(previous.Status.Addresses, next.Status.Addresses)
	case *networkingv1.NetworkPolicy:
		previous, ok := old.(*networkingv1.NetworkPolicy)
		return !ok || previous == nil || next == nil || previous.UID != next.UID || previous.Name != next.Name ||
			previous.Namespace != next.Namespace || previous.Generation != next.Generation ||
			!maps.Equal(previous.Labels, next.Labels) || !maps.Equal(previous.Annotations, next.Annotations) || !reflect.DeepEqual(previous.Spec, next.Spec)
	default:
		return true
	}
}

func nativeContainerStatusesEqual(a, b []corev1.ContainerStatus) bool {
	return slices.EqualFunc(a, b, func(a, b corev1.ContainerStatus) bool {
		return a.ContainerID == b.ContainerID && (a.State.Running != nil) == (b.State.Running != nil)
	})
}

func nativeContainersEqual(a, b []corev1.Container) bool {
	return slices.EqualFunc(a, b, func(a, b corev1.Container) bool {
		return a.Name == b.Name && nativeSecurityContextsEqual(a.SecurityContext, b.SecurityContext)
	})
}

func nativeSecurityContextsEqual(a, b *corev1.SecurityContext) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(a.AllowPrivilegeEscalation, b.AllowPrivilegeEscalation) &&
		reflect.DeepEqual(a.Privileged, b.Privileged) && reflect.DeepEqual(a.Capabilities, b.Capabilities)
}
