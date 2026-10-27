//go:build linux

package cli

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

func newNativeAgentInformers(client nativeKubernetesClient, nodeName string) []cache.SharedIndexInformer {
	// Pods and Namespaces must remain cluster-wide for peer selector resolution.
	// The standard informer still owns watch recovery, relists and cache sync;
	// each ListWatch delegates its API operations to a typed client-go client.
	policies := client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll)
	pods := client.CoreV1().Pods(metav1.NamespaceAll)
	namespaces := client.CoreV1().Namespaces()
	nodes := client.CoreV1().Nodes()
	newInformer := func(object runtime.Object, list func(context.Context, metav1.ListOptions) (runtime.Object, error), watchFunc func(context.Context, metav1.ListOptions) (watch.Interface, error)) cache.SharedIndexInformer {
		lw := cache.ToListWatcherWithWatchListSemantics(&cache.ListWatch{ListWithContextFunc: list, WatchFuncWithContext: watchFunc}, client)
		return cache.NewSharedIndexInformer(lw, object, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	}
	return []cache.SharedIndexInformer{
		newInformer(&networkingv1.NetworkPolicy{}, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return policies.List(ctx, opts)
		}, policies.Watch),
		newInformer(&corev1.Pod{}, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return pods.List(ctx, opts)
		}, pods.Watch),
		newInformer(&corev1.Namespace{}, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return namespaces.List(ctx, opts)
		}, namespaces.Watch),
		newInformer(&corev1.Node{}, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", nodeName).String()
			return nodes.List(ctx, opts)
		}, func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", nodeName).String()
			return nodes.Watch(ctx, opts)
		}),
	}
}
