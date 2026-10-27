//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/policy"
)

// BuildResolutionSnapshot converts one caller-owned Kubernetes object snapshot
// into compiler facts. The caller supplies objects from one informer-cache
// view; this method does not issue independent API reads that could mix
// resource versions. Cgroup paths are retained separately for Engine links.
func (r *k8sSubjectResolver) BuildResolutionSnapshot(nodeName string, node *corev1.Node, namespaces []corev1.Namespace, pods []corev1.Pod) (policy.ResolutionInput, error) {
	namespaceRefs := make([]*corev1.Namespace, len(namespaces))
	for i := range namespaces {
		namespaceRefs[i] = &namespaces[i]
	}
	podRefs := make([]*corev1.Pod, len(pods))
	for i := range pods {
		podRefs[i] = &pods[i]
	}
	return r.buildResolutionSnapshot(nodeName, node, namespaceRefs, podRefs)
}

// Informer objects are immutable. Read this cache view directly and copy only
// compiler facts into ResolutionInput; never clone full Kubernetes objects.
func (r *k8sSubjectResolver) buildResolutionSnapshot(nodeName string, node *corev1.Node, namespaces []*corev1.Namespace, pods []*corev1.Pod) (policy.ResolutionInput, error) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return policy.ResolutionInput{}, errors.New("node name is required to resolve the local policy snapshot")
	}
	if node == nil {
		return policy.ResolutionInput{}, fmt.Errorf("local node %q is missing from the policy snapshot", nodeName)
	}
	if node.Name != nodeName {
		return policy.ResolutionInput{}, fmt.Errorf("local node snapshot is %q, want %q", node.Name, nodeName)
	}

	input := policy.ResolutionInput{
		NodeIPs:    nodeStatusIPs(node),
		Namespaces: make([]policy.ResolvedNamespace, 0, len(namespaces)),
		Pods:       make([]policy.ResolvedPod, 0, len(pods)),
	}
	for i := range namespaces {
		ns := namespaces[i]
		input.Namespaces = append(input.Namespaces, policy.ResolvedNamespace{
			Name:   ns.Name,
			Labels: copyStringMap(ns.Labels),
		})
	}
	sort.Slice(input.Namespaces, func(i, j int) bool {
		return input.Namespaces[i].Name < input.Namespaces[j].Name
	})

	cgroupPaths := make(map[uint64]string)
	activeContainers := make(map[cgroupCacheKey]struct{})
	unresolvedRunning := 0
	observedAt := time.Now()
	for i := range pods {
		pod := pods[i]
		// Terminal Pods retain their labels and IPs in the API even after the
		// runtime releases those addresses. They must never authorize a new
		// workload that subsequently receives the same IP.
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		local := pod.Spec.NodeName == nodeName
		resolved := policy.ResolvedPod{
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Labels:      copyStringMap(pod.Labels),
			PodIPs:      podStatusIPs(pod),
			Local:       local,
			HostNetwork: pod.Spec.HostNetwork,
		}
		if local && !pod.Spec.HostNetwork {
			containerIDs, _ := extractRunningContainerdIDs(pod)
			qos := pod.Status.QOSClass
			if qos == "" {
				qos = corev1.PodQOSBurstable
			}
			for _, containerID := range containerIDs {
				key := cgroupCacheKey{containerID: containerID, podUID: string(pod.UID), qos: qos}
				activeContainers[key] = struct{}{}
				r.observeRunningContainer(key, observedAt)
			}
			podCgroups, failure := r.resolvePodCgroupsCached(pod)
			resolved.CgroupResolutionFailure = failure
			if running := runningContainerWithIDCount(pod); running > len(podCgroups) {
				unresolvedRunning += running - len(podCgroups)
			}
			seen := make(map[uint64]struct{})
			for _, cgroup := range podCgroups {
				if _, ok := seen[cgroup.ID]; ok {
					continue
				}
				seen[cgroup.ID] = struct{}{}
				resolved.CgroupIDs = append(resolved.CgroupIDs, cgroup.ID)
				path := filepath.Clean(cgroup.Path)
				if previous, ok := cgroupPaths[cgroup.ID]; ok && previous != path {
					return policy.ResolutionInput{}, fmt.Errorf("cgroup ID %d resolved to conflicting paths %q and %q", cgroup.ID, previous, path)
				}
				cgroupPaths[cgroup.ID] = path
			}
			sort.Slice(resolved.CgroupIDs, func(i, j int) bool {
				return resolved.CgroupIDs[i] < resolved.CgroupIDs[j]
			})
		}
		input.Pods = append(input.Pods, resolved)
	}
	sort.Slice(input.Pods, func(i, j int) bool {
		if input.Pods[i].Namespace != input.Pods[j].Namespace {
			return input.Pods[i].Namespace < input.Pods[j].Namespace
		}
		return input.Pods[i].Name < input.Pods[j].Name
	})

	// Drop cache entries for containers no longer present in this immutable
	// snapshot. Entries that remain are still identity-checked on every use.
	if err := r.publishWorkloadSnapshot(cgroupPaths, activeContainers); err != nil {
		return policy.ResolutionInput{}, err
	}
	r.pruneRunningObservations(activeContainers)
	r.setUnresolvedRunning(unresolvedRunning)
	return input, nil
}

// classificationObservations returns the first time each resolved cgroup was
// observed as a running container. The native agent uses these timestamps to
// report the watcher gap separately from reconciliation duration.
func (r *k8sSubjectResolver) classificationObservations() (map[uint64]time.Time, int) {
	r.mu.RLock()
	observed := make(map[uint64]time.Time, len(r.cgroupCache))
	for key, cached := range r.cgroupCache {
		timestamp, ok := r.runningObservedAt[key]
		if !ok || timestamp.IsZero() {
			continue
		}
		if previous, exists := observed[cached.value.ID]; !exists || timestamp.Before(previous) {
			observed[cached.value.ID] = timestamp
		}
	}
	unresolved := r.unresolvedRunningContainers
	r.mu.RUnlock()
	return observed, unresolved
}

// ResolveCgroupPath implements enforcer.CgroupPathResolver for cgroups seen
// during the latest full snapshot or subject resolution.
func (r *k8sSubjectResolver) ResolveCgroupPath(ctx context.Context, cgroupID uint64) (string, error) {
	if ctx == nil {
		return "", errors.New("cgroup path context is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.RLock()
	path, ok := r.cgroupPath[cgroupID]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("cgroup path for ID %d has not been resolved", cgroupID)
	}
	return path, nil
}

// ResolveWorkloadIdentity uses only the latest fully resolved snapshot. A
// pending/missing container status cannot satisfy a committed identity merely
// because the informer itself reports synchronized.
func (r *k8sSubjectResolver) ResolveWorkloadIdentity(ctx context.Context, id uint64) (enforcer.WorkloadIdentity, error) {
	if ctx == nil {
		return enforcer.WorkloadIdentity{}, errors.New("workload identity context is nil")
	}
	if err := ctx.Err(); err != nil {
		return enforcer.WorkloadIdentity{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if identity, ok := r.workloadIdentities[id]; ok {
		return identity, nil
	}
	return enforcer.WorkloadIdentity{}, fmt.Errorf("no complete running identity for cgroup %d in candidate snapshot", id)
}

func (r *k8sSubjectResolver) ValidateWorkloadIdentity(ctx context.Context, committed enforcer.WorkloadIdentity) error {
	current, err := r.ResolveWorkloadIdentity(ctx, committed.CgroupID)
	if err != nil {
		return err
	}
	if current != committed {
		return errors.New("candidate workload identity differs from committed ownership")
	}
	return nil
}

type resolvedPodCgroup struct {
	ID   uint64
	Path string
}

// Publish paths and complete identities together, only after conflict checks.
// Cache entries absent from the candidate cannot authorize recovered ownership.
func (r *k8sSubjectResolver) publishWorkloadSnapshot(paths map[uint64]string, active map[cgroupCacheKey]struct{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	identities := make(map[uint64]enforcer.WorkloadIdentity, len(paths))
	for key := range active {
		cached, ok := r.cgroupCache[key]
		if !ok || paths[cached.value.ID] != cached.value.Path {
			continue
		}
		relative, err := filepath.Rel(r.cgroupRoot, cached.value.Path)
		if err != nil {
			return err
		}
		identity := enforcer.WorkloadIdentity{CgroupID: cached.value.ID, Device: cached.identity.device,
			PodUID: key.podUID, ContainerID: key.containerID, Path: relative}
		if previous, exists := identities[identity.CgroupID]; exists && previous != identity {
			return fmt.Errorf("cgroup ID %d resolved to conflicting workload identities", identity.CgroupID)
		}
		identities[identity.CgroupID] = identity
	}
	for key, cached := range r.cgroupCache {
		if _, ok := active[key]; !ok || paths[cached.value.ID] != cached.value.Path {
			delete(r.cgroupCache, key)
		}
	}
	r.cgroupPath = paths
	r.workloadIdentities = identities
	return nil
}

func nodeStatusIPs(node *corev1.Node) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	addresses := make([]netip.Addr, 0, len(node.Status.Addresses))
	for _, entry := range node.Status.Addresses {
		if entry.Type != corev1.NodeInternalIP && entry.Type != corev1.NodeExternalIP {
			continue
		}
		address, err := netip.ParseAddr(strings.TrimSpace(entry.Address))
		if err != nil || address.Zone() != "" {
			continue
		}
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return addresses
}

func podStatusIPs(pod *corev1.Pod) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	addresses := make([]netip.Addr, 0, len(pod.Status.PodIPs)+1)
	appendAddress := func(raw string) {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || address.Zone() != "" {
			return
		}
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			return
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	for _, podIP := range pod.Status.PodIPs {
		appendAddress(podIP.IP)
	}
	appendAddress(pod.Status.PodIP)
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return addresses
}

func copyStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
