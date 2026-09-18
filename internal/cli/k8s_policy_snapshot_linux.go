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

	"ztap/internal/policy"
)

// BuildResolutionSnapshot converts one caller-owned Kubernetes object snapshot
// into compiler facts. The caller supplies objects from one informer-cache
// view; this method does not issue independent API reads that could mix
// resource versions. Cgroup paths are retained separately for Engine links.
func (r *k8sSubjectResolver) BuildResolutionSnapshot(nodeName string, node *corev1.Node, namespaces []corev1.Namespace, pods []corev1.Pod) (policy.ResolutionInput, error) {
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
		ns := &namespaces[i]
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
		pod := &pods[i]
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
	r.pruneCgroupCache(cgroupPaths)
	r.pruneRunningObservations(activeContainers)
	r.replaceCgroupPaths(cgroupPaths)
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

type resolvedPodCgroup struct {
	ID   uint64
	Path string
}

func (r *k8sSubjectResolver) rememberCgroupPath(id uint64, path string) {
	if id == 0 || strings.TrimSpace(path) == "" {
		return
	}
	r.mu.Lock()
	if r.cgroupPath == nil {
		r.cgroupPath = make(map[uint64]string)
	}
	r.cgroupPath[id] = filepath.Clean(path)
	r.mu.Unlock()
}

func (r *k8sSubjectResolver) replaceCgroupPaths(paths map[uint64]string) {
	copyPaths := make(map[uint64]string, len(paths))
	for id, path := range paths {
		copyPaths[id] = filepath.Clean(path)
	}
	r.mu.Lock()
	r.cgroupPath = copyPaths
	r.mu.Unlock()
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
