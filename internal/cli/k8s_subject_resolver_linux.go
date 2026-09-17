//go:build linux

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"ztap/internal/enforcer"
	"ztap/internal/policy"
)

type k8sSubjectResolver struct {
	client                      kubernetes.Interface
	cgroupRoot                  string
	mu                          sync.RWMutex
	cgroupPath                  map[uint64]string
	cgroupCache                 map[cgroupCacheKey]cachedPodCgroup
	runningObservedAt           map[cgroupCacheKey]time.Time
	unresolvedRunningContainers int
}

// cgroupCacheKey ties a container identity to the pod layout used to resolve
// its systemd scope. Including the Pod UID and QoS class prevents a stale
// entry from being reused after a pod is recreated or its cgroup layout
// changes.
type cgroupCacheKey struct {
	containerID string
	podUID      string
	qos         corev1.PodQOSClass
}

type cgroupFilesystemIdentity struct {
	device uint64
	inode  uint64
}

type cachedPodCgroup struct {
	value    resolvedPodCgroup
	identity cgroupFilesystemIdentity
}

func newK8sSubjectResolver(client kubernetes.Interface, cgroupRoot string) enforcer.SubjectResolver {
	cgroupRoot = strings.TrimSpace(cgroupRoot)
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	return &k8sSubjectResolver{
		client:            client,
		cgroupRoot:        cgroupRoot,
		cgroupPath:        make(map[uint64]string),
		cgroupCache:       make(map[cgroupCacheKey]cachedPodCgroup),
		runningObservedAt: make(map[cgroupCacheKey]time.Time),
	}
}

func (r *k8sSubjectResolver) ResolveCgroupIDs(ctx context.Context, tenant string, podSelector policy.PodSelectorSpec) ([]uint64, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		tenant = "default"
	}

	selector, err := selectorFromPolicy(podSelector)
	if err != nil {
		return nil, err
	}
	sel := selector.String()
	pods, err := r.client.CoreV1().Pods(tenant).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return []uint64{}, nil
	}

	ids := make([]uint64, 0, len(pods.Items))
	seen := make(map[uint64]struct{}, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		podCgroups, failure := r.resolvePodCgroupsCached(pod)
		if failure != policy.CgroupResolutionFailureNone {
			return nil, podCgroupResolutionError(pod, failure)
		}
		for _, cgroup := range podCgroups {
			if _, ok := seen[cgroup.ID]; ok {
				continue
			}
			seen[cgroup.ID] = struct{}{}
			ids = append(ids, cgroup.ID)
			r.rememberCgroupPath(cgroup.ID, cgroup.Path)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("matched %d pods but resolved 0 cgroup IDs (namespace=%s selector=%s)", len(pods.Items), tenant, sel)
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (r *k8sSubjectResolver) ResolveSubjectPorts(ctx context.Context, tenant string, podSelector policy.PodSelectorSpec) ([]enforcer.SubjectPortInfo, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		tenant = "default"
	}

	selector, err := selectorFromPolicy(podSelector)
	if err != nil {
		return nil, err
	}
	sel := selector.String()
	pods, err := r.client.CoreV1().Pods(tenant).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return []enforcer.SubjectPortInfo{}, nil
	}

	infos := make([]enforcer.SubjectPortInfo, 0)
	seen := make(map[uint64]struct{})
	for i := range pods.Items {
		pod := &pods.Items[i]
		ports := podPortsFromSpec(pod)
		podCgroups, failure := r.resolvePodCgroupsCached(pod)
		if failure != policy.CgroupResolutionFailureNone {
			return nil, podCgroupResolutionError(pod, failure)
		}
		for _, cgroup := range podCgroups {
			if _, ok := seen[cgroup.ID]; ok {
				continue
			}
			seen[cgroup.ID] = struct{}{}
			infos = append(infos, enforcer.SubjectPortInfo{CgroupID: cgroup.ID, Ports: ports, PodName: pod.Name})
			r.rememberCgroupPath(cgroup.ID, cgroup.Path)
		}
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("matched %d pods but resolved 0 cgroup IDs (namespace=%s selector=%s)", len(pods.Items), tenant, sel)
	}
	return infos, nil
}

func podPortsFromSpec(pod *corev1.Pod) []policy.PodPort {
	ports := make([]policy.PodPort, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			name := strings.TrimSpace(port.Name)
			if name == "" {
				continue
			}
			proto := strings.ToUpper(string(port.Protocol))
			if proto == "" {
				proto = "TCP"
			}
			ports = append(ports, policy.PodPort{
				Name:     name,
				Protocol: proto,
				Port:     int(port.ContainerPort),
			})
		}
	}
	return ports
}

func selectorFromPolicy(selector policy.PodSelectorSpec) (labels.Selector, error) {
	if len(selector.MatchExpressions) == 0 {
		return labels.Set(selector.MatchLabels).AsSelector(), nil
	}
	reqs := make([]metav1.LabelSelectorRequirement, 0, len(selector.MatchExpressions))
	for _, expr := range selector.MatchExpressions {
		reqs = append(reqs, metav1.LabelSelectorRequirement{
			Key:      expr.Key,
			Operator: metav1.LabelSelectorOperator(expr.Operator),
			Values:   expr.Values,
		})
	}
	labelSelector := &metav1.LabelSelector{MatchLabels: selector.MatchLabels, MatchExpressions: reqs}
	return metav1.LabelSelectorAsSelector(labelSelector)
}

func extractRunningContainerdIDs(pod *corev1.Pod) ([]string, policy.CgroupResolutionFailure) {
	ids := make([]string, 0)
	if pod == nil {
		return ids, policy.CgroupResolutionFailureNotFound
	}
	seen := make(map[string]struct{})
	failure := policy.CgroupResolutionFailureNone
	add := func(status corev1.ContainerStatus) {
		if status.State.Running == nil {
			return
		}
		if status.ContainerID == "" {
			failure = policy.CgroupResolutionFailureNotFound
			return
		}
		containerID, err := parseContainerdContainerID(status.ContainerID)
		if err != nil {
			failure = policy.CgroupResolutionFailureUnsupportedRuntime
			return
		}
		if _, ok := seen[containerID]; ok {
			return
		}
		seen[containerID] = struct{}{}
		ids = append(ids, containerID)
	}

	for _, status := range pod.Status.InitContainerStatuses {
		add(status)
	}
	for _, status := range pod.Status.ContainerStatuses {
		add(status)
	}
	for _, status := range pod.Status.EphemeralContainerStatuses {
		add(status)
	}
	sort.Strings(ids)
	return ids, failure
}

func parseContainerdContainerID(raw string) (string, error) {
	runtimeName, containerID, ok := strings.Cut(raw, "://")
	if !ok || runtimeName != "containerd" || len(containerID) != 64 {
		return "", errors.New("container identity must use containerd with a full 64-hex ID")
	}
	if _, err := hex.DecodeString(containerID); err != nil {
		return "", errors.New("container identity must use containerd with a full 64-hex ID")
	}
	return strings.ToLower(containerID), nil
}

func podCgroupResolutionError(pod *corev1.Pod, failure policy.CgroupResolutionFailure) error {
	podName := "<unknown>"
	if pod != nil {
		podName = pod.Name
		if pod.Namespace != "" {
			podName = pod.Namespace + "/" + pod.Name
		}
	}
	switch failure {
	case policy.CgroupResolutionFailureNotFound:
		return fmt.Errorf("resolve cgroups for pod %s: a running container cgroup was not found", podName)
	case policy.CgroupResolutionFailureUnsupportedRuntime:
		return fmt.Errorf("resolve cgroups for pod %s: a running container has an unsupported runtime identity", podName)
	default:
		return fmt.Errorf("resolve cgroups for pod %s: unknown resolution failure", podName)
	}
}

func cgroupIDFromPath(path string) (uint64, error) {
	identity, err := cgroupFilesystemIdentityForPath(path)
	if err != nil {
		return 0, err
	}
	return identity.inode, nil
}

func cgroupFilesystemIdentityForPath(path string) (cgroupFilesystemIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return cgroupFilesystemIdentity{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return cgroupFilesystemIdentity{}, fmt.Errorf("unexpected stat type for %s", path)
	}
	return cgroupFilesystemIdentity{device: uint64(st.Dev), inode: uint64(st.Ino)}, nil
}

func findContainerCgroupPath(cgroupRoot string, pod *corev1.Pod, containerID string) (string, error) {
	if pod == nil {
		return "", errors.New("pod is required to resolve a container cgroup")
	}
	if strings.TrimSpace(string(pod.UID)) == "" {
		return "", errors.New("pod UID is required to resolve a container cgroup")
	}
	if len(containerID) != 64 {
		return "", errors.New("containerd ID must contain exactly 64 hex characters")
	}
	if _, err := hex.DecodeString(containerID); err != nil {
		return "", errors.New("containerd ID must contain exactly 64 hex characters")
	}
	containerID = strings.ToLower(containerID)
	uidToken := strings.ReplaceAll(string(pod.UID), "-", "_")
	qos := pod.Status.QOSClass
	if qos == "" {
		qos = corev1.PodQOSBurstable
	}

	podToken := "pod" + uidToken
	// These are the two supported systemd layouts observed for containerd on
	// Linux. Keep the candidates explicit: do not recursively search the host
	// cgroup tree or guess from shortened container IDs.
	layouts := []struct {
		prefix    []string
		qosPrefix string
	}{
		{prefix: []string{"kubepods.slice"}, qosPrefix: "kubepods"},
		{prefix: []string{"kubelet.slice", "kubelet-kubepods.slice"}, qosPrefix: "kubelet-kubepods"},
	}
	var lastErr error
	for _, layout := range layouts {
		var podSlice []string
		switch qos {
		case corev1.PodQOSBestEffort:
			podSlice = append(append([]string{}, layout.prefix...), layout.qosPrefix+"-besteffort.slice", layout.qosPrefix+"-besteffort-"+podToken+".slice")
		case corev1.PodQOSGuaranteed:
			podSlice = append(append([]string{}, layout.prefix...), layout.qosPrefix+"-"+podToken+".slice")
		default:
			podSlice = append(append([]string{}, layout.prefix...), layout.qosPrefix+"-burstable.slice", layout.qosPrefix+"-burstable-"+podToken+".slice")
		}
		pathSegments := append([]string{cgroupRoot}, podSlice...)
		path := filepath.Join(append(pathSegments, "cri-containerd-"+containerID+".scope")...)
		path, err := resolveCgroupPathUnderRoot(cgroupRoot, path)
		if err != nil {
			lastErr = err
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			lastErr = err
			continue
		}
		if !info.IsDir() {
			lastErr = errors.New("containerd systemd cgroup is not a directory")
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("locate exact containerd systemd cgroup: %w", lastErr)
}

func resolveCgroupPathUnderRoot(root, target string) (string, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(target) {
		return "", errors.New("cgroup root and target must be absolute")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve cgroup root: %w", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) ||
		(len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("resolved cgroup path %q is outside root %q", resolvedTarget, resolvedRoot)
	}
	return filepath.Clean(resolvedTarget), nil
}

func (r *k8sSubjectResolver) resolvePodCgroupsCached(pod *corev1.Pod) ([]resolvedPodCgroup, policy.CgroupResolutionFailure) {
	if pod == nil {
		return nil, policy.CgroupResolutionFailureNotFound
	}
	containerIDs, failure := extractRunningContainerdIDs(pod)
	cgroups := make([]resolvedPodCgroup, 0, len(containerIDs))
	seen := make(map[uint64]struct{})
	qos := pod.Status.QOSClass
	if qos == "" {
		qos = corev1.PodQOSBurstable
	}
	for _, containerID := range containerIDs {
		key := cgroupCacheKey{containerID: containerID, podUID: string(pod.UID), qos: qos}
		if cached, ok := r.cachedCgroup(key); ok {
			identity, err := cgroupFilesystemIdentityForPath(cached.value.Path)
			if err == nil && identity == cached.identity {
				if _, duplicate := seen[cached.value.ID]; !duplicate {
					seen[cached.value.ID] = struct{}{}
					cgroups = append(cgroups, cached.value)
				}
				continue
			}
			r.deleteCachedCgroup(key)
		}

		path, err := findContainerCgroupPath(r.cgroupRoot, pod, containerID)
		if err != nil {
			if failure == policy.CgroupResolutionFailureNone {
				failure = policy.CgroupResolutionFailureNotFound
			}
			continue
		}
		identity, err := cgroupFilesystemIdentityForPath(path)
		if err != nil {
			if failure == policy.CgroupResolutionFailureNone {
				failure = policy.CgroupResolutionFailureNotFound
			}
			continue
		}
		value := resolvedPodCgroup{ID: identity.inode, Path: filepath.Clean(path)}
		r.cacheCgroup(key, cachedPodCgroup{value: value, identity: identity})
		if _, duplicate := seen[value.ID]; duplicate {
			continue
		}
		seen[value.ID] = struct{}{}
		cgroups = append(cgroups, value)
	}
	sort.Slice(cgroups, func(i, j int) bool { return cgroups[i].ID < cgroups[j].ID })
	return cgroups, failure
}

func runningContainerCount(pod *corev1.Pod) int {
	if pod == nil {
		return 0
	}
	count := 0
	countRunning := func(statuses []corev1.ContainerStatus) {
		for _, status := range statuses {
			if status.State.Running != nil {
				count++
			}
		}
	}
	countRunning(pod.Status.InitContainerStatuses)
	countRunning(pod.Status.ContainerStatuses)
	countRunning(pod.Status.EphemeralContainerStatuses)
	return count
}

func (r *k8sSubjectResolver) observeRunningContainer(key cgroupCacheKey, observedAt time.Time) {
	if key.containerID == "" || observedAt.IsZero() {
		return
	}
	r.mu.Lock()
	if r.runningObservedAt == nil {
		r.runningObservedAt = make(map[cgroupCacheKey]time.Time)
	}
	if _, exists := r.runningObservedAt[key]; !exists {
		r.runningObservedAt[key] = observedAt
	}
	r.mu.Unlock()
}

func (r *k8sSubjectResolver) pruneRunningObservations(active map[cgroupCacheKey]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.runningObservedAt {
		if _, exists := active[key]; !exists {
			delete(r.runningObservedAt, key)
		}
	}
}

func (r *k8sSubjectResolver) setUnresolvedRunning(count int) {
	if count < 0 {
		count = 0
	}
	r.mu.Lock()
	r.unresolvedRunningContainers = count
	r.mu.Unlock()
}

func (r *k8sSubjectResolver) cachedCgroup(key cgroupCacheKey) (cachedPodCgroup, bool) {
	r.mu.RLock()
	value, ok := r.cgroupCache[key]
	r.mu.RUnlock()
	return value, ok
}

func (r *k8sSubjectResolver) cacheCgroup(key cgroupCacheKey, value cachedPodCgroup) {
	r.mu.Lock()
	if r.cgroupCache == nil {
		r.cgroupCache = make(map[cgroupCacheKey]cachedPodCgroup)
	}
	r.cgroupCache[key] = value
	r.mu.Unlock()
}

func (r *k8sSubjectResolver) deleteCachedCgroup(key cgroupCacheKey) {
	r.mu.Lock()
	delete(r.cgroupCache, key)
	r.mu.Unlock()
}

func (r *k8sSubjectResolver) pruneCgroupCache(paths map[uint64]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, cached := range r.cgroupCache {
		path, ok := paths[cached.value.ID]
		if !ok || filepath.Clean(path) != cached.value.Path {
			delete(r.cgroupCache, key)
		}
	}
}
