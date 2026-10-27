//go:build linux

package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const nodeBootstrapFile = "node-bootstrap.json"

type nodeBootstrap struct {
	Schema          uint32                      `json:"schema"`
	Boot            string                      `json:"boot"`
	Node            string                      `json:"node"`
	NodeUID         string                      `json:"node_uid"`
	HostNetnsCookie uint64                      `json:"host_netns_cookie"`
	Parents         []string                    `json:"parents"`
	APIPeers        []netip.AddrPort            `json:"api_peers"`
	HostNetwork     []enforcer.WorkloadIdentity `json:"host_network"`
}

func nodeBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	boot := strings.TrimSpace(string(data))
	if len(boot) != 36 {
		return "", errors.New("invalid kernel boot identity")
	}
	return boot, nil
}

// The host-network initializer uses authenticated API facts and its own exact
// kernel cgroup membership. A network namespace name or namespace label never
// grants a workload the bootstrap exception.
func initializeNodeBootstrap(ctx context.Context, client nativeCoreClient, config *rest.Config, nodeName, cgroupRoot, runDir string) error {
	if config == nil || config.Insecure {
		return errors.New("node initialization requires verified Kubernetes TLS")
	}
	apiURL, err := url.Parse(config.Host)
	if err != nil || apiURL.Scheme != "https" || apiURL.Hostname() == "" {
		return errors.New("node initialization requires an authenticated HTTPS API endpoint")
	}
	lock, _, err := openZTAPLock(runDir, "bootstrap.lock", "node bootstrap")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + nodeName})
	if err != nil {
		return err
	}
	selfUID := os.Getenv("POD_UID")
	var self *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if string(pod.UID) == selfUID && pod.Spec.NodeName == nodeName && pod.Spec.HostNetwork {
			self = pod
			break
		}
	}
	if self == nil {
		return errors.New("node initializer must be a verified host-network Pod on this node")
	}
	if _, err := findBootstrapProcessIdentity(cgroupRoot, selfUID); err != nil {
		return fmt.Errorf("verify initializer runtime identity: %w", err)
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	cookie, cookieErr := unix.GetsockoptUint64(socket, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	closeErr := unix.Close(socket)
	if err := errors.Join(cookieErr, closeErr); err != nil {
		return err
	}
	if cookie == 0 {
		return errors.New("node socket has no network namespace cookie")
	}
	boot, err := nodeBootID()
	if err != nil {
		return err
	}
	record := nodeBootstrap{Schema: 1, Boot: boot, Node: nodeName, NodeUID: string(node.UID), HostNetnsCookie: cookie}
	for _, relative := range []string{"kubepods.slice", "kubelet.slice/kubelet-kubepods.slice"} {
		fd, err := openExistingDirectory(filepath.Join(cgroupRoot, relative), "Kubernetes parent")
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		_ = unix.Close(fd)
		record.Parents = append(record.Parents, relative)
	}
	if len(record.Parents) == 0 {
		return errors.New("no supported Kubernetes systemd cgroup parent exists")
	}
	port := uint16(443)
	if apiURL.Port() != "" {
		value, err := strconv.ParseUint(apiURL.Port(), 10, 16)
		if err != nil || value == 0 {
			return errors.New("invalid API TCP port")
		}
		port = uint16(value)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", apiURL.Hostname())
	if err != nil {
		return err
	}
	for _, address := range addresses {
		record.APIPeers = append(record.APIPeers, netip.AddrPortFrom(address.Unmap(), port))
	}
	// Both the Service frontend and authenticated backend facts are needed:
	// cgroup hooks may observe the packet after Service DNAT.
	endpoints, err := client.CoreV1().Endpoints("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			ip, err := netip.ParseAddr(address.IP)
			if err != nil || !ip.Is4() {
				continue
			}
			for _, endpointPort := range subset.Ports {
				if endpointPort.Protocol != corev1.ProtocolTCP || endpointPort.Port <= 0 || endpointPort.Port > 65535 {
					continue
				}
				record.APIPeers = append(record.APIPeers, netip.AddrPortFrom(ip, uint16(endpointPort.Port)))
			}
		}
	}
	slices.SortFunc(record.APIPeers, func(a, b netip.AddrPort) int { return a.Compare(b) })
	record.APIPeers = slices.Compact(record.APIPeers)
	if len(record.APIPeers) == 0 || len(record.APIPeers) > 32 {
		return errors.New("invalid bootstrap API endpoint inventory")
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName != nodeName || !pod.Spec.HostNetwork || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		owners, err := scanBootstrapHostNetworkIdentities(cgroupRoot, pod)
		if err != nil {
			return err
		}
		record.HostNetwork = append(record.HostNetwork, owners...)
	}
	if len(record.HostNetwork) > 16384 {
		return errors.New("host-network bootstrap identity capacity exceeded")
	}
	return writeNodeBootstrap(runDir, record)
}

func bootstrapPodDirectories(root, uid string) ([]string, error) {
	compact := strings.ReplaceAll(uid, "-", "")
	if (len(uid) != 36 && len(uid) != 32) || len(compact) != 32 {
		return nil, errors.New("bootstrap requires a full canonical Pod UID")
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return nil, errors.New("invalid bootstrap Pod UID")
	}
	token := "pod" + strings.ReplaceAll(uid, "-", "_")
	var directories []string
	for _, layout := range []struct{ parent, prefix string }{{"kubepods.slice", "kubepods"}, {"kubelet.slice/kubelet-kubepods.slice", "kubelet-kubepods"}} {
		directories = append(directories, filepath.Join(root, layout.parent, layout.prefix+"-"+token+".slice"))
		for _, qos := range []string{"burstable", "besteffort"} {
			directories = append(directories, filepath.Join(root, layout.parent, layout.prefix+"-"+qos+".slice", layout.prefix+"-"+qos+"-"+token+".slice"))
		}
	}
	return directories, nil
}

func scanBootstrapPodIdentities(root, uid string) ([]enforcer.WorkloadIdentity, error) {
	if len(uid) != 36 {
		return nil, errors.New("bootstrap requires a full canonical API Pod UID")
	}
	return scanBootstrapScopes(root, uid)
}

func scanBootstrapScopes(root, uid string) ([]enforcer.WorkloadIdentity, error) {
	directories, err := bootstrapPodDirectories(root, uid)
	if err != nil {
		return nil, err
	}
	var owners []enforcer.WorkloadIdentity
	for _, directory := range directories {
		fd, err := openExistingDirectory(directory, "bootstrap Pod cgroup")
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), directory)
		entries, readErr := file.ReadDir(-1)
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			id, valid := strings.CutPrefix(entry.Name(), "cri-containerd-")
			if !valid {
				continue
			}
			id, valid = strings.CutSuffix(id, ".scope")
			if !valid || len(id) != 64 {
				continue
			}
			if _, err := hex.DecodeString(id); err != nil {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			fd, err := openExistingDirectory(path, "bootstrap container cgroup")
			if err != nil {
				return nil, err
			}
			var st unix.Stat_t
			var fs unix.Statfs_t
			err = errors.Join(unix.Fstat(fd, &st), unix.Fstatfs(fd, &fs))
			closeErr := unix.Close(fd)
			if err := errors.Join(err, closeErr); err != nil {
				return nil, err
			}
			if fs.Type != unix.CGROUP2_SUPER_MAGIC {
				return nil, errors.New("bootstrap identity is not on cgroup v2")
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			owners = append(owners, enforcer.WorkloadIdentity{CgroupID: st.Ino, Device: uint64(st.Dev), Path: relative, PodUID: uid, ContainerID: id})
		}
	}
	return owners, nil
}

// Static Pods have a runtime config hash and a different API mirror Pod UID.
// Bind the authenticated mirror annotations AND each full status container ID
// before using that runtime path; an annotation alone cannot grant a bypass.
func scanBootstrapHostNetworkIdentities(root string, pod *corev1.Pod) ([]enforcer.WorkloadIdentity, error) {
	mirror := pod.Annotations["kubernetes.io/config.mirror"]
	if mirror == "" {
		return scanBootstrapPodIdentities(root, string(pod.UID))
	}
	if pod.Annotations["kubernetes.io/config.source"] != "file" || pod.Annotations["kubernetes.io/config.hash"] != mirror || len(mirror) != 32 {
		return nil, errors.New("inconsistent authenticated static Pod identity")
	}
	owners, err := scanBootstrapScopes(root, mirror)
	if err != nil {
		return nil, err
	}
	statusIDs := make(map[string]bool)
	for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		if status.ContainerID == "" {
			continue
		}
		id, err := parseContainerdContainerID(status.ContainerID)
		if err != nil {
			return nil, err
		}
		if status.State.Running != nil {
			statusIDs[id] = true
		}
	}
	var verified []enforcer.WorkloadIdentity
	for _, owner := range owners {
		if statusIDs[owner.ContainerID] {
			owner.PodUID = string(pod.UID)
			verified = append(verified, owner)
			delete(statusIDs, owner.ContainerID)
		}
	}
	if len(statusIDs) != 0 || ((len(owners) != 0 || pod.Status.Phase == corev1.PodRunning) && len(verified) == 0) {
		return nil, errors.New("live static host-network Pod lacks a complete runtime identity")
	}
	return verified, nil
}

func findBootstrapProcessIdentity(root, uid string) (enforcer.WorkloadIdentity, error) {
	owners, err := scanBootstrapPodIdentities(root, uid)
	if err != nil {
		return enforcer.WorkloadIdentity{}, err
	}
	var matching []enforcer.WorkloadIdentity
	for _, owner := range owners {
		fd, err := openExistingDirectory(filepath.Join(root, owner.Path), "bootstrap process cgroup")
		if err != nil {
			return enforcer.WorkloadIdentity{}, err
		}
		procsFD, openErr := unix.Openat(fd, "cgroup.procs", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return enforcer.WorkloadIdentity{}, openErr
		}
		file := os.NewFile(uintptr(procsFD), "bootstrap cgroup.procs")
		data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024))
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return enforcer.WorkloadIdentity{}, err
		}
		for _, pid := range strings.Fields(string(data)) {
			if pid == strconv.Itoa(os.Getpid()) {
				matching = append(matching, owner)
				break
			}
		}
	}
	if len(matching) != 1 {
		return enforcer.WorkloadIdentity{}, errors.New("current process does not have one exact Pod UID/containerd cgroup identity")
	}
	return matching[0], nil
}

func writeNodeBootstrap(runDir string, record nodeBootstrap) error {
	fd, err := openLockDirectory(runDir, "node bootstrap")
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	name := fmt.Sprintf(".node-bootstrap-%d-%d.tmp", os.Getpid(), time.Now().UnixNano())
	fileFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(fd, name, 0) }()
	file := os.NewFile(uintptr(fileFD), name)
	err = json.NewEncoder(file).Encode(record)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := unix.Renameat(fd, name, fd, nodeBootstrapFile); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func loadNodeGuardBootstrap(runDir, root, node, podUID string) (*enforcer.WorkloadGuardOptions, error) {
	directory, err := openLockDirectory(runDir, "node bootstrap")
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(directory) }()
	fd, err := unix.Openat(directory, nodeBootstrapFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), nodeBootstrapFile)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Uid) != uint64(os.Geteuid()) || st.Mode&0o077 != 0 || st.Nlink != 1 || st.Size > 1024*1024 {
		return nil, errors.New("unsafe node bootstrap record")
	}
	var record nodeBootstrap
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("node bootstrap has trailing data")
	}
	boot, err := nodeBootID()
	if err != nil {
		return nil, err
	}
	if record.Schema != 1 || record.Boot != boot || record.Node != node || record.NodeUID == "" || record.HostNetnsCookie == 0 {
		return nil, errors.New("node bootstrap belongs to another node, boot, or schema")
	}
	identity, err := findBootstrapProcessIdentity(root, podUID)
	if err != nil {
		return nil, err
	}
	return &enforcer.WorkloadGuardOptions{Parents: record.Parents, HostNetnsCookie: record.HostNetnsCookie, HostNetwork: record.HostNetwork, BootstrapIdentity: identity, APIPeers: record.APIPeers}, nil
}
