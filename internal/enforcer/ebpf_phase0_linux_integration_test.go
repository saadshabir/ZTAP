//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestEBPFIntegrationPhase0KernelPreflight(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges; re-run with sudo or CAP_BPF + CAP_NET_ADMIN")
	}

	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		t.Fatalf("cgroup v2 is unavailable at /sys/fs/cgroup: %v", err)
	}
	if strings.TrimSpace(string(controllers)) == "" {
		t.Fatal("cgroup v2 controller list is empty")
	}
	if !phase0MountInfoHas("/sys/fs/cgroup", "cgroup2") {
		t.Fatal("/sys/fs/cgroup is not mounted as cgroup2")
	}
	if !phase0MountInfoHas("/sys/fs/bpf", "bpf") {
		t.Fatal("/sys/fs/bpf is not mounted as bpffs")
	}

	t.Logf("kernel=%s cgroup_controllers=%s", phase0KernelRelease(t), strings.TrimSpace(string(controllers)))

	probe, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "ztap_phase0_probe",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("BPF map creation failed under the runner capabilities: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("close BPF map probe: %v", err)
	}
}

func TestEBPFIntegrationFlowMapPinCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges; re-run with sudo or CAP_BPF + CAP_NET_ADMIN")
	}

	compileTestBPF(t)
	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = enf.Close()
		}
	})
	if err := enf.LoadPolicies(nil); err != nil {
		t.Fatalf("failed to load eBPF objects: %v", err)
	}

	path := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ztap-phase0-flow-events-%d", os.Getpid()))
	_ = os.Remove(path)
	if err := enf.PinFlowEventsMap(path); err != nil {
		t.Fatalf("pin flow map: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pinned flow map is not visible at %s: %v", path, err)
	}

	pinned, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatalf("open pinned flow map: %v", err)
	}
	if err := pinned.Close(); err != nil {
		t.Fatalf("close pinned flow map: %v", err)
	}
	if err := enf.Close(); err != nil {
		t.Fatalf("close enforcer: %v", err)
	}
	closed = true
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("flow map pin remains after enforcer shutdown: %v", err)
	}
}

func phase0KernelRelease(t *testing.T) string {
	t.Helper()
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(release))
}

func phase0MountInfoHas(mountpoint, filesystem string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) {
			continue
		}
		if fields[4] == mountpoint && fields[separator+1] == filesystem {
			return true
		}
	}
	return false
}
