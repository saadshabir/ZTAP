//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"ztap/internal/flow"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// TestEBPFIntegrationPhase0FlowTupleAndLifetime exercises the flow map with
// more than one real packet. The earlier Phase 0 test only proved that a pin
// could be opened and removed; this records the decoded tuple and confirms
// that the same reader continues to observe events over the map lifetime.
func TestEBPFIntegrationPhase0FlowTupleAndLifetime(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)

	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	t.Cleanup(func() { _ = enf.Close() })

	cgroupPath := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)
	port := reserveUDPPort(t)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{
		Tenant:           "phase0",
		Policy:           allowUDPPolicy("phase0-flow-lifetime", "127.0.0.0/8", port),
		SubjectCgroupIDs: []uint64{cgroupID},
	}}); err != nil {
		t.Fatalf("failed to load scoped policy: %v", err)
	}
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach eBPF programs: %v", err)
	}

	pinPath := fmt.Sprintf("/sys/fs/bpf/ztap/phase0-flow-lifetime-%d", os.Getpid())
	if err := enf.PinFlowEventsMap(pinPath); err != nil {
		t.Fatalf("failed to pin flow map: %v", err)
	}
	pinned, err := loadPinnedPhase0FlowMap(pinPath)
	if err != nil {
		t.Fatalf("failed to open pinned flow map: %v", err)
	}
	t.Cleanup(func() { _ = pinned.Close() })
	reader, err := ringbuf.NewReader(pinned)
	if err != nil {
		t.Fatalf("failed to create flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	runUDPSendHelperInCgroup(t, cgroupPath, addr)
	first := readFlowEvent(t, reader, uint16(port), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	runUDPSendHelperInCgroup(t, cgroupPath, addr)
	second := readFlowEvent(t, reader, uint16(port), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)

	for name, event := range map[string]flow.RawFlowEvent{"first": first, "second": second} {
		if event.Family != 4 {
			t.Errorf("%s event family = %d, want IPv4", name, event.Family)
		}
		if event.Action != flow.ActionAllowed {
			t.Errorf("%s event action = %d, want allowed", name, event.Action)
		}
		if event.SrcIP[0] == 0 || event.DestIP[0] != 0x7f000001 {
			t.Errorf("%s event tuple = src=%#x dest=%#x, want loopback destination", name, event.SrcIP[0], event.DestIP[0])
		}
		if event.SrcPort == 0 || event.DestPort != uint16(port) {
			t.Errorf("%s event ports = %d -> %d, want ephemeral -> %d", name, event.SrcPort, event.DestPort, port)
		}
	}
	if second.TimestampNs < first.TimestampNs {
		t.Fatalf("flow event timestamps moved backwards: first=%d second=%d", first.TimestampNs, second.TimestampNs)
	}

	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("flow map pin disappeared while enforcer was active: %v", err)
	}
	if err := enf.Close(); err != nil {
		t.Fatalf("close enforcer: %v", err)
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("flow map pin remains after shutdown: %v", err)
	}
}

// TestEBPFIntegrationPhase0IPv6Rejected records the current first-release
// boundary: a selected IPv4-only cgroup must emit and block an IPv6 packet
// instead of silently treating it as an IPv4 packet or allowing it through.
func TestEBPFIntegrationPhase0IPv6Rejected(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)

	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	t.Cleanup(func() { _ = enf.Close() })

	cgroupPath := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)
	port := reserveUDPPort(t)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{
		Tenant:           "phase0",
		Policy:           allowUDPPolicy("phase0-ipv4-only", "127.0.0.1/32", port),
		SubjectCgroupIDs: []uint64{cgroupID},
	}}); err != nil {
		t.Fatalf("failed to load scoped IPv4 policy: %v", err)
	}
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach eBPF programs: %v", err)
	}
	reader, err := ringbuf.NewReader(enf.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDP6SendHelperInCgroup(t, cgroupPath, fmt.Sprintf("[::1]:%d", port))
	event := readFlowEvent(t, reader, uint16(port), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if event.Family != 6 {
		t.Fatalf("IPv6 event family = %d, want 6", event.Family)
	}
	if event.Action != flow.ActionBlocked {
		t.Fatalf("IPv6 event action = %d, want blocked", event.Action)
	}
}

func TestCgroupUDP6SendHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_IPV6_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	startFile := os.NewFile(uintptr(3), "start")
	if startFile == nil {
		t.Fatal("failed to open start fd")
	}
	if _, err := startFile.Read(make([]byte, 1)); err != nil {
		t.Fatalf("start signal: %v", err)
	}
	_ = startFile.Close()

	conn, err := net.DialTimeout("udp6", addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial udp6 failed: %v", err)
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
}

func runUDP6SendHelperInCgroup(t *testing.T, cgroupPath, addr string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	cmd := testHelperCommand(t, "^TestCgroupUDP6SendHelper$")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_IPV6_HELPER=1", "ZTAP_UDP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start IPv6 helper: %v", err)
	}

	procsPath := cgroupPath + "/cgroup.procs"
	f, err := os.OpenFile(procsPath, os.O_WRONLY, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open %s: %v", procsPath, err)
	}
	_, writeErr := fmt.Fprintf(f, "%d\n", cmd.Process.Pid)
	_ = f.Close()
	if writeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("write %s: %v", procsPath, writeErr)
	}

	if _, err := w.Write([]byte("1")); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release IPv6 helper: %v", err)
	}
	_ = w.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("IPv6 helper failed: %v", err)
	}
}

func testHelperCommand(t *testing.T, testName string) *exec.Cmd {
	t.Helper()
	return exec.Command(os.Args[0], "-test.run", testName, "-test.v")
}

func requirePhase0LinuxRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges; re-run with sudo or CAP_BPF + CAP_NET_ADMIN")
	}
}

func loadPinnedPhase0FlowMap(path string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(path, nil)
}
