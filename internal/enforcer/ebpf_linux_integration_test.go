//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"ztap/internal/flow"
	"ztap/internal/policy"

	"github.com/cilium/ebpf/ringbuf"
)

// TestEBPFIntegrationLoadAndAttach verifies that the compiled eBPF program loads,
// populates the policy map, and attaches to a real Linux cgroup. Requires root.
func TestEBPFIntegrationLoadAndAttach(t *testing.T) {
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
	t.Cleanup(func() {
		if err := enf.Close(); err != nil {
			t.Errorf("failed to close enforcer: %v", err)
		}
	})

	policies := []policy.NetworkPolicy{allowTCPPolicy("allow-web", "10.1.2.0/24", 443)}
	if err := enf.LoadPolicies(policies); err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	cgroupPath := createTestCgroup(t)
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	_, ipnet, err := net.ParseCIDR("10.1.2.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	mode := detectPolicyMapMode(enf.objs.PolicyMap)
	protocol := protocolToNum("TCP")

	var lookupKey any
	if mode == policyMapModeLPMTrie {
		ones, _ := ipnet.Mask.Size()
		prefixLen, err := lpmPrefixLen(ones)
		if err != nil {
			t.Fatalf("prefix length: %v", err)
		}
		var ipBytes [4]byte
		copy(ipBytes[:], ipnet.IP.To4())
		lookupKey = &policyKeyLPM{
			PrefixLen: prefixLen,
			Meta:      packLPMMeta(DirectionEgress, protocol, 443),
			CgroupID:  0,
			IP:        ipBytes,
		}
	} else {
		lookupKey = &policyKey{
			IP:        ipToUint32(ipnet.IP.To4()),
			Port:      443,
			Protocol:  protocol,
			Direction: DirectionEgress,
		}
	}
	var value policyValue
	if err := enf.objs.PolicyMap.Lookup(lookupKey, &value); err != nil {
		t.Fatalf("failed to lookup policy map: %v", err)
	}

	if value.Action != 1 {
		t.Fatalf("expected allow action (1), got %d", value.Action)
	}
}

func TestEBPFIntegrationCgroupScopedMapKey(t *testing.T) {
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
	t.Cleanup(func() {
		_ = enf.Close()
	})

	cgroupPath := createTestCgroup(t)
	fi, err := os.Stat(cgroupPath)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type: %T", fi.Sys())
	}
	cgid := uint64(st.Ino)

	p := allowTCPPolicy("allow-web", "10.1.2.0/24", 443)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{Tenant: "default", Policy: p, SubjectCgroupIDs: []uint64{cgid}}}); err != nil {
		t.Fatalf("failed to load scoped policies: %v", err)
	}
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	mode := detectPolicyMapMode(enf.objs.PolicyMap)
	protocol := protocolToNum("TCP")
	_, ipnet, err := net.ParseCIDR("10.1.2.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}

	var lookupKey any
	if mode == policyMapModeLPMTrie {
		ones, _ := ipnet.Mask.Size()
		prefixLen, err := lpmPrefixLen(ones)
		if err != nil {
			t.Fatalf("prefix length: %v", err)
		}
		var ipBytes [4]byte
		copy(ipBytes[:], ipnet.IP.To4())
		lookupKey = &policyKeyLPM{
			PrefixLen: prefixLen,
			Meta:      packLPMMeta(DirectionEgress, protocol, 443),
			CgroupID:  cgid,
			IP:        ipBytes,
		}
	} else {
		lookupKey = &policyKey{
			CgroupID:  cgid,
			IP:        ipToUint32(ipnet.IP.To4()),
			Port:      443,
			Protocol:  protocol,
			Direction: DirectionEgress,
		}
	}
	var value policyValue
	if err := enf.objs.PolicyMap.Lookup(lookupKey, &value); err != nil {
		t.Fatalf("failed to lookup policy map: %v", err)
	}
	if value.Action != 1 {
		t.Fatalf("expected allow action (1), got %d", value.Action)
	}

	if enf.enforcedCgroups == nil {
		t.Fatal("expected enforcedCgroups map to be available")
	}
	var present uint8
	if err := enf.enforcedCgroups.Lookup(&cgid, &present); err != nil {
		t.Fatalf("expected cgroup id to be present in enforced_cgroups map: %v", err)
	}
	if present != 1 {
		t.Fatalf("expected enforced_cgroups value 1, got %d", present)
	}

	if enf.enforcementConfigMap == nil {
		t.Fatal("expected enforcementConfigMap to be available")
	}
	var cfgK uint32
	var cfg enforcementConfig
	if err := enf.enforcementConfigMap.Lookup(&cfgK, &cfg); err != nil {
		t.Fatalf("expected enforcement_config_map to be readable: %v", err)
	}
	if cfg.SelectedOnly != 1 {
		t.Fatalf("expected selected_only=1, got %d", cfg.SelectedOnly)
	}
}

func TestEBPFIntegrationCgroupIsolationBetweenCgroups(t *testing.T) {
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
	t.Cleanup(func() { _ = enf.Close() })

	cgroupA := createTestCgroup(t)
	cgroupB := createTestCgroup(t)

	cgidA := mustCgroupID(t, cgroupA)
	cgidB := mustCgroupID(t, cgroupB)

	p := allowTCPPolicy("allow-web", "10.1.2.0/24", 443)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{Tenant: "default", Policy: p, SubjectCgroupIDs: []uint64{cgidA}}}); err != nil {
		t.Fatalf("failed to load scoped policies: %v", err)
	}
	if err := enf.Attach(cgroupA); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	mode := detectPolicyMapMode(enf.objs.PolicyMap)
	protocol := protocolToNum("TCP")
	_, ipnet, err := net.ParseCIDR("10.1.2.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}

	var keyA any
	var keyB any
	if mode == policyMapModeLPMTrie {
		ones, _ := ipnet.Mask.Size()
		prefixLen, err := lpmPrefixLen(ones)
		if err != nil {
			t.Fatalf("prefix length: %v", err)
		}
		var ipBytes [4]byte
		copy(ipBytes[:], ipnet.IP.To4())
		keyA = &policyKeyLPM{PrefixLen: prefixLen, Meta: packLPMMeta(DirectionEgress, protocol, 443), CgroupID: cgidA, IP: ipBytes}
		keyB = &policyKeyLPM{PrefixLen: prefixLen, Meta: packLPMMeta(DirectionEgress, protocol, 443), CgroupID: cgidB, IP: ipBytes}
	} else {
		keyA = &policyKey{CgroupID: cgidA, IP: ipToUint32(ipnet.IP.To4()), Port: 443, Protocol: protocol, Direction: DirectionEgress}
		keyB = &policyKey{CgroupID: cgidB, IP: ipToUint32(ipnet.IP.To4()), Port: 443, Protocol: protocol, Direction: DirectionEgress}
	}

	var value policyValue
	if err := enf.objs.PolicyMap.Lookup(keyA, &value); err != nil {
		t.Fatalf("failed to lookup policy map for cgroup A: %v", err)
	}
	if value.Action != 1 {
		t.Fatalf("expected allow for cgroup A, got %d", value.Action)
	}
	if err := enf.objs.PolicyMap.Lookup(keyB, &value); err == nil {
		t.Fatalf("expected policy map lookup for cgroup B to fail, but it succeeded")
	}
}

func TestEBPFIntegrationSelectedOnlySemantics(t *testing.T) {
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
	t.Cleanup(func() { _ = enf.Close() })

	parent := createTestCgroup(t)
	childA := createSubCgroup(t, parent, "a")
	childB := createSubCgroup(t, parent, "b")
	cgidA := mustCgroupID(t, childA)
	cgidB := mustCgroupID(t, childB)

	allowPort := 31001
	denyPort := 31002
	policyA := allowUDPPolicy("allow-udp", "127.0.0.1/32", allowPort)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{Tenant: "default", Policy: policyA, SubjectCgroupIDs: []uint64{cgidA}}}); err != nil {
		t.Fatalf("failed to load scoped policies: %v", err)
	}
	if err := enf.Attach(parent); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	if enf.enforcedCgroups == nil {
		t.Fatal("expected enforcedCgroups map")
	}
	if err := enf.enforcedCgroups.Lookup(&cgidA, new(uint8)); err != nil {
		t.Fatalf("expected cgroup A to be enforced: %v", err)
	}
	if err := enf.enforcedCgroups.Lookup(&cgidB, new(uint8)); err == nil {
		t.Fatalf("expected cgroup B to NOT be enforced")
	}

	reader, err := ringbuf.NewReader(enf.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	// From enforced cgroup A: allowed port should be allowed.
	runUDPSendHelperInCgroup(t, childA, fmt.Sprintf("127.0.0.1:%d", allowPort))
	evt := readFlowEvent(t, reader, uint16(allowPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if evt.Action != flow.ActionAllowed {
		t.Fatalf("expected allowed for enforced cgroup on allowed port, got %d", evt.Action)
	}

	// From enforced cgroup A: missing rule should be blocked (default-deny on miss).
	runUDPSendHelperInCgroup(t, childA, fmt.Sprintf("127.0.0.1:%d", denyPort))
	evt = readFlowEvent(t, reader, uint16(denyPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if evt.Action != flow.ActionBlocked {
		t.Fatalf("expected blocked for enforced cgroup on missing rule, got %d", evt.Action)
	}

	// From non-enforced cgroup B: missing rule should be allowed.
	runUDPSendHelperInCgroup(t, childB, fmt.Sprintf("127.0.0.1:%d", denyPort))
	evt = readFlowEvent(t, reader, uint16(denyPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if evt.Action != flow.ActionAllowed {
		t.Fatalf("expected allowed for non-enforced cgroup on missing rule, got %d", evt.Action)
	}
}

func TestEBPFIntegrationCIDREndToEndEgress(t *testing.T) {
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
	t.Cleanup(func() { _ = enf.Close() })

	allowPort := 31011
	policies := []policy.NetworkPolicy{allowUDPPolicy("allow-loopback", "127.0.0.0/24", allowPort)}
	if err := enf.LoadPolicies(policies); err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	cgroupPath := createTestCgroup(t)
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	reader, err := ringbuf.NewReader(enf.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	// In-range destination should be allowed.
	runUDPSendHelperInCgroup(t, cgroupPath, fmt.Sprintf("127.0.0.2:%d", allowPort))
	evt := readFlowEvent(t, reader, uint16(allowPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if evt.Action != flow.ActionAllowed {
		t.Fatalf("expected allowed for in-range CIDR destination, got %d", evt.Action)
	}

	// Out-of-range destination should be blocked (same port, different /24).
	runUDPSendHelperInCgroup(t, cgroupPath, fmt.Sprintf("127.0.1.2:%d", allowPort))
	evt = readFlowEvent(t, reader, uint16(allowPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if evt.Action != flow.ActionBlocked {
		t.Fatalf("expected blocked for out-of-range CIDR destination, got %d", evt.Action)
	}
}

// TestEBPFIntegrationIngressCgroupTraffic verifies that the ingress hook
// observes real UDP traffic for a selected cgroup and preserves
// default-deny behavior for a port without a rule.
func TestEBPFIntegrationIngressCgroupTraffic(t *testing.T) {
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
	t.Cleanup(func() { _ = enf.Close() })

	cgroupPath := createTestCgroup(t)
	cgid := mustCgroupID(t, cgroupPath)
	allowedPort := reserveUDPPort(t)
	policyObj := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: "allow-ingress"},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "test"}},
			Ingress: []policy.IngressRule{{
				From:  policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "127.0.0.1/32"}},
				Ports: []policy.PortSpec{{Protocol: "UDP", Port: allowedPort}},
			}},
		},
	}
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{{Tenant: "default", Policy: policyObj, SubjectCgroupIDs: []uint64{cgid}}}); err != nil {
		t.Fatalf("failed to load scoped ingress policy: %v", err)
	}
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach programs: %v", err)
	}

	reader, err := ringbuf.NewReader(enf.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	if !runUDPReceiveHelperInCgroup(t, cgroupPath, allowedPort) {
		t.Fatal("allowed ingress datagram was not delivered")
	}
	evt := readFlowEvent(t, reader, uint16(allowedPort), flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	if evt.Action != flow.ActionAllowed {
		t.Fatalf("expected allowed ingress event, got action %d", evt.Action)
	}

	deniedPort := reserveUDPPort(t)
	if runUDPReceiveHelperInCgroup(t, cgroupPath, deniedPort) {
		t.Fatal("unmatched ingress datagram was delivered")
	}
	evt = readFlowEvent(t, reader, uint16(deniedPort), flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	if evt.Action != flow.ActionBlocked {
		t.Fatalf("expected blocked ingress event, got action %d", evt.Action)
	}
}

func TestCgroupUDPSendHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	fdStr := os.Getenv("ZTAP_START_FD")
	if fdStr == "" {
		t.Fatal("ZTAP_START_FD not set")
	}
	fd := uintptr(3)
	if fdStr != "3" {
		// only support the fixed ExtraFiles offset used by the parent
		t.Fatalf("unexpected ZTAP_START_FD=%s", fdStr)
	}
	startFile := os.NewFile(fd, "start")
	if startFile == nil {
		t.Fatal("failed to open start fd")
	}
	buf := make([]byte, 1)
	_, _ = startFile.Read(buf)
	_ = startFile.Close()

	conn, err := net.DialTimeout("udp4", addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial udp failed: %v", err)
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
}

func TestCgroupUDPReceiveHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_RECEIVE_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	startFile := os.NewFile(uintptr(3), "start")
	statusFile := os.NewFile(uintptr(4), "status")
	if startFile == nil || statusFile == nil {
		t.Fatal("failed to open helper pipes")
	}
	defer startFile.Close()
	defer statusFile.Close()

	if _, err := io.ReadFull(startFile, make([]byte, 1)); err != nil {
		t.Fatalf("start signal: %v", err)
	}
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		_, _ = statusFile.Write([]byte{'e'})
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	if _, err := statusFile.Write([]byte{'r'}); err != nil {
		t.Fatalf("ready signal: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	_, _, err = conn.ReadFrom(make([]byte, 1))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			_, _ = statusFile.Write([]byte{'0'})
			return
		}
		_, _ = statusFile.Write([]byte{'e'})
		t.Fatalf("receive: %v", err)
	}
	_, _ = statusFile.Write([]byte{'1'})
}

func allowUDPPolicy(name, cidr string, port int) policy.NetworkPolicy {
	p := allowTCPPolicy(name, cidr, port)
	// rewrite protocol to UDP
	if len(p.Spec.Egress) > 0 && len(p.Spec.Egress[0].Ports) > 0 {
		p.Spec.Egress[0].Ports[0].Protocol = "UDP"
	}
	return p
}

func mustCgroupID(t *testing.T, cgroupPath string) uint64 {
	t.Helper()
	fi, err := os.Stat(cgroupPath)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type: %T", fi.Sys())
	}
	return uint64(st.Ino)
}

func createSubCgroup(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("failed to create child cgroup %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func runUDPSendHelperInCgroup(t *testing.T, cgroupPath, addr string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPSendHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_HELPER=1", "ZTAP_UDP_ADDR="+addr, "ZTAP_START_FD=3")
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	// Move helper into cgroup before allowing it to run.
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	f, err := os.OpenFile(procsPath, os.O_WRONLY, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open %s: %v", procsPath, err)
	}
	_, err = fmt.Fprintf(f, "%d\n", cmd.Process.Pid)
	_ = f.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("write %s: %v", procsPath, err)
	}

	_, _ = w.Write([]byte("1"))
	_ = w.Close()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper failed: %v", err)
	}
}

func runUDPReceiveHelperInCgroup(t *testing.T, cgroupPath string, port int) bool {
	t.Helper()
	startR, startW, err := os.Pipe()
	if err != nil {
		t.Fatalf("start pipe: %v", err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		_ = startR.Close()
		_ = startW.Close()
		t.Fatalf("status pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = startR.Close()
		_ = startW.Close()
		_ = statusR.Close()
		_ = statusW.Close()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPReceiveHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_RECEIVE_HELPER=1", "ZTAP_UDP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{startR, statusW}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start receive helper: %v", err)
	}
	_ = startR.Close()
	_ = statusW.Close()

	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
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

	if _, err := startW.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release helper: %v", err)
	}
	_ = startW.Close()

	status := make([]byte, 2)
	if _, err := io.ReadFull(statusR, status[:1]); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper readiness: %v", err)
	}
	if status[0] != 'r' {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper failed before readiness: %q", status[0])
	}

	conn, err := net.DialTimeout("udp4", addr, 500*time.Millisecond)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("dial receive helper: %v", err)
	}
	_, writeErr = conn.Write([]byte{'x'})
	_ = conn.Close()
	if writeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("send receive helper datagram: %v", writeErr)
	}

	if _, err := io.ReadFull(statusR, status[1:]); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper result: %v", err)
	}
	if err := cmd.Wait(); err != nil && status[1] != '0' {
		t.Fatalf("receive helper failed: %v", err)
	}
	return status[1] == '1'
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release UDP port: %v", err)
	}
	return port
}

func readFlowEvent(t *testing.T, r *ringbuf.Reader, destPort uint16, protocol uint8, direction uint8, timeout time.Duration) flow.RawFlowEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timeout waiting for flow event destPort=%d protocol=%d direction=%d", destPort, protocol, direction)
		}
		recCh := make(chan ringbuf.Record, 1)
		errCh := make(chan error, 1)
		go func() {
			rec, err := r.Read()
			if err != nil {
				errCh <- err
				return
			}
			recCh <- rec
		}()
		select {
		case err := <-errCh:
			t.Fatalf("ringbuf read error: %v", err)
		case rec := <-recCh:
			var raw flow.RawFlowEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
				t.Fatalf("parse raw event: %v", err)
			}
			if raw.DestPort != destPort {
				continue
			}
			if raw.Protocol != protocol {
				continue
			}
			if raw.Direction != direction {
				continue
			}
			return raw
		case <-time.After(remaining):
			// loop
		}
	}
}

func compileTestBPF(t *testing.T) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine caller path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	cmd := exec.Command("make")
	cmd.Dir = filepath.Join(repoRoot, "bpf")
	bpfClang := os.Getenv("BPF_CLANG")
	if bpfClang == "" {
		bpfClang = "clang"
	}
	cmd.Env = append(os.Environ(), "CLANG="+bpfClang)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build eBPF program: %v\n%s", err, string(output))
	}

	// Set override so the enforcer uses the fresh build instead of embedded bytecode
	t.Setenv("ZTAP_BPF_OBJECT", filepath.Join(repoRoot, "bpf", "filter.o"))
}

func createTestCgroup(t *testing.T) string {
	t.Helper()

	name := fmt.Sprintf("ztap-test-%d", time.Now().UnixNano())
	path := filepath.Join("/sys/fs/cgroup", name)

	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("failed to create test cgroup %s: %v", path, err)
	}

	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("failed to remove test cgroup %s: %v", path, err)
		}
	})

	return path
}

func allowTCPPolicy(name, cidr string, port int) policy.NetworkPolicy {
	policyObj := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
	}
	policyObj.Metadata.Name = name
	policyObj.Spec.PodSelector.MatchLabels = map[string]string{"app": "test"}

	egressRule := policy.EgressRule{
		To: policy.EgressTarget{
			IPBlock: policy.IPBlockSpec{CIDR: cidr},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: port},
		},
	}

	policyObj.Spec.Egress = append(policyObj.Spec.Egress, egressRule)
	return policyObj
}

// TestEBPFGracefulReload verifies that updating policies via EnforceWithEBPFReal
// works without error and updates existing rules.
func TestEBPFGracefulReload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	compileTestBPF(t)

	cgroupPath := createTestCgroup(t)
	defer StopEBPFEnforcement() // Ensure we clean up active enforcement

	// Step 1: Initial enforcement
	p1 := allowTCPPolicy("policy-1", "10.0.0.1/32", 80)
	opts1 := EnforcementOptions{
		Policies:   []policy.NetworkPolicy{p1},
		CgroupPath: cgroupPath,
	}

	if err := EnforceWithEBPFReal(opts1); err != nil {
		t.Fatalf("Initial enforcement failed: %v", err)
	}

	// Capture initial enforcer and its members
	enf1 := activeEBPFEnforcer
	if enf1 == nil {
		t.Fatal("activeEBPFEnforcer is nil after initial enforcement")
	}
	if enf1.egressLink == nil {
		t.Fatal("egressLink is nil")
	}

	// Step 2: Graceful reload with different policy
	p2 := allowTCPPolicy("policy-1", "10.0.0.2/32", 443)
	opts2 := EnforcementOptions{
		Policies:   []policy.NetworkPolicy{p2},
		CgroupPath: cgroupPath,
	}

	if err := EnforceWithEBPFReal(opts2); err != nil {
		t.Fatalf("Graceful reload failed: %v", err)
	}

	enf2 := activeEBPFEnforcer
	if enf2 == nil {
		t.Fatal("activeEBPFEnforcer is nil after reload")
	}

	if enf2 == enf1 {
		t.Fatal("activeEBPFEnforcer did not change after reload")
	}

	// Verify that ownership of the link was transferred
	if enf1.egressLink != nil {
		t.Error("old enforcer still owns egressLink")
	}
	if enf2.egressLink == nil {
		t.Error("new enforcer does not own egressLink")
	}

	// Step 3: Verify the map content of the new enforcer
	mode := detectPolicyMapMode(enf2.objs.PolicyMap)
	protocol := protocolToNum("TCP")
	_, ipnetNew, err := net.ParseCIDR("10.0.0.2/32")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}

	var key any
	if mode == policyMapModeLPMTrie {
		ones, _ := ipnetNew.Mask.Size()
		prefixLen, err := lpmPrefixLen(ones)
		if err != nil {
			t.Fatalf("prefix length: %v", err)
		}
		var ipBytes [4]byte
		copy(ipBytes[:], ipnetNew.IP.To4())
		key = &policyKeyLPM{PrefixLen: prefixLen, Meta: packLPMMeta(DirectionEgress, protocol, 443), CgroupID: 0, IP: ipBytes}
	} else {
		key = &policyKey{IP: ipToUint32(ipnetNew.IP.To4()), Port: 443, Protocol: protocol, Direction: DirectionEgress}
	}
	var val policyValue
	if err := enf2.objs.PolicyMap.Lookup(key, &val); err != nil {
		t.Fatalf("New policy rule not found in map: %v", err)
	}
	if val.Action != 1 {
		t.Errorf("Expected action 1, got %d", val.Action)
	}

	// Verify old rule is NOT in the new map
	_, ipnetOld, err := net.ParseCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	var oldKey any
	if mode == policyMapModeLPMTrie {
		ones, _ := ipnetOld.Mask.Size()
		prefixLen, err := lpmPrefixLen(ones)
		if err != nil {
			t.Fatalf("prefix length: %v", err)
		}
		var ipBytes [4]byte
		copy(ipBytes[:], ipnetOld.IP.To4())
		oldKey = &policyKeyLPM{PrefixLen: prefixLen, Meta: packLPMMeta(DirectionEgress, protocol, 80), CgroupID: 0, IP: ipBytes}
	} else {
		oldKey = &policyKey{IP: ipToUint32(ipnetOld.IP.To4()), Port: 80, Protocol: protocol, Direction: DirectionEgress}
	}
	if err := enf2.objs.PolicyMap.Lookup(oldKey, &val); err == nil {
		t.Error("Old policy rule still exists in the new map")
	}
}
