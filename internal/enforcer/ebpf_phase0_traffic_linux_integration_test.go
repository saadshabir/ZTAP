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
	"ztap/internal/policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

// TestEBPFIntegrationPhase0QuarantineIsolation proves that an unsupported
// subject can fail closed without freezing accepted policy for another
// subject under the same attachment.
func TestEBPFIntegrationPhase0QuarantineIsolation(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)

	parent := createTestCgroup(t)
	quarantinedCgroup := createSubCgroup(t, parent, "quarantined")
	acceptedCgroup := createSubCgroup(t, parent, "accepted")
	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	t.Cleanup(func() { _ = enf.Close() })

	quarantinedID := mustCgroupID(t, quarantinedCgroup)
	acceptedID := mustCgroupID(t, acceptedCgroup)
	port := reserveUDPPort(t)
	allow := allowUDPPolicy("phase0-quarantine", "127.0.0.1/32", port)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{
		{
			Tenant:                "phase0",
			Policy:                allow,
			SubjectCgroupIDs:      []uint64{quarantinedID},
			QuarantinedDirections: DirectionEgressMask,
		},
		{Tenant: "phase0", Policy: allow, SubjectCgroupIDs: []uint64{acceptedID}},
	}); err != nil {
		t.Fatalf("failed to load quarantine candidate: %v", err)
	}
	if err := enf.Attach(parent); err != nil {
		t.Fatalf("failed to attach eBPF programs: %v", err)
	}

	reader, err := ringbuf.NewReader(enf.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	runUDPSendHelperInCgroup(t, quarantinedCgroup, addr)
	quarantinedEvent := readFlowEvent(t, reader, uint16(port), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if quarantinedEvent.Action != flow.ActionBlocked {
		t.Fatalf("quarantined subject action = %d, want blocked", quarantinedEvent.Action)
	}

	runUDPSendHelperInCgroup(t, acceptedCgroup, addr)
	acceptedEvent := readFlowEvent(t, reader, uint16(port), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if acceptedEvent.Action != flow.ActionAllowed {
		t.Fatalf("unrelated accepted subject action = %d, want allowed", acceptedEvent.Action)
	}
}

// TestEBPFIntegrationPhase0PerSubjectIngressIdentity verifies the attachment
// model required by the target engine: one shared program/map collection can
// be attached to more than one subject cgroup, and cgroup-local storage gives
// each ingress invocation the identity of its own attachment.
func TestEBPFIntegrationPhase0PerSubjectIngressIdentity(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)

	cgroupA := createTestCgroup(t)
	cgroupB := createTestCgroup(t)
	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	t.Cleanup(func() { _ = enf.Close() })

	cgroupIDA := mustCgroupID(t, cgroupA)
	cgroupIDB := mustCgroupID(t, cgroupB)
	portA := reserveUDPPort(t)
	portB := reserveUDPPort(t)
	policyA := allowUDPIngressPolicy("phase0-subject-a", portA)
	policyB := allowUDPIngressPolicy("phase0-subject-b", portB)
	if err := enf.LoadPoliciesScoped([]ScopedPolicy{
		{Tenant: "phase0", Policy: policyA, SubjectCgroupIDs: []uint64{cgroupIDA}},
		{Tenant: "phase0", Policy: policyB, SubjectCgroupIDs: []uint64{cgroupIDB}},
	}); err != nil {
		t.Fatalf("failed to load per-subject ingress candidate: %v", err)
	}
	if err := enf.Attach(cgroupA); err != nil {
		t.Fatalf("failed to attach subject A: %v", err)
	}

	extraEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupB, Attach: ebpf.AttachCGroupInetEgress, Program: enf.objs.FilterEgress,
	})
	if err != nil {
		t.Fatalf("failed to attach subject B egress: %v", err)
	}
	t.Cleanup(func() { _ = extraEgress.Close() })
	extraIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupB, Attach: ebpf.AttachCGroupInetIngress, Program: enf.objs.FilterIngress,
	})
	if err != nil {
		t.Fatalf("failed to attach subject B ingress: %v", err)
	}
	t.Cleanup(func() { _ = extraIngress.Close() })
	if err := enf.objs.AttachedCgroup.Put(&cgroupIDB, &cgroupIDB); err != nil {
		t.Fatalf("record subject B cgroup identity: %v", err)
	}

	if !runUDPReceiveHelperInCgroup(t, cgroupA, portA) {
		t.Fatal("subject A did not receive its allowed ingress packet")
	}
	if runUDPReceiveHelperInCgroup(t, cgroupA, portB) {
		t.Fatal("subject A received traffic allowed only for subject B")
	}
	if !runUDPReceiveHelperInCgroup(t, cgroupB, portB) {
		t.Fatal("subject B did not receive its allowed ingress packet")
	}
	if runUDPReceiveHelperInCgroup(t, cgroupB, portA) {
		t.Fatal("subject B received traffic allowed only for subject A")
	}
}

// TestEBPFIntegrationPhase0ExplicitSelfBypass verifies that a mapped Pod IP
// bypasses ordinary policy lookup for traffic whose two endpoints are that
// address. The Kubernetes fixture covers all four request/reply hook events.
func TestEBPFIntegrationPhase0ExplicitSelfBypass(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)
	if err := StopEBPFEnforcement(); err != nil {
		t.Fatalf("clear prior enforcement: %v", err)
	}

	cgroupPath := createTestCgroup(t)
	t.Cleanup(func() { _ = StopEBPFEnforcement() })
	allowedPort := reserveUDPPort(t)
	policyPort := reserveUDPPort(t)
	policyObj := allowUDPPolicy("phase0-explicit-self", "127.0.0.1/32", policyPort)
	if err := EnforceWithEBPFReal(EnforcementOptions{
		CgroupPath: cgroupPath,
		SelfIPs:    []string{"127.0.0.1"},
		Policies:   []policy.NetworkPolicy{policyObj},
	}); err != nil {
		t.Fatalf("apply policy with self bypass: %v", err)
	}

	reader, err := ringbuf.NewReader(activeEBPFEnforcer.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDPSendHelperInCgroup(t, cgroupPath, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event := readFlowEvent(t, reader, uint16(allowedPort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if event.Action != flow.ActionAllowed {
		t.Fatalf("self-bypass action = %d, want allowed", event.Action)
	}
}

// TestEBPFIntegrationPhase0FailedCandidatePreservesActivePolicy verifies that
// a candidate which fails after partially populating its private maps never
// reaches the active links.
func TestEBPFIntegrationPhase0FailedCandidatePreservesActivePolicy(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)
	if err := StopEBPFEnforcement(); err != nil {
		t.Fatalf("clear prior enforcement: %v", err)
	}

	parent := createTestCgroup(t)
	child := createSubCgroup(t, parent, "subject")
	t.Cleanup(func() { _ = StopEBPFEnforcement() })
	cgroupID := mustCgroupID(t, child)
	activePort := reserveUDPPort(t)
	candidatePort := reserveUDPPort(t)

	activePolicy := allowUDPPolicy("phase0-active", "127.0.0.1/32", activePort)
	if err := EnforceWithEBPFRealScoped(ScopedEnforcementOptions{
		CgroupPath: parent,
		Policies: []ScopedPolicy{{
			Tenant:           "phase0",
			Policy:           activePolicy,
			SubjectCgroupIDs: []uint64{cgroupID},
		}},
	}); err != nil {
		t.Fatalf("apply active policy: %v", err)
	}
	active := activeEBPFEnforcer

	candidatePolicy := allowUDPPolicy("phase0-candidate", "127.0.0.1/32", candidatePort)
	invalidPolicy := allowUDPPolicy("phase0-invalid", "127.0.0.1/32", candidatePort)
	invalidPolicy.Spec.Egress[0].Ports[0].PortName = "named-port"
	if err := EnforceWithEBPFRealScoped(ScopedEnforcementOptions{
		CgroupPath: parent,
		Policies: []ScopedPolicy{
			{Tenant: "phase0", Policy: candidatePolicy, SubjectCgroupIDs: []uint64{cgroupID}},
			{Tenant: "phase0", Policy: invalidPolicy, SubjectCgroupIDs: []uint64{cgroupID}},
		},
	}); err == nil {
		t.Fatal("candidate with an unsupported named port unexpectedly applied")
	}
	if activeEBPFEnforcer != active {
		t.Fatal("failed candidate replaced the active enforcer")
	}

	reader, err := ringbuf.NewReader(active.objs.FlowEvents)
	if err != nil {
		t.Fatalf("failed to create active flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDPSendHelperInCgroup(t, child, fmt.Sprintf("127.0.0.1:%d", activePort))
	activeEvent := readFlowEvent(t, reader, uint16(activePort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if activeEvent.Action != flow.ActionAllowed {
		t.Fatalf("active policy action = %d after failed candidate, want allowed", activeEvent.Action)
	}
	runUDPSendHelperInCgroup(t, child, fmt.Sprintf("127.0.0.1:%d", candidatePort))
	candidateEvent := readFlowEvent(t, reader, uint16(candidatePort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if candidateEvent.Action != flow.ActionBlocked {
		t.Fatalf("candidate policy leaked into active state: action = %d, want blocked", candidateEvent.Action)
	}
}

// TestEBPFIntegrationPhase0IngressLinkFailureRollsBackEgress forces the
// second direction update to fail after egress has changed, then verifies the
// first direction is restored and link ownership remains with the old engine.
func TestEBPFIntegrationPhase0IngressLinkFailureRollsBackEgress(t *testing.T) {
	requirePhase0LinuxRoot(t)
	compileTestBPF(t)

	parent := createTestCgroup(t)
	child := createSubCgroup(t, parent, "subject")
	cgroupID := mustCgroupID(t, child)
	activePort := reserveUDPPort(t)
	candidatePort := reserveUDPPort(t)

	oldEnforcer, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("create old enforcer: %v", err)
	}
	t.Cleanup(func() { _ = oldEnforcer.Close() })
	activePolicy := allowUDPPolicy("phase0-rollback-active", "127.0.0.1/32", activePort)
	if err := oldEnforcer.LoadPoliciesScoped([]ScopedPolicy{{
		Tenant: "phase0", Policy: activePolicy, SubjectCgroupIDs: []uint64{cgroupID},
	}}); err != nil {
		t.Fatalf("load old policy: %v", err)
	}
	if err := oldEnforcer.Attach(parent); err != nil {
		t.Fatalf("attach old enforcer: %v", err)
	}

	newEnforcer, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("create candidate enforcer: %v", err)
	}
	t.Cleanup(func() { _ = newEnforcer.Close() })
	newEnforcer.cgroupStorageReplacement = oldEnforcer.objs.AttachedCgroup
	candidatePolicy := allowUDPPolicy("phase0-rollback-candidate", "127.0.0.1/32", candidatePort)
	if err := newEnforcer.LoadPoliciesScoped([]ScopedPolicy{{
		Tenant: "phase0", Policy: candidatePolicy, SubjectCgroupIDs: []uint64{cgroupID},
	}}); err != nil {
		t.Fatalf("load candidate policy: %v", err)
	}

	originalIngress := newEnforcer.objs.FilterIngress
	newEnforcer.objs.FilterIngress = newEnforcer.objs.FilterEgress
	updateErr := newEnforcer.UpdateFrom(oldEnforcer)
	newEnforcer.objs.FilterIngress = originalIngress
	if updateErr == nil {
		t.Fatal("ingress link accepted an egress-typed replacement program")
	}
	if oldEnforcer.egressLink == nil || oldEnforcer.ingressLink == nil {
		t.Fatal("old enforcer lost link ownership after rolled-back update")
	}
	if newEnforcer.egressLink != nil || newEnforcer.ingressLink != nil {
		t.Fatal("candidate enforcer acquired links after rolled-back update")
	}

	reader, err := ringbuf.NewReader(oldEnforcer.objs.FlowEvents)
	if err != nil {
		t.Fatalf("create old flow reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	runUDPSendHelperInCgroup(t, child, fmt.Sprintf("127.0.0.1:%d", activePort))
	activeEvent := readFlowEvent(t, reader, uint16(activePort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if activeEvent.Action != flow.ActionAllowed {
		t.Fatalf("rolled-back active action = %d, want allowed", activeEvent.Action)
	}
	runUDPSendHelperInCgroup(t, child, fmt.Sprintf("127.0.0.1:%d", candidatePort))
	candidateEvent := readFlowEvent(t, reader, uint16(candidatePort), flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if candidateEvent.Action != flow.ActionBlocked {
		t.Fatalf("candidate remained active after rollback: action = %d, want blocked", candidateEvent.Action)
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

func allowUDPIngressPolicy(name string, port int) policy.NetworkPolicy {
	return policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   policy.NetworkPolicyMetadata{Name: name},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "test"}},
			Ingress: []policy.IngressRule{{
				From:  policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "127.0.0.1/32"}},
				Ports: []policy.PortSpec{{Protocol: "UDP", Port: port}},
			}},
		},
	}
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
