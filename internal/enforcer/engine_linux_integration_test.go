//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"
	"github.com/saadshabir/ZTAP/internal/policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func TestLinuxEngineRejectsIncompatibleCgroupProgram(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	foreign, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "ztap_foreign_cgroup_skb",
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetEgress,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 1, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("load foreign cgroup program: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	foreignLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: foreign,
	})
	if err != nil {
		t.Fatalf("attach foreign cgroup program: %v", err)
	}
	t.Cleanup(func() { _ = foreignLink.Close() })

	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	err = engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, 80))
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("kernel cannot query cgroup programs: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "incompatible program") {
		t.Fatalf("engine apply error = %v, want incompatible attachment failure", err)
	}
}

func TestLinuxEnginePublishesLifecycleStatus(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	zero := uint32(0)
	var status bpfAgentStatus
	if err := engine.AgentStatusMap().Lookup(&zero, &status); err != nil {
		t.Fatalf("read starting agent status: %v", err)
	}
	if status.SchemaVersion != engineAgentStatusSchema || status.LifecycleState != engineStateStarting || status.AgentEpoch != 42 || status.HeartbeatNS == 0 {
		t.Fatalf("starting agent status = %+v", status)
	}

	if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, 80)); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	var enforcing bpfAgentStatus
	if err := engine.AgentStatusMap().Lookup(&zero, &enforcing); err != nil {
		t.Fatalf("read enforcing agent status: %v", err)
	}
	if enforcing.SchemaVersion != engineAgentStatusSchema || enforcing.LifecycleState != engineStateEnforcing || enforcing.AgentEpoch != 42 || enforcing.HeartbeatNS == 0 {
		t.Fatalf("enforcing agent status = %+v", enforcing)
	}
	if enforcing.HeartbeatNS < status.HeartbeatNS {
		t.Fatalf("heartbeat moved backwards: starting=%d enforcing=%d", status.HeartbeatNS, enforcing.HeartbeatNS)
	}
}

func TestLinuxEnginePublishesStoppingLifecycleStatus(t *testing.T) {
	requireLinuxEBPFRoot(t)

	engine := newLinuxEngineForTest(t, nil)
	status, err := ebpf.LoadPinnedMap(engine.store.agentStatusPin, nil)
	if err != nil {
		t.Fatalf("open pinned agent status map: %v", err)
	}
	t.Cleanup(func() { _ = status.Close() })
	if err := engine.Close(); err != nil {
		t.Fatalf("close engine: %v", err)
	}

	zero := uint32(0)
	var stopping bpfAgentStatus
	if err := status.Lookup(&zero, &stopping); err != nil {
		t.Fatalf("read stopping agent status: %v", err)
	}
	if stopping.SchemaVersion != engineAgentStatusSchema || stopping.LifecycleState != engineStateStopping || stopping.AgentEpoch != 42 || stopping.HeartbeatNS == 0 {
		t.Fatalf("stopping agent status = %+v", stopping)
	}
	if _, err := os.Lstat(engine.store.agentStatusPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("agent status pin remains after close: %v", err)
	}
}

func TestLinuxEngineMetricsSnapshotReadsStableCounters(t *testing.T) {
	requireLinuxEBPFRoot(t)

	engine := newLinuxEngineForTest(t, nil)
	snapshot, err := engine.MetricsSnapshot(context.Background())
	if err != nil {
		t.Fatalf("initial engine metrics snapshot: %v", err)
	}
	if snapshot.ActivePolicyEpoch != 0 || len(snapshot.Decisions) != 48 || len(snapshot.EventDrops) != 2 {
		t.Fatalf("initial engine metrics snapshot = %+v, want epoch 0, 48 decisions, 2 drops", snapshot)
	}
	for _, decision := range snapshot.Decisions {
		if decision.Count != 0 {
			t.Fatalf("initial decision metric %+v has non-zero count", decision)
		}
	}
	for _, drop := range snapshot.EventDrops {
		if drop.Count != 0 {
			t.Fatalf("initial event-drop metric %+v has non-zero count", drop)
		}
	}

	snapshot, err = engine.MetricsSnapshot(context.Background())
	if err != nil {
		t.Fatalf("second engine metrics snapshot: %v", err)
	}
	if snapshot.ActivePolicyEpoch != 0 {
		t.Fatalf("second engine active epoch = %d, want 0 before apply", snapshot.ActivePolicyEpoch)
	}
}

func TestLinuxEngineDirectionAndBypassSemantics(t *testing.T) {
	requireLinuxEBPFRoot(t)

	root := createTestCgroup(t)
	selected := createSubCgroup(t, root, "selected")
	selectedChild := createSubCgroup(t, selected, "selected-child")
	unselected := createSubCgroup(t, root, "unselected")
	selectedID := mustCgroupID(t, selected)
	allowedListener := listenEngineTestUDP(t)
	deniedListener := listenEngineTestUDP(t)
	allowedPort := uint16(allowedListener.LocalAddr().(*net.UDPAddr).Port)
	deniedPort := uint16(deniedListener.LocalAddr().(*net.UDPAddr).Port)

	engine := newLinuxEngineForTest(t, map[uint64]string{selectedID: selected})
	initial := engineTestPolicySet(t, selectedID, allowedPort)
	if err := engine.Apply(context.Background(), initial); err != nil {
		t.Fatalf("apply initial policy: %v", err)
	}
	stableMaps := snapshotEngineMaps(engine)
	flowMap := engine.FlowEventsMap()
	reader, err := ringbuf.NewReader(flowMap)
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDPSendHelperInCgroup(t, selected, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event := readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, selectedID)
	assertEngineUDPDelivery(t, allowedListener, true)

	runUDPSendHelperInCgroup(t, selected, fmt.Sprintf("127.0.0.1:%d", deniedPort))
	event = readFlowEvent(t, reader, deniedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, selectedID)
	assertEngineUDPDelivery(t, deniedListener, false)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonRule, flow.DirectionEgress, flow.ActionAllowed, 1)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonDefaultDeny, flow.DirectionEgress, flow.ActionBlocked, 1)

	// Descendants inherit both the program and the selected attachment identity.
	runUDPSendHelperInCgroup(t, selectedChild, fmt.Sprintf("127.0.0.1:%d", deniedPort))
	event = readFlowEvent(t, reader, deniedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, selectedID)
	assertEngineUDPDelivery(t, deniedListener, false)

	// A sibling outside the selected attachment remains unselected.
	runUDPSendHelperInCgroup(t, unselected, fmt.Sprintf("127.0.0.1:%d", deniedPort))
	assertEngineUDPDelivery(t, deniedListener, true)

	// Ingress is not isolated by the egress-only candidate.
	ingressPort := reserveUDPPort(t)
	if !runUDPReceiveHelperInCgroup(t, selected, int(ingressPort)) {
		t.Fatal("egress-only subject did not receive an ingress datagram")
	}
	event = readFlowEvent(t, reader, uint16(ingressPort), flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonUnisolated, 1, selectedID)

	// A quarantined direction blocks an ordinary matching rule.
	quarantined := engineTestPolicySet(t, selectedID, allowedPort)
	quarantined.Subjects[0].Quarantined = policy.DirectionEgress
	if err := engine.Apply(context.Background(), quarantined); err != nil {
		t.Fatalf("apply quarantine candidate: %v", err)
	}
	assertEngineMapsStable(t, engine, stableMaps)
	if engine.FlowEventsMap() != flowMap {
		t.Fatal("flow ring map changed across policy updates")
	}
	runUDPSendHelperInCgroup(t, selected, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event = readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonQuarantine, 2, selectedID)
	assertEngineUDPDelivery(t, allowedListener, false)

	// Documented bypasses stay available even when the direction is quarantined.
	nodeBypass := compileEngineTestPolicySet(t, []uint64{selectedID}, []string{"Egress"}, []uint16{allowedPort}, nil,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	nodeBypass.Subjects[0].Quarantined = policy.DirectionEgress
	if err := engine.Apply(context.Background(), nodeBypass); err != nil {
		t.Fatalf("apply Node bypass candidate: %v", err)
	}
	assertEngineMapsStable(t, engine, stableMaps)
	runUDPSendHelperInCgroup(t, selected, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event = readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonNodeBypass, 3, selectedID)
	assertEngineUDPDelivery(t, allowedListener, true)

	selfBypass := compileEngineTestPolicySet(t, []uint64{selectedID}, []string{"Egress"}, []uint16{allowedPort}, nil, nil,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	selfBypass.Subjects[0].Quarantined = policy.DirectionEgress
	if err := engine.Apply(context.Background(), selfBypass); err != nil {
		t.Fatalf("apply self-bypass candidate: %v", err)
	}
	assertEngineMapsStable(t, engine, stableMaps)
	runUDPSendHelperInCgroup(t, selected, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event = readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonSelfBypass, 4, selectedID)
	assertEngineUDPDelivery(t, allowedListener, true)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonRule, flow.DirectionEgress, flow.ActionAllowed, 1)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonDefaultDeny, flow.DirectionEgress, flow.ActionBlocked, 1)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonQuarantine, flow.DirectionEgress, flow.ActionBlocked, 1)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonNodeBypass, flow.DirectionEgress, flow.ActionAllowed, 1)
	assertEngineDecisionCountAtLeast(t, engine.DecisionCountsMap(), flow.ReasonSelfBypass, flow.DirectionEgress, flow.ActionAllowed, 1)
}

func TestLinuxEnginePolicyDeletionRemovesSelectedContribution(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	allowedListener := listenEngineTestUDP(t)
	deletedListener := listenEngineTestUDP(t)
	allowedPort := uint16(allowedListener.LocalAddr().(*net.UDPAddr).Port)
	deletedPort := uint16(deletedListener.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, allowedPort)); err != nil {
		t.Fatalf("apply selected policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", allowedPort))
	event := readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)
	assertEngineUDPDelivery(t, allowedListener, true)

	// An empty policy set is the engine-level representation of deleting the
	// last policy selecting this cgroup. It must clear both the active slot's
	// contents and the process-owned cgroup attachment before the next epoch.
	if err := engine.Apply(context.Background(), policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}); err != nil {
		t.Fatalf("apply policy deletion: %v", err)
	}
	if len(engine.links) != 0 {
		t.Fatalf("policy deletion retained %d active cgroup links", len(engine.links))
	}
	if len(engine.orphanLinks) != 0 {
		t.Fatalf("policy deletion retained orphan cgroup links: %#v", engine.orphanLinks)
	}
	activeSlot := engine.engineCore.active.Slot
	retiredSlot := activeSlot ^ 1
	assertEnginePolicySlotEmpty(t, engine, activeSlot)
	assertEngineSlotEmpty(t, engine, retiredSlot)
	wantNode := nodeBypassKey{Slot: activeSlot, Address: [4]byte{127, 0, 0, 1}}
	var nodeKey nodeBypassKey
	var nodeValue uint8
	iter := engine.store.maps["node_bypass"].Iterate()
	var activeNodeEntries int
	for iter.Next(&nodeKey, &nodeValue) {
		if nodeKey.Slot != activeSlot {
			continue
		}
		if nodeKey != wantNode {
			t.Fatalf("policy deletion retained unexpected active node bypass: %+v", nodeKey)
		}
		activeNodeEntries++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate active node bypass entries: %v", err)
	}
	if activeNodeEntries != 1 {
		t.Fatalf("active node bypass entries = %d, want exactly the configured node IP", activeNodeEntries)
	}

	// With the attachment removed, traffic to a port that was never allowed by
	// the deleted policy is no longer subject to that policy's default deny.
	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", deletedPort))
	assertEngineUDPDelivery(t, deletedListener, true)
}

func TestLinuxEnginePolicyDeletionPreservesRemainingContribution(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	retainedListener := listenEngineTestUDP(t)
	deletedListener := listenEngineTestUDP(t)
	retainedPort := uint16(retainedListener.LocalAddr().(*net.UDPAddr).Port)
	deletedPort := uint16(deletedListener.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	combined := compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Egress"},
		[]uint16{retainedPort, deletedPort}, nil, nil, nil)
	if err := engine.Apply(context.Background(), combined); err != nil {
		t.Fatalf("apply combined policy contributions: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", retainedPort))
	event := readFlowEvent(t, reader, retainedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)
	assertEngineUDPDelivery(t, retainedListener, true)

	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", deletedPort))
	event = readFlowEvent(t, reader, deletedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)
	assertEngineUDPDelivery(t, deletedListener, true)

	remaining := compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Egress"},
		[]uint16{retainedPort}, nil, nil, nil)
	if err := engine.Apply(context.Background(), remaining); err != nil {
		t.Fatalf("apply policy after deleting one contribution: %v", err)
	}
	if len(engine.links) != 1 {
		t.Fatalf("remaining policy retained %d active cgroup links, want 1", len(engine.links))
	}
	if len(engine.orphanLinks) != 0 {
		t.Fatalf("remaining policy left orphan links: %#v", engine.orphanLinks)
	}

	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", retainedPort))
	event = readFlowEvent(t, reader, retainedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 2, cgroupID)
	assertEngineUDPDelivery(t, retainedListener, true)

	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", deletedPort))
	event = readFlowEvent(t, reader, deletedPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 2, cgroupID)
	assertEngineUDPDelivery(t, deletedListener, false)
}

func TestLinuxEngineIngressDirectionSpecificDeny(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	descendant := createSubCgroup(t, cgroup, "selected-child")
	cgroupID := mustCgroupID(t, cgroup)
	allowedPort := uint16(reserveUDPPort(t))
	deniedPort := uint16(reserveUDPPort(t))
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	set := engineIngressPolicySet(t, cgroupID, allowedPort)
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply ingress policy: %v", err)
	}
	if got := set.Subjects[0].Isolated; got != policy.DirectionIngress {
		t.Fatalf("compiled isolation mask = %d, want ingress only", got)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	if !runUDPReceiveHelperInCgroup(t, cgroup, int(allowedPort)) {
		t.Fatal("ingress rule did not deliver the allowed datagram")
	}
	event := readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)

	if runUDPReceiveHelperInCgroup(t, cgroup, int(deniedPort)) {
		t.Fatal("ingress default-deny rule delivered an unlisted datagram")
	}
	event = readFlowEvent(t, reader, deniedPort, flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, cgroupID)

	if !runUDPReceiveHelperInCgroup(t, descendant, int(allowedPort)) {
		t.Fatal("descendant ingress rule did not deliver the allowed datagram")
	}
	event = readFlowEvent(t, reader, allowedPort, flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)

	if runUDPReceiveHelperInCgroup(t, descendant, int(deniedPort)) {
		t.Fatal("descendant ingress default-deny rule delivered an unlisted datagram")
	}
	event = readFlowEvent(t, reader, deniedPort, flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, cgroupID)
}

func TestLinuxEngineRejectsIPv6ForIsolatedSubject(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	port := reserveUDPPort(t)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, uint16(port))); err != nil {
		t.Fatalf("apply IPv4-only policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	// The native engine deliberately returns the IPv6 decision before parsing
	// transport headers, so the versioned event carries a zero destination port.
	runUDP6SendHelperInCgroup(t, cgroup, fmt.Sprintf("[::1]:%d", port))
	event := readFlowEvent(t, reader, 0, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if event.Family != 6 {
		t.Fatalf("IPv6 event family = %d, want 6", event.Family)
	}
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonIPv6, 1, cgroupID)
}

func TestLinuxEngineRejectsUnsupportedProtocolBeforeNodeAndSelfBypass(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	set := compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Egress"}, nil, nil,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply unsupported-protocol policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runICMPSendHelperInCgroup(t, cgroup, "127.0.0.1")
	event := readFlowEvent(t, reader, 0, flow.ProtocolICMP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonUnsupported, 1, cgroupID)
}

func TestLinuxEngineRejectsUnsupportedProtocolOnIngress(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	port := uint16(reserveUDPPort(t))
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	set := compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Ingress"}, nil, nil,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply ingress unsupported-protocol policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	if runRawIPv4IngressHelperInCgroup(t, cgroup, port, "unsupported") {
		t.Fatal("isolated ingress raw socket received unsupported traffic")
	}
	event := readFlowEvent(t, reader, 0, flow.ProtocolICMP, flow.DirectionIngress, 2*time.Second)
	if event.Family != 4 {
		t.Fatalf("unsupported ingress event family = %d, want 4", event.Family)
	}
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonUnsupported, 1, cgroupID)
}

func TestLinuxEngineRejectsIPv4FragmentsForIsolatedSubject(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, 80)); err != nil {
		t.Fatalf("apply IPv4-only policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runRawIPv4SendHelperInCgroup(t, cgroup, "fragment")
	event := readFlowEvent(t, reader, 0, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	if event.Family != 4 {
		t.Fatalf("fragment event family = %d, want 4", event.Family)
	}
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonFragment, 1, cgroupID)
}

func TestLinuxEngineRejectsMalformedIPv4ForIsolatedSubject(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, 80)); err != nil {
		t.Fatalf("apply IPv4-only policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	runRawIPv4SendHelperInCgroup(t, cgroup, "malformed")
	event := readFlowEvent(t, reader, 0, 0, flow.DirectionEgress, 2*time.Second)
	if event.Family != 0 || event.Protocol != 0 {
		t.Fatalf("malformed event retained packet metadata: family=%d protocol=%d", event.Family, event.Protocol)
	}
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonMalformed, 1, cgroupID)
}

func TestLinuxEngineFlowEventRateLimitPersistsAcrossPolicyEpochs(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	listener := listenEngineTestUDP(t)
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	set := engineTestPolicySet(t, cgroupID, port)
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply initial policy: %v", err)
	}

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("read possible CPU count: %v", err)
	}
	now, err := monotonicNowNS()
	if err != nil {
		t.Fatalf("read monotonic clock: %v", err)
	}
	limiters := make([]bpfEventLimiterValue, possibleCPUs)
	for i := range limiters {
		limiters[i] = bpfEventLimiterValue{WindowStartNS: now, Emitted: 100}
	}
	zero := uint32(0)
	if err := engine.store.maps["event_limiter"].Update(&zero, limiters, ebpf.UpdateAny); err != nil {
		t.Fatalf("prime flow event limiter: %v", err)
	}

	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply second policy epoch: %v", err)
	}
	var persisted []bpfEventLimiterValue
	if err := engine.store.maps["event_limiter"].Lookup(&zero, &persisted); err != nil {
		t.Fatalf("read flow event limiter after policy update: %v", err)
	}
	if len(persisted) != len(limiters) {
		t.Fatalf("flow event limiter CPU count = %d, want %d", len(persisted), len(limiters))
	}
	for i := range persisted {
		if persisted[i].WindowStartNS != now || persisted[i].Emitted != 100 {
			t.Fatalf("flow event limiter CPU %d changed across policy update: %+v", i, persisted[i])
		}
	}

	now, err = monotonicNowNS()
	if err != nil {
		t.Fatalf("refresh monotonic clock: %v", err)
	}
	for i := range limiters {
		limiters[i].WindowStartNS = now
	}
	if err := engine.store.maps["event_limiter"].Update(&zero, limiters, ebpf.UpdateAny); err != nil {
		t.Fatalf("refresh flow event limiter window: %v", err)
	}
	runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", port))
	assertEngineUDPDelivery(t, listener, true)
	assertEngineEventDropCountAtLeast(t, engine.EventDropsMap(), 0, 1)
	assertEngineEpochEventDropCountAtLeast(t, engine.EpochEventDropsMap(), 2, 0, 1)
}

func TestLinuxEngineAllowsReplyTrafficWithinPolicyEpoch(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	server := listenEngineTestUDP(t)
	serverPort := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineReplyPolicySet(t, cgroupID, serverPort)); err != nil {
		t.Fatalf("apply request policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	child, statusReader := startUDPRequestReplyHelper(t, cgroup, fmt.Sprintf("127.0.0.1:%d", serverPort))
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		_ = statusReader.Close()
	}()
	event := readFlowEvent(t, reader, serverPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set server read deadline: %v", err)
	}
	_, client, err := server.ReadFromUDP(make([]byte, 16))
	if err != nil {
		t.Fatalf("receive UDP request: %v", err)
	}
	if _, err := server.WriteToUDP([]byte("reply"), client); err != nil {
		t.Fatalf("send UDP reply: %v", err)
	}
	event = readFlowEvent(t, reader, uint16(client.Port), flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonConnection, 1, cgroupID)
	if got := readEngineReplyResult(t, statusReader); got != '1' {
		t.Fatalf("helper did not receive allowed reply: status %q", got)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("reply helper failed: %v", err)
	}
}

func TestLinuxEngineAllowsTCPReplyTrafficWithoutReverseRule(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	server := listenEngineTestTCP(t)
	serverPort := uint16(server.Addr().(*net.TCPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	if err := engine.Apply(context.Background(), engineTCPReplyPolicySet(t, cgroupID, serverPort)); err != nil {
		t.Fatalf("apply TCP request policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	child, statusReader := startTCPRequestReplyHelper(t, cgroup, fmt.Sprintf("127.0.0.1:%d", serverPort))
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		_ = statusReader.Close()
	}()
	event := readFlowEvent(t, reader, serverPort, flow.ProtocolTCP, flow.DirectionEgress, 3*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)

	if err := server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set TCP server deadline: %v", err)
	}
	connection, err := server.AcceptTCP()
	if err != nil {
		t.Fatalf("accept TCP request: %v", err)
	}
	defer connection.Close()
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(connection, request); err != nil {
		t.Fatalf("read TCP request: %v", err)
	}
	if string(request) != "request" {
		t.Fatalf("TCP request = %q, want request", request)
	}
	if _, err := connection.Write([]byte("reply!")); err != nil {
		t.Fatalf("write TCP reply: %v", err)
	}
	clientPort := uint16(connection.RemoteAddr().(*net.TCPAddr).Port)
	event = readFlowEvent(t, reader, clientPort, flow.ProtocolTCP, flow.DirectionIngress, 3*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonConnection, 1, cgroupID)
	if got := readEngineReplyResult(t, statusReader); got != '1' {
		t.Fatalf("TCP reply helper did not receive the response: status %q", got)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("TCP reply helper failed: %v", err)
	}
}

func TestLinuxEngineReplyStateExpiresAcrossReusedSlot(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	server := listenEngineTestUDP(t)
	serverPort := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	set := engineReplyPolicySet(t, cgroupID, serverPort)
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply initial policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	child, statusReader := startUDPRequestReplyHelper(t, cgroup, fmt.Sprintf("127.0.0.1:%d", serverPort))
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		_ = statusReader.Close()
	}()
	event := readFlowEvent(t, reader, serverPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)

	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 8)
	_, client, err := server.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("receive initial request: %v", err)
	}

	// Two complete updates cycle the active slot 1 -> 0 -> 1. The reply-state
	// entry remains physically present under epoch 1 but cannot match epoch 3.
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply epoch 2: %v", err)
	}
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatalf("apply epoch 3: %v", err)
	}
	if active := engine.engineCore.active; active != (activeConfiguration{Slot: 1, PolicyEpoch: 3}) {
		t.Fatalf("active config after slot reuse = %+v", active)
	}
	if !engineHasConnectionEpoch(engine, 1) {
		t.Fatal("expected old epoch-1 reply state to remain in the LRU map")
	}

	if _, err := server.WriteToUDP([]byte("reply"), client); err != nil {
		t.Fatalf("send delayed reply: %v", err)
	}
	reply := readFlowEvent(t, reader, uint16(client.Port), flow.ProtocolUDP, flow.DirectionIngress, 2*time.Second)
	assertEngineDecision(t, reply, flow.ActionBlocked, flow.ReasonDefaultDeny, 3, cgroupID)
	if got := readEngineReplyResult(t, statusReader); got != '0' {
		t.Fatalf("helper received stale reply after slot reuse: status %q", got)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("reply helper failed: %v", err)
	}
}

func TestLinuxEngineConcurrentTrafficSeesCompletePolicyEpoch(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	listenerA := listenEngineTestUDP(t)
	listenerB := listenEngineTestUDP(t)
	portA := uint16(listenerA.LocalAddr().(*net.UDPAddr).Port)
	portB := uint16(listenerB.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
	policyA := engineTestPolicySet(t, cgroupID, portA)
	policyB := engineTestPolicySet(t, cgroupID, portB)
	if err := engine.Apply(context.Background(), policyA); err != nil {
		t.Fatalf("apply initial policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	events := make(chan engineFlipObservation, 10_000)
	readerErrors := make(chan error, 1)
	go func() {
		defer close(events)
		for {
			record, err := reader.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					readerErrors <- err
				}
				return
			}
			observation, ok := parseEngineFlipObservation(record.RawSample)
			if !ok {
				continue
			}
			select {
			case events <- observation:
			default:
			}
		}
	}()
	loopHelper := startUDPLoopHelper(t, cgroup, []string{
		fmt.Sprintf("127.0.0.1:%d", portA),
		fmt.Sprintf("127.0.0.1:%d", portB),
	}, 0)

	// Keep packets flowing while alternating two complete rule sets. Each event
	// carries the epoch selected by the same map-of-maps lookup as the slot, so
	// its result must match exactly one committed snapshot.
	for update := range 10 {
		time.Sleep(30 * time.Millisecond)
		candidate := policyA
		if update%2 == 0 {
			candidate = policyB
		}
		if err := engine.Apply(context.Background(), candidate); err != nil {
			t.Fatalf("apply concurrent candidate %d: %v", update+2, err)
		}
	}
	time.Sleep(30 * time.Millisecond)

	if loopHelper.ProcessState == nil {
		_ = loopHelper.Process.Kill()
		_ = loopHelper.Wait()
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close flow event reader: %v", err)
	}
	observedActions := map[uint16]map[uint8]int{
		portA: {},
		portB: {},
	}
	for event := range events {
		if event.Direction != flow.DirectionEgress || event.SchemaVersion != 1 {
			t.Fatalf("unexpected concurrent decision event: %+v", event)
		}
		if event.PolicyEpoch == 0 || event.PolicyEpoch > 11 {
			t.Fatalf("event reported uncommitted policy epoch %d", event.PolicyEpoch)
		}
		var wantAction uint8
		switch event.DestPort {
		case portA:
			if event.PolicyEpoch%2 == 1 {
				wantAction = flow.ActionAllowed
			} else {
				wantAction = flow.ActionBlocked
			}
		case portB:
			if event.PolicyEpoch%2 == 0 {
				wantAction = flow.ActionAllowed
			} else {
				wantAction = flow.ActionBlocked
			}
		default:
			t.Fatalf("unexpected destination port in event: %+v", event)
		}
		if event.Action != wantAction {
			t.Fatalf("event mixed policy slot and epoch: %+v, want action %d", event, wantAction)
		}
		wantReason := flow.ReasonDefaultDeny
		if wantAction == flow.ActionAllowed {
			wantReason = flow.ReasonRule
		}
		if event.Reason != wantReason {
			t.Fatalf("event reason does not match its policy epoch: %+v, want reason %d", event, wantReason)
		}
		observedActions[event.DestPort][event.Action]++
	}
	for _, port := range []uint16{portA, portB} {
		if observedActions[port][flow.ActionAllowed] == 0 || observedActions[port][flow.ActionBlocked] == 0 {
			t.Fatalf("did not observe both decisions for port %d during policy updates: %v", port, observedActions[port])
		}
	}
	select {
	case err := <-readerErrors:
		t.Fatalf("read flow events during policy updates: %v", err)
	default:
	}
}

type engineFlipObservation struct {
	PolicyEpoch   uint64
	DestPort      uint16
	Direction     uint8
	Action        uint8
	Reason        uint8
	SchemaVersion uint8
}

func parseEngineFlipObservation(data []byte) (engineFlipObservation, bool) {
	if len(data) != 72 || data[65] != 1 {
		return engineFlipObservation{}, false
	}
	return engineFlipObservation{
		PolicyEpoch:   binary.LittleEndian.Uint64(data[8:16]),
		DestPort:      binary.LittleEndian.Uint16(data[58:60]),
		Direction:     data[61],
		Action:        data[62],
		Reason:        data[63],
		SchemaVersion: data[65],
	}, true
}

func TestLinuxEngineRealCandidateAttachFailurePreservesActivePolicy(t *testing.T) {
	requireLinuxEBPFRoot(t)

	parent := createTestCgroup(t)
	activeCgroup := createSubCgroup(t, parent, "active")
	candidateCgroup := createSubCgroup(t, parent, "candidate")
	activeID := mustCgroupID(t, activeCgroup)
	candidateID := mustCgroupID(t, candidateCgroup)
	activeListener := listenEngineTestUDP(t)
	candidateListener := listenEngineTestUDP(t)
	activePort := uint16(activeListener.LocalAddr().(*net.UDPAddr).Port)
	candidatePort := uint16(candidateListener.LocalAddr().(*net.UDPAddr).Port)
	engine := newLinuxEngineForTest(t, map[uint64]string{activeID: activeCgroup, candidateID: candidateCgroup})
	if err := engine.Apply(context.Background(), engineTestPolicySet(t, activeID, activePort)); err != nil {
		t.Fatalf("apply active policy: %v", err)
	}
	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow event reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	injectedErr := errors.New("injected candidate link failure")
	engine.engineCore.linker = failingEngineSubjectLinker{cgroupID: candidateID, err: injectedErr}
	candidate := compileEngineTestPolicySet(t, []uint64{activeID, candidateID}, []string{"Egress"}, []uint16{candidatePort}, nil, nil, nil)
	if err := engine.Apply(context.Background(), candidate); !errors.Is(err, injectedErr) {
		t.Fatalf("candidate apply error = %v, want injected link failure", err)
	}
	if got, want := engine.engineCore.active, (activeConfiguration{Slot: 1, PolicyEpoch: 1}); got != want {
		t.Fatalf("active configuration after failure = %+v, want %+v", got, want)
	}
	if engine.store.slotCounts[0] != (slotMapCounts{}) {
		t.Fatalf("failed candidate slot was not cleared: %+v", engine.store.slotCounts[0])
	}
	assertEngineSlotEmpty(t, engine, 0)

	runUDPSendHelperInCgroup(t, activeCgroup, fmt.Sprintf("127.0.0.1:%d", activePort))
	event := readFlowEvent(t, reader, activePort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, activeID)
	assertEngineUDPDelivery(t, activeListener, true)

	runUDPSendHelperInCgroup(t, activeCgroup, fmt.Sprintf("127.0.0.1:%d", candidatePort))
	event = readFlowEvent(t, reader, candidatePort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
	assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, activeID)
	assertEngineUDPDelivery(t, candidateListener, false)
}

func TestLinuxEngineKernelMapWriteFailurePreservesActivePackets(t *testing.T) {
	requireLinuxEBPFRoot(t)

	for _, tc := range []struct {
		name    string
		mapName string
	}{
		{name: "candidate population", mapName: "subject_state"},
		{name: "configuration flip", mapName: "active_config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cgroup := createTestCgroup(t)
			cgroupID := mustCgroupID(t, cgroup)
			oldListener := listenEngineTestUDP(t)
			newListener := listenEngineTestUDP(t)
			oldPort := uint16(oldListener.LocalAddr().(*net.UDPAddr).Port)
			newPort := uint16(newListener.LocalAddr().(*net.UDPAddr).Port)
			engine := newLinuxEngineForTest(t, map[uint64]string{cgroupID: cgroup})
			if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, oldPort)); err != nil {
				t.Fatalf("apply active policy: %v", err)
			}
			reader, err := ringbuf.NewReader(engine.FlowEventsMap())
			if err != nil {
				t.Fatalf("create flow event reader: %v", err)
			}
			t.Cleanup(func() { _ = reader.Close() })

			// Freeze a real kernel map so the next update fails at the intended
			// syscall, rather than at a fake-store boundary.
			if err := engine.store.maps[tc.mapName].Freeze(); err != nil {
				t.Fatalf("freeze %s map: %v", tc.mapName, err)
			}
			if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, newPort)); !errors.Is(err, unix.EPERM) {
				t.Fatalf("candidate map write error = %v, want EPERM from frozen %s map", err, tc.mapName)
			}
			if got, want := engine.active, (activeConfiguration{Slot: 1, PolicyEpoch: 1}); got != want {
				t.Fatalf("active configuration after failed map write = %+v, want %+v", got, want)
			}
			assertEngineSlotEmpty(t, engine, 0)

			runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", oldPort))
			event := readFlowEvent(t, reader, oldPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
			assertEngineDecision(t, event, flow.ActionAllowed, flow.ReasonRule, 1, cgroupID)
			assertEngineUDPDelivery(t, oldListener, true)

			runUDPSendHelperInCgroup(t, cgroup, fmt.Sprintf("127.0.0.1:%d", newPort))
			event = readFlowEvent(t, reader, newPort, flow.ProtocolUDP, flow.DirectionEgress, 2*time.Second)
			assertEngineDecision(t, event, flow.ActionBlocked, flow.ReasonDefaultDeny, 1, cgroupID)
			assertEngineUDPDelivery(t, newListener, false)
		})
	}
}

func TestLinuxEngineRetiredSlotQuiescenceIgnoresCurrentTraffic(t *testing.T) {
	requireLinuxEBPFRoot(t)

	engine := newLinuxEngineForTest(t, nil)
	if err := engine.Apply(context.Background(), policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}); err != nil {
		t.Fatalf("activate slot 1: %v", err)
	}
	counterMap := engine.store.maps["in_flight"]
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("read possible CPU count: %v", err)
	}
	busy := make([]uint64, possibleCPUs)
	busy[0] = 1
	currentSlot := uint32(1)
	retiredSlot := uint32(0)
	if err := counterMap.Put(&currentSlot, busy); err != nil {
		t.Fatalf("mark current slot busy: %v", err)
	}
	if err := engine.store.WaitQuiescent(context.Background(), retiredSlot); err != nil {
		t.Fatalf("retired slot must not wait for current traffic: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := engine.store.WaitQuiescent(ctx, currentSlot); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy current slot wait = %v, want context deadline", err)
	}
}

func TestLinuxEngineRepeatedApplyCloseReleasesOwnedResources(t *testing.T) {
	requireLinuxEBPFRoot(t)

	cgroup := createTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroup)
	paths := map[uint64]string{cgroupID: cgroup}
	for cycle := range 3 {
		engine := newLinuxEngineForTest(t, paths)
		stableMaps := snapshotEngineMaps(engine)
		for update := range 6 {
			port := uint16(10_000 + cycle*10 + update)
			if err := engine.Apply(context.Background(), engineTestPolicySet(t, cgroupID, port)); err != nil {
				t.Fatalf("cycle %d apply %d: %v", cycle, update, err)
			}
			assertEngineMapsStable(t, engine, stableMaps)
			assertEngineSlotEmpty(t, engine, 1-engine.engineCore.active.Slot)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", cycle, err)
		}
		if len(engine.links) != 0 || len(engine.orphanLinks) != 0 || engine.store.collection != nil || engine.store.activeConfigMap != nil {
			t.Fatalf("cycle %d retained engine resources: links=%d orphans=%d collection=%v active_config=%v",
				cycle, len(engine.links), len(engine.orphanLinks), engine.store.collection != nil, engine.store.activeConfigMap != nil)
		}
		for _, pin := range []string{engine.store.flowEventsPin, engine.store.agentStatusPin} {
			if _, err := os.Lstat(pin); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cycle %d left engine pin %q: %v", cycle, pin, err)
			}
		}
	}
}

func requireLinuxEBPFRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges; re-run with sudo or CAP_BPF + CAP_NET_ADMIN")
	}
}

func TestCgroupUDPRequestReplyHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_REPLY_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	start := os.NewFile(uintptr(3), "start")
	status := os.NewFile(uintptr(4), "status")
	if start == nil || status == nil {
		t.Fatal("helper pipes are missing")
	}
	defer start.Close()
	defer status.Close()
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatalf("start signal: %v", err)
	}
	conn, err := net.DialTimeout("udp4", addr, time.Second)
	if err != nil {
		t.Fatalf("dial UDP server: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("send UDP request: %v", err)
	}
	if _, err := status.Write([]byte{'r'}); err != nil {
		t.Fatalf("signal request sent: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = conn.Read(make([]byte, 16))
	if err == nil {
		_, _ = status.Write([]byte{'1'})
		return
	}
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		t.Fatalf("read UDP reply: %v", err)
	}
	if _, err := status.Write([]byte{'0'}); err != nil {
		t.Fatalf("signal reply timeout: %v", err)
	}
}

func TestCgroupTCPRequestReplyHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_TCP_REPLY_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_TCP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_TCP_ADDR not set")
	}
	start := os.NewFile(uintptr(3), "start")
	status := os.NewFile(uintptr(4), "status")
	if start == nil || status == nil {
		t.Fatal("helper pipes are missing")
	}
	defer start.Close()
	defer status.Close()
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatalf("wait for helper start: %v", err)
	}
	connection, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		_, _ = status.Write([]byte{'e'})
		t.Fatalf("dial TCP server: %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("request")); err != nil {
		t.Fatalf("send TCP request: %v", err)
	}
	if _, err := status.Write([]byte{'r'}); err != nil {
		t.Fatalf("signal TCP request sent: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
	response := make([]byte, len("reply!"))
	if _, err := io.ReadFull(connection, response); err != nil {
		_, _ = status.Write([]byte{'0'})
		t.Fatalf("read TCP reply: %v", err)
	}
	if string(response) != "reply!" {
		t.Fatalf("TCP reply = %q, want reply!", response)
	}
	if _, err := status.Write([]byte{'1'}); err != nil {
		t.Fatalf("signal TCP reply received: %v", err)
	}
}

func TestCgroupUDPLoopHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_LOOP_HELPER") != "1" {
		t.Skip("helper")
	}
	addresses := strings.Split(os.Getenv("ZTAP_UDP_ADDRS"), ",")
	if len(addresses) < 2 || addresses[0] == "" || addresses[1] == "" {
		t.Fatal("at least two UDP destinations are required")
	}
	packetsPerSecond := 0
	if value := os.Getenv("ZTAP_CGROUP_LOOP_PACKETS_PER_SECOND"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid UDP loop packets-per-second value %q", value)
		}
		packetsPerSecond = parsed
	}
	start := os.NewFile(uintptr(3), "start")
	if start == nil {
		t.Fatal("helper start pipe is missing")
	}
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatalf("wait for helper start: %v", err)
	}
	_ = start.Close()

	connections := make([]net.Conn, 0, len(addresses))
	for _, address := range addresses {
		connection, err := net.DialTimeout("udp4", address, time.Second)
		if err != nil {
			t.Fatalf("dial UDP destination %q: %v", address, err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	if packetsPerSecond > 0 {
		interval := time.Second / time.Duration(packetsPerSecond)
		if interval <= 0 {
			t.Fatalf("UDP loop interval is not positive for %d packets/second", packetsPerSecond)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		connectionIndex := 0
		for range ticker.C {
			_, _ = connections[connectionIndex].Write([]byte("flip"))
			connectionIndex = (connectionIndex + 1) % len(connections)
		}
	}
	for {
		for _, connection := range connections {
			_, _ = connection.Write([]byte("flip"))
		}
		time.Sleep(time.Millisecond)
	}
}

func newLinuxEngineForTest(t *testing.T, cgroupPaths map[uint64]string) *LinuxEngine {
	t.Helper()
	engine, err := NewLinuxEngine(context.Background(), LinuxEngineOptions{
		CgroupRoot: "/sys/fs/cgroup",
		BPFFSRoot:  "/sys/fs/bpf",
		ResolveCgroupPath: func(_ context.Context, cgroupID uint64) (string, error) {
			path, ok := cgroupPaths[cgroupID]
			if !ok {
				return "", fmt.Errorf("cgroup %d has no test path", cgroupID)
			}
			return path, nil
		},
		AgentEpoch: 42,
	})
	if err != nil {
		t.Fatalf("create Linux engine: %v", err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close Linux engine: %v", err)
		}
	})
	return engine
}

func startUDPLoopHelper(t *testing.T, cgroup string, addresses []string, packetsPerSecond int) *exec.Cmd {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create loop helper start pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPLoopHelper$")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_LOOP_HELPER=1", "ZTAP_UDP_ADDRS="+strings.Join(addresses, ","))
	if packetsPerSecond > 0 {
		cmd.Env = append(cmd.Env, "ZTAP_CGROUP_LOOP_PACKETS_PER_SECOND="+strconv.Itoa(packetsPerSecond))
	}
	cmd.ExtraFiles = []*os.File{startReader}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("start UDP loop helper: %v", err)
	}
	_ = startReader.Close()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = startWriter.Close()
	})
	moveProcessToCgroup(t, cmd, cgroup)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		t.Fatalf("release UDP loop helper: %v", err)
	}
	if err := startWriter.Close(); err != nil {
		t.Fatalf("close UDP loop helper start pipe: %v", err)
	}
	return cmd
}

func engineTestPolicySet(t *testing.T, cgroupID uint64, allowPort uint16) policy.PolicySet {
	t.Helper()
	return compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Egress"}, []uint16{allowPort}, nil, nil, nil)
}

func engineReplyPolicySet(t *testing.T, cgroupID uint64, serverPort uint16) policy.PolicySet {
	t.Helper()
	return compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Ingress", "Egress"}, []uint16{serverPort}, nil, nil, nil)
}

func engineTCPReplyPolicySet(t *testing.T, cgroupID uint64, serverPort uint16) policy.PolicySet {
	t.Helper()
	return compileEngineTestPolicySetWithProtocol(t, []uint64{cgroupID}, []string{"Ingress", "Egress"}, []uint16{serverPort}, nil, "TCP", nil, nil)
}

func engineIngressPolicySet(t *testing.T, cgroupID uint64, allowedPort uint16) policy.PolicySet {
	t.Helper()
	return compileEngineTestPolicySet(t, []uint64{cgroupID}, []string{"Ingress"}, nil, []uint16{allowedPort}, nil, nil)
}

func compileEngineTestPolicySet(
	t *testing.T,
	cgroupIDs []uint64,
	policyTypes []string,
	egressPorts []uint16,
	ingressPorts []uint16,
	nodeIPs []netip.Addr,
	selfIPs []netip.Addr,
) policy.PolicySet {
	return compileEngineTestPolicySetWithProtocol(t, cgroupIDs, policyTypes, egressPorts, ingressPorts, "UDP", nodeIPs, selfIPs)
}

func compileEngineTestPolicySetWithProtocol(
	t *testing.T,
	cgroupIDs []uint64,
	policyTypes []string,
	egressPorts []uint16,
	ingressPorts []uint16,
	protocol string,
	nodeIPs []netip.Addr,
	selfIPs []netip.Addr,
) policy.PolicySet {
	t.Helper()
	if nodeIPs == nil {
		nodeIPs = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	}
	if selfIPs == nil {
		selfIPs = make([]netip.Addr, len(cgroupIDs))
		for i := range cgroupIDs {
			selfIPs[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 2)})
		}
	}
	if len(selfIPs) != len(cgroupIDs) {
		t.Fatalf("self IP count = %d, want one per cgroup (%d)", len(selfIPs), len(cgroupIDs))
	}

	native := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata:   &policy.NativeObjectMeta{Name: "engine-test", Namespace: "default"},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{MatchLabels: map[string]string{"app": "engine-test"}},
			PolicyTypes: &policyTypes,
		},
	}
	if len(egressPorts) != 0 {
		rule := policy.NativeEgressRule{To: []policy.NativePeer{{IPBlock: &policy.NativeIPBlock{CIDR: "127.0.0.0/8"}}}}
		for _, port := range egressPorts {
			rule.Ports = append(rule.Ports, policy.NativePort{Protocol: protocol, Port: int(port)})
		}
		native.Spec.Egress = append(native.Spec.Egress, rule)
	}
	if len(ingressPorts) != 0 {
		rule := policy.NativeIngressRule{From: []policy.NativePeer{{IPBlock: &policy.NativeIPBlock{CIDR: "127.0.0.0/8"}}}}
		for _, port := range ingressPorts {
			rule.Ports = append(rule.Ports, policy.NativePort{Protocol: protocol, Port: int(port)})
		}
		native.Spec.Ingress = append(native.Spec.Ingress, rule)
	}
	if err := policy.ValidateNativePolicies([]policy.NativeNetworkPolicy{native}); err != nil {
		t.Fatalf("validate native engine-test policy: %v", err)
	}

	pods := make([]policy.ResolvedPod, 0, len(cgroupIDs))
	for i, cgroupID := range cgroupIDs {
		pods = append(pods, policy.ResolvedPod{
			Namespace: "default",
			Name:      fmt.Sprintf("engine-subject-%d", i),
			Labels:    map[string]string{"app": "engine-test"},
			PodIPs:    []netip.Addr{selfIPs[i]},
			CgroupIDs: []uint64{cgroupID},
			Local:     true,
		})
	}
	result, err := policy.CompileNativePolicies([]policy.NativeNetworkPolicy{native}, policy.ResolutionInput{
		NodeIPs:    nodeIPs,
		Namespaces: []policy.ResolvedNamespace{{Name: "default", Labels: map[string]string{}}},
		Pods:       pods,
	})
	if err != nil {
		t.Fatalf("compile native engine-test policy: %v", err)
	}
	if len(result.Rejected) != 0 {
		t.Fatalf("native engine-test policy was rejected: %#v", result.Rejected)
	}
	return result.PolicySet
}

type namedEngineMap struct {
	name string
	mapP *ebpf.Map
}

func snapshotEngineMaps(engine *LinuxEngine) []namedEngineMap {
	return []namedEngineMap{
		{name: "flow_events", mapP: engine.FlowEventsMap()},
		{name: "decision_counts", mapP: engine.DecisionCountsMap()},
		{name: "decision_epoch_counts", mapP: engine.EpochDecisionCountsMap()},
		{name: "event_drops", mapP: engine.EventDropsMap()},
		{name: "event_drop_epoch_counts", mapP: engine.EpochEventDropsMap()},
		{name: "agent_status", mapP: engine.AgentStatusMap()},
	}
}

func assertEngineMapsStable(t *testing.T, engine *LinuxEngine, want []namedEngineMap) {
	t.Helper()
	got := snapshotEngineMaps(engine)
	if len(got) != len(want) {
		t.Fatalf("engine map count changed from %d to %d", len(want), len(got))
	}
	for i := range want {
		if got[i].name != want[i].name || got[i].mapP != want[i].mapP {
			t.Fatalf("engine map %q was replaced across policy update", want[i].name)
		}
	}
}

func assertEngineDecisionCountAtLeast(t *testing.T, countsMap *ebpf.Map, reason, direction, action uint8, want uint64) {
	t.Helper()
	key := uint32((uint32(reason)*2+uint32(direction))*2 + uint32(action))
	var perCPU []uint64
	if err := countsMap.Lookup(&key, &perCPU); err != nil {
		t.Fatalf("read decision counter %d: %v", key, err)
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	if total < want {
		t.Fatalf("decision counter %d = %d, want at least %d", key, total, want)
	}
}

func assertEngineEventDropCountAtLeast(t *testing.T, countsMap *ebpf.Map, reason uint32, want uint64) {
	t.Helper()
	var perCPU []uint64
	if err := countsMap.Lookup(&reason, &perCPU); err != nil {
		t.Fatalf("read event drop counter %d: %v", reason, err)
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	if total < want {
		t.Fatalf("event drop counter %d = %d, want at least %d", reason, total, want)
	}
}

func assertEngineEpochEventDropCountAtLeast(t *testing.T, countsMap *ebpf.Map, epoch uint64, reason uint32, want uint64) {
	t.Helper()
	key := bpfEpochEventDropKey{PolicyEpoch: epoch, Reason: reason}
	var perCPU []uint64
	if err := countsMap.Lookup(&key, &perCPU); err != nil {
		t.Fatalf("read epoch %d event drop counter %d: %v", epoch, reason, err)
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	if total < want {
		t.Fatalf("epoch %d event drop counter %d = %d, want at least %d", epoch, reason, total, want)
	}
}

func assertEngineSlotEmpty(t *testing.T, engine *LinuxEngine, slot uint32) {
	t.Helper()
	assertEnginePolicySlotEmpty(t, engine, slot)

	var nodeKey nodeBypassKey
	var nodeValue uint8
	iter := engine.store.maps["node_bypass"].Iterate()
	for iter.Next(&nodeKey, &nodeValue) {
		if nodeKey.Slot == slot {
			t.Fatalf("node_bypass retained slot %d entry: %+v", slot, nodeKey)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate node_bypass: %v", err)
	}
}

func assertEnginePolicySlotEmpty(t *testing.T, engine *LinuxEngine, slot uint32) {
	t.Helper()
	var subjectKey subjectStateKey
	var subjectValue subjectStateValue
	iter := engine.store.maps["subject_state"].Iterate()
	for iter.Next(&subjectKey, &subjectValue) {
		if subjectKey.Slot == slot {
			t.Fatalf("subject_state retained slot %d entry: %+v", slot, subjectKey)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate subject_state: %v", err)
	}

	var selfKey selfBypassKey
	var selfValue uint8
	iter = engine.store.maps["self_bypass"].Iterate()
	for iter.Next(&selfKey, &selfValue) {
		if selfKey.Slot == slot {
			t.Fatalf("self_bypass retained slot %d entry: %+v", slot, selfKey)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate self_bypass: %v", err)
	}

	var ruleKey policyRuleKey
	var ruleValue uint8
	iter = engine.store.maps["policy_rules"].Iterate()
	for iter.Next(&ruleKey, &ruleValue) {
		if ruleKey.Meta>>31 == slot {
			t.Fatalf("policy_rules retained slot %d entry: %+v", slot, ruleKey)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate policy_rules: %v", err)
	}
}

type failingEngineSubjectLinker struct {
	cgroupID uint64
	err      error
}

func (l failingEngineSubjectLinker) Attach(_ context.Context, cgroupID uint64) (io.Closer, error) {
	if cgroupID == l.cgroupID {
		return nil, l.err
	}
	return nil, fmt.Errorf("unexpected attachment request for cgroup %d", cgroupID)
}

func listenEngineTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on loopback UDP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func listenEngineTestTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on loopback TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func assertEngineUDPDelivery(t *testing.T, listener *net.UDPConn, want bool) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set UDP listener deadline: %v", err)
	}
	_, _, err := listener.ReadFromUDP(make([]byte, 32))
	if want && err != nil {
		t.Fatalf("expected UDP datagram to be delivered: %v", err)
	}
	if !want {
		if err == nil {
			t.Fatal("unexpected UDP datagram delivery")
		}
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			t.Fatalf("expected UDP receive timeout, got %v", err)
		}
	}
}

func assertEngineDecision(t *testing.T, event flow.RawFlowEvent, action, reason uint8, epoch, cgroupID uint64) {
	t.Helper()
	if event.SchemaVersion != 1 {
		t.Fatalf("flow event schema = %d, want 1", event.SchemaVersion)
	}
	if event.Action != action || event.Reason != reason || event.PolicyEpoch != epoch || event.CgroupID != cgroupID {
		t.Fatalf("decision event = %+v, want action=%d reason=%d epoch=%d cgroup=%d", event, action, reason, epoch, cgroupID)
	}
}

func engineHasConnectionEpoch(engine *LinuxEngine, epoch uint64) bool {
	iterator := engine.store.maps["conn_state"].Iterate()
	var key bpfConnectionKey
	var expires uint64
	for iterator.Next(&key, &expires) {
		if key.PolicyEpoch == epoch && key.Direction == flow.DirectionIngress {
			return true
		}
	}
	return false
}

func startUDPRequestReplyHelper(t *testing.T, cgroup, addr string) (*exec.Cmd, *os.File) {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create helper start pipe: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("create helper status pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPRequestReplyHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_REPLY_HELPER=1", "ZTAP_UDP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{startReader, statusWriter}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		_ = statusReader.Close()
		_ = statusWriter.Close()
		t.Fatalf("start reply helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = statusReader.Close()
	})
	_ = startReader.Close()
	_ = statusWriter.Close()
	moveProcessToCgroup(t, cmd, cgroup)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release reply helper: %v", err)
	}
	_ = startWriter.Close()
	if got := readEngineReplyResult(t, statusReader); got != 'r' {
		_ = cmd.Process.Kill()
		t.Fatalf("unexpected helper startup status %q", got)
	}
	return cmd, statusReader
}

func startTCPRequestReplyHelper(t *testing.T, cgroup, addr string) (*exec.Cmd, *os.File) {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create TCP helper start pipe: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("create TCP helper status pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupTCPRequestReplyHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_TCP_REPLY_HELPER=1", "ZTAP_TCP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{startReader, statusWriter}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		_ = statusReader.Close()
		_ = statusWriter.Close()
		t.Fatalf("start TCP reply helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = statusReader.Close()
	})
	_ = startReader.Close()
	_ = statusWriter.Close()
	moveProcessToCgroup(t, cmd, cgroup)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release TCP reply helper: %v", err)
	}
	_ = startWriter.Close()
	if got := readEngineReplyResult(t, statusReader); got != 'r' {
		_ = cmd.Process.Kill()
		t.Fatalf("unexpected TCP helper startup status %q", got)
	}
	return cmd, statusReader
}

func readEngineReplyResult(t *testing.T, reader *os.File) byte {
	t.Helper()
	type readResult struct {
		value byte
		err   error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		var result [1]byte
		_, err := io.ReadFull(reader, result[:])
		resultCh <- readResult{value: result[0], err: err}
	}()
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("read helper status: %v", result.err)
		}
		return result.value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading helper status")
	}
	return 0
}

func moveProcessToCgroup(t *testing.T, cmd *exec.Cmd, cgroup string) {
	t.Helper()
	expectedID, err := cgroupInodeID(cgroup)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("inspect cgroup %s: %v", cgroup, err)
	}
	directory, resolved, err := openValidatedCgroup("/sys/fs/cgroup", cgroup, expectedID)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open validated cgroup %s: %v", cgroup, err)
	}
	fd, err := unix.Openat(int(directory.Fd()), "cgroup.procs", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	closeErr := directory.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("open %s/cgroup.procs without following symlinks: %v", resolved, err)
	}
	if closeErr != nil {
		_ = cmd.Process.Kill()
		_ = unix.Close(fd)
		t.Fatalf("close validated cgroup %s: %v", resolved, closeErr)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(resolved, "cgroup.procs"))
	if file == nil {
		_ = cmd.Process.Kill()
		_ = unix.Close(fd)
		t.Fatalf("open %s/cgroup.procs returned no file handle", resolved)
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", cmd.Process.Pid)
	closeErr = file.Close()
	if writeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("move helper into cgroup: %v", writeErr)
	}
	if closeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("close %s/cgroup.procs: %v", resolved, closeErr)
	}
}
