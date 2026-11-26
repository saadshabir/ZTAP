//go:build linux && integration

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/saadshabir/ZTAP/internal/policy"
	"github.com/saadshabir/ZTAP/internal/restartproof"
)

func createEngineTestBPFFSRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ztap-test-%d", time.Now().UnixNano()))
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := RemoveEnforcement(context.Background(), root); err != nil {
			t.Errorf("explicit test enforcement cleanup: %v", err)
			return
		}
		if err := os.Remove(filepath.Join(root, "ztap")); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
		if err := os.Remove(root); err != nil {
			t.Error(err)
		}
	})
	return root
}

func restartProofPolicy(id uint64, ingress, egress uint16) policy.PolicySet {
	return policy.PolicySet{
		NodeIPs:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Subjects: []policy.Subject{{CgroupID: id, Isolated: policy.DirectionIngress | policy.DirectionEgress}},
		Rules: []policy.Rule{
			{CgroupID: id, Direction: policy.DirectionIngress, Protocol: policy.ProtocolUDP, Port: ingress, Peer: netip.MustParsePrefix("127.0.0.1/32")},
			{CgroupID: id, Direction: policy.DirectionEgress, Protocol: policy.ProtocolUDP, Port: egress, Peer: netip.MustParsePrefix("127.0.0.1/32")},
		},
	}
}

func TestLinuxEnginePortRangesSurviveReopen(t *testing.T) {
	requireLinuxEBPFRoot(t)
	cgroup := createTestCgroup(t)
	id := mustCgroupID(t, cgroup)
	options := LinuxEngineOptions{
		BPFFSRoot: createEngineTestBPFFSRoot(t),
		ResolveCgroupPath: func(context.Context, uint64) (string, error) {
			return cgroup, nil
		},
	}
	openEngine := func() *LinuxEngine {
		t.Helper()
		engine, err := NewLinuxEngine(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := engine.Close(); err != nil {
				t.Error(err)
			}
		})
		return engine
	}

	listeners := []*net.UDPConn{listenEngineTestUDP(t), listenEngineTestUDP(t), listenEngineTestUDP(t)}
	port := func(conn *net.UDPConn) int { return conn.LocalAddr().(*net.UDPAddr).Port }
	slices.SortFunc(listeners, func(a, b *net.UDPConn) int { return port(a) - port(b) })
	end, outside := port(listeners[1]), port(listeners[2])
	// Include an aligned block even if the allowed listeners are adjacent.
	start := port(listeners[0]) &^ 3
	peer := policy.NativePeer{IPBlock: &policy.NativeIPBlock{CIDR: "127.0.0.0/8"}}
	portRange := policy.NativePort{Protocol: "UDP", Port: start, EndPort: &end}
	outsideEnd := outside | 1
	otherPeerRange := policy.NativePort{Protocol: "UDP", Port: outside &^ 1, EndPort: &outsideEnd}
	otherProtocolRange := otherPeerRange
	otherProtocolRange.Protocol = "TCP"
	native := policy.NativeNetworkPolicy{
		APIVersion: policy.NativeNetworkPolicyAPIVersion,
		Kind:       policy.NativeNetworkPolicyKind,
		Metadata:   &policy.NativeObjectMeta{Name: "port-range"},
		Spec: &policy.NativeNetworkPolicySpec{
			PodSelector: &policy.NativeLabelSelector{},
			Ingress:     []policy.NativeIngressRule{{From: []policy.NativePeer{peer}, Ports: []policy.NativePort{portRange}}},
			Egress: []policy.NativeEgressRule{
				{To: []policy.NativePeer{peer}, Ports: []policy.NativePort{portRange, otherProtocolRange}},
				{To: []policy.NativePeer{{IPBlock: &policy.NativeIPBlock{CIDR: "192.0.2.0/24"}}}, Ports: []policy.NativePort{otherPeerRange}},
			},
		},
	}
	input := policy.ResolutionInput{
		NodeIPs:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Namespaces: []policy.ResolvedNamespace{{Name: "default"}},
		Pods:       []policy.ResolvedPod{{Namespace: "default", Name: "client", CgroupIDs: []uint64{id}, Local: true}},
	}
	result, err := policy.CompileNativePolicies([]policy.NativeNetworkPolicy{native}, input)
	if err != nil || len(result.Rejected) != 0 {
		t.Fatalf("compile port range: %v, rejected: %+v", err, result.Rejected)
	}
	engine := openEngine()
	if err := engine.Apply(t.Context(), result.PolicySet); err != nil {
		t.Fatal(err)
	}
	for _, listener := range listeners {
		runUDPSendHelperInCgroup(t, cgroup, listener.LocalAddr().String())
		assertEngineUDPDelivery(t, listener, port(listener) <= end)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}

	engine = openEngine()
	epoch := engine.active.PolicyEpoch
	if err := engine.Apply(t.Context(), result.PolicySet); err != nil {
		t.Fatal(err)
	}
	if engine.active.PolicyEpoch != epoch {
		t.Fatal("unchanged range policy advanced the recovered epoch")
	}
	for _, p := range []int{start, end, outside} {
		if delivered := runUDPReceiveHelperInCgroup(t, cgroup, p); delivered != (p <= end) {
			t.Errorf("ingress port %d after reopen: delivered=%t, want %t", p, delivered, p <= end)
		}
	}
}

func compatibleRestartProgramSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := loadEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range spec.Programs {
		// Small nonnegative immediate assignments have the same result in
		// ALU32 and ALU64. Change the tag without moving BTF/branch offsets.
		changed := false
		for index, instruction := range program.Instructions {
			is64 := instruction.OpCode == asm.Mov.Imm(asm.R0, 0).OpCode
			is32 := instruction.OpCode == asm.Mov.Imm32(asm.R0, 0).OpCode
			if (is64 || is32) && instruction.Constant >= 0 && instruction.Constant <= 0x7fffffff {
				replacement := asm.Mov.Imm32(instruction.Dst, int32(instruction.Constant))
				if is32 {
					replacement = asm.Mov.Imm(instruction.Dst, int32(instruction.Constant))
				}
				replacement.Metadata = instruction.Metadata
				program.Instructions[index] = replacement
				changed = true
				break
			}
		}
		if !changed {
			t.Fatal("could not construct a compatible program variant")
		}
	}
	return spec
}

func TestRestartEngineOwnerHelper(t *testing.T) {
	if os.Getenv("ZTAP_RESTART_OWNER_HELPER") != "1" {
		t.Skip("helper")
	}
	root, cgroup := os.Getenv("ZTAP_RESTART_BPFFS"), os.Getenv("ZTAP_RESTART_CGROUP")
	id := mustCgroupID(t, cgroup)
	ingress, err := strconv.ParseUint(os.Getenv("ZTAP_RESTART_INGRESS"), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	egress, err := strconv.ParseUint(os.Getenv("ZTAP_RESTART_EGRESS"), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ready := os.NewFile(3, "engine ready and checkpoint")
	defer func() { _ = ready.Close() }()
	target := os.Getenv("ZTAP_RESTART_CHECKPOINT")
	armed := os.Getenv("ZTAP_RESTART_UPGRADE") == "1"
	retiring := false
	options := LinuxEngineOptions{BPFFSRoot: root, AgentEpoch: 100, ResolveCgroupPath: func(_ context.Context, cgroupID uint64) (string, error) {
		if cgroupID == id {
			return cgroup, nil
		}
		return os.Getenv("ZTAP_RESTART_EXTRA_CGROUP"), nil
	}, ObserveCheckpoint: func(name string) {
		if !armed {
			return
		}
		if name == "retired-slot-cleanup-started" {
			retiring = true
		}
		if name != target || (target == "slot-subjects-cleared" && !retiring) {
			return
		}
		if _, err := ready.Write([]byte{'c'}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		// The parent kills the process; an accidental SIGCONT must not advance
		// the checkpoint and turn this into a fast-recovery measurement.
		select {}
	}}
	var spec *ebpf.CollectionSpec
	if armed {
		spec = compatibleRestartProgramSpec(t)
	}
	engine, err := newPersistentLinuxEngineWithSpec(ctx, options, spec, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	}()
	set := restartProofPolicy(id, uint16(ingress), uint16(egress))
	extra := os.Getenv("ZTAP_RESTART_EXTRA_CGROUP")
	removing := strings.HasPrefix(target, "obsolete-")
	if removing {
		set.Subjects = append(set.Subjects, policy.Subject{CgroupID: mustCgroupID(t, extra), Isolated: policy.DirectionIngress | policy.DirectionEgress})
	}
	if err := engine.Apply(ctx, set); err != nil {
		t.Fatal(err)
	}
	if _, err := ready.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	if target != "" {
		control := os.NewFile(4, "candidate commit request")
		defer func() { _ = control.Close() }()
		if _, err := io.ReadFull(control, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		armed = true
		if removing {
			set.Subjects = set.Subjects[:1]
		} else {
			set.Subjects = append(set.Subjects, policy.Subject{CgroupID: mustCgroupID(t, extra), Isolated: policy.DirectionIngress | policy.DirectionEgress})
		}
		if err := engine.Apply(ctx, set); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("candidate passed requested checkpoint %s", target)
	}
	<-ctx.Done()
}

// The receiving sockets, the sending socket, and reply sockets are all created
// after the helper enters the protected cgroup. The peer process stays outside.
func TestRestartTrafficHelper(t *testing.T) { restartproof.RunHelper(t) }

func TestLinuxPinnedEnforcementSurvivesOwnerLoss(t *testing.T) {
	requireLinuxEBPFRoot(t)
	for _, mode := range []string{"SIGTERM", "SIGKILL", "SIGSTOP",
		"inactive-slot-partial", "inactive-slot-populated", "egress-link-pinned", "ingress-link-pinned",
		"candidate-links-pinned", "active-config-committed", "obsolete-egress-removed",
		"obsolete-ingress-removed", "slot-subjects-cleared", "retired-slot-cleanup-started", "retired-slot-cleared",
		"programs-pinned", "ztap_egress-updated", "ztap_ingress-updated"} {
		t.Run(mode, func(t *testing.T) {
			cgroup := createTestCgroup(t)
			id := mustCgroupID(t, cgroup)
			root := createEngineTestBPFFSRoot(t)
			checkpoint := ""
			upgrade := mode == "programs-pinned" || strings.HasPrefix(mode, "ztap_")
			if !strings.HasPrefix(mode, "SIG") && !upgrade {
				checkpoint = mode
			}
			extra := createTestCgroup(t)
			extraID := mustCgroupID(t, extra)
			traffic := restartproof.Start(t, cgroup, "TestRestartTrafficHelper")
			ports := traffic.Ports

			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			owner := exec.Command(os.Args[0], "-test.run=^TestRestartEngineOwnerHelper$")
			owner.Env = append(os.Environ(), "ZTAP_RESTART_OWNER_HELPER=1", "ZTAP_RESTART_BPFFS="+root, "ZTAP_RESTART_CGROUP="+cgroup, "ZTAP_RESTART_INGRESS="+strconv.Itoa(int(ports.AllowedPort)), "ZTAP_RESTART_EGRESS="+strconv.Itoa(int(traffic.EgressPort())))
			updateRead, updateWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = updateWrite.Close() }()
			owner.Env = append(owner.Env, "ZTAP_RESTART_CHECKPOINT="+checkpoint, "ZTAP_RESTART_EXTRA_CGROUP="+extra)
			owner.ExtraFiles = []*os.File{readyWrite, updateRead}
			owner.Stdout, owner.Stderr = os.Stdout, os.Stderr
			if err := owner.Start(); err != nil {
				t.Fatal(err)
			}
			_ = readyWrite.Close()
			_ = updateRead.Close()
			ownerWaited := false
			defer func() {
				if !ownerWaited {
					_ = owner.Process.Kill()
					_ = owner.Wait()
				}
				_ = readyRead.Close()
			}()
			_ = readyRead.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(readyRead, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			set := restartProofPolicy(id, ports.AllowedPort, traffic.EgressPort())
			expectedEpoch := uint64(1)
			if strings.HasPrefix(mode, "obsolete-") {
				expectedEpoch = 2
			} else if mode == "active-config-committed" || mode == "slot-subjects-cleared" || mode == "retired-slot-cleanup-started" || mode == "retired-slot-cleared" {
				expectedEpoch = 2
				set.Subjects = append(set.Subjects, policy.Subject{CgroupID: extraID, Isolated: policy.DirectionIngress | policy.DirectionEgress})
			}
			statusMap, err := ebpf.LoadPinnedMap(filepath.Join(root, "ztap", engineAgentStatusPinName), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = statusMap.Close() }()
			traffic.Begin()
			snapshot := traffic.Snapshot

			time.Sleep(500 * time.Millisecond)
			before := snapshot()
			originalTags := restartLinkTags(t, root, id)
			beforeExternal := traffic.Egress[0].Load()
			if before.IngressAllowed == 0 || before.Replies == 0 || beforeExternal == 0 || before.IngressDenied != 0 || traffic.Egress[1].Load() != 0 {
				t.Fatalf("invalid directional baseline: %+v egress allowed=%d denied=%d", before, beforeExternal, traffic.Egress[1].Load())
			}
			outageStarted := time.Now()
			switch mode {
			case "SIGTERM":
				if err := owner.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				if err := owner.Wait(); err != nil {
					t.Fatal(err)
				}
				ownerWaited = true
			case "SIGKILL":
				if err := owner.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := owner.Wait(); err == nil {
					t.Fatal("owner was not killed")
				}
				ownerWaited = true
			case "SIGSTOP":
				if err := owner.Process.Signal(syscall.SIGSTOP); err != nil {
					t.Fatal(err)
				}
			default:
				if upgrade {
					_ = owner.Process.Kill()
					_ = owner.Wait()
					ownerWaited = true
					_ = readyRead.Close()
					readyRead, readyWrite, err = os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					owner = exec.Command(os.Args[0], "-test.run=^TestRestartEngineOwnerHelper$")
					owner.Env = append(os.Environ(), "ZTAP_RESTART_OWNER_HELPER=1", "ZTAP_RESTART_BPFFS="+root,
						"ZTAP_RESTART_CGROUP="+cgroup, "ZTAP_RESTART_INGRESS="+strconv.Itoa(int(ports.AllowedPort)),
						"ZTAP_RESTART_EGRESS="+strconv.Itoa(int(traffic.EgressPort())),
						"ZTAP_RESTART_CHECKPOINT="+mode, "ZTAP_RESTART_UPGRADE=1")
					owner.ExtraFiles = []*os.File{readyWrite}
					owner.Stdout, owner.Stderr = os.Stdout, os.Stderr
					if err := owner.Start(); err != nil {
						t.Fatal(err)
					}
					ownerWaited = false
					_ = readyWrite.Close()
				} else if _, err := updateWrite.Write([]byte{'u'}); err != nil {
					t.Fatal(err)
				}
				_ = readyRead.SetReadDeadline(time.Now().Add(10 * time.Second))
				reached := []byte{0}
				if _, err := io.ReadFull(readyRead, reached); err != nil || reached[0] != 'c' {
					t.Fatalf("checkpoint %s was not reached: %v", mode, err)
				}
				if upgrade {
					tags := restartLinkTags(t, root, id)
					switch mode {
					case "programs-pinned":
						if tags != originalTags {
							t.Fatal("program publication changed attachments before the update")
						}
					case "ztap_egress-updated":
						if tags[0] == originalTags[0] || tags[1] != originalTags[1] {
							t.Fatal("checkpoint did not leave compatible mixed directional generations")
						}
					case "ztap_ingress-updated":
						if tags[0] == originalTags[0] || tags[1] == originalTags[1] {
							t.Fatal("checkpoint did not update both compatible directions")
						}
					}
				}
				if err := owner.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = owner.Wait()
				ownerWaited = true
			}
			// Delay recovery deliberately; the traffic helpers are independent
			// processes and continue exercising both directional sockets.
			time.Sleep(1500 * time.Millisecond)
			during := snapshot()
			if during.IngressDenied != 0 || traffic.Egress[1].Load() != 0 || during.IngressAllowed <= before.IngressAllowed || during.Replies <= before.Replies || traffic.Egress[0].Load() <= beforeExternal {
				t.Fatalf("continuity violated during %s: before=%+v during=%+v prohibited-egress=%d", mode, before, during, traffic.Egress[1].Load())
			}
			if !ownerWaited {
				_ = owner.Process.Kill()
				_ = owner.Wait()
				ownerWaited = true
			}
			replacement, err := NewLinuxEngine(context.Background(), LinuxEngineOptions{BPFFSRoot: root, AgentEpoch: 101, ResolveCgroupPath: func(_ context.Context, subjectID uint64) (string, error) {
				if subjectID == id {
					return cgroup, nil
				}
				return extra, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = replacement.Close() }()
			if replacement.active.PolicyEpoch != expectedEpoch || !engineHasConnectionEpoch(replacement, expectedEpoch) {
				t.Fatal("recovery lost the committed epoch or established replies")
			}
			if err := replacement.Apply(context.Background(), set); err != nil {
				t.Fatal(err)
			}
			if replacement.active.PolicyEpoch != expectedEpoch {
				t.Fatal("unchanged recovery advanced policy epoch")
			}
			if upgrade && restartLinkTags(t, root, id) != originalTags {
				t.Fatal("compatible downgrade did not restore the original program generation in place")
			}
			time.Sleep(500 * time.Millisecond)
			after := snapshot()
			if after.IngressDenied != 0 || traffic.Egress[1].Load() != 0 || after.IngressAllowed <= during.IngressAllowed || after.Replies <= during.Replies {
				t.Fatalf("post-recovery continuity violated: %+v", after)
			}
			t.Logf("restart-proof-v1 mode=%s outage=%s cgroup=%d epoch=%d ingress_allowed=%d egress_allowed=%d established_replies=%d ingress_prohibited=%d egress_prohibited=%d", mode, time.Since(outageStarted), id, expectedEpoch, after.IngressAllowed, traffic.Egress[0].Load(), after.Replies, after.IngressDenied, traffic.Egress[1].Load())
		})
	}
}

func restartLinkTags(t *testing.T, root string, id uint64) [2]string {
	t.Helper()
	var tags [2]string
	for direction := range tags {
		handle, err := link.LoadPinnedLink(filepath.Join(root, "ztap", subjectPinName(id, direction)), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := handle.Info()
		_ = handle.Close()
		if err != nil {
			t.Fatal(err)
		}
		program, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			t.Fatal(err)
		}
		programInfo, err := program.Info()
		_ = program.Close()
		if err != nil {
			t.Fatal(err)
		}
		tags[direction] = programInfo.Tag
	}
	return tags
}
