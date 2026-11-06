//go:build linux && integration

package enforcer

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/saadshabir/ZTAP/internal/restartproof"
)

func TestLinuxPreflightRejectsDirectGuardAttachments(t *testing.T) {
	requireLinuxEBPFRoot(t)
	root := createTestCgroup(t)
	parent := createSubCgroup(t, root, "kubepods.slice")
	parents := []string{"kubepods.slice"}
	if err := CheckGuardParents(root, parents); err != nil {
		t.Fatalf("empty guard hooks: %v", err)
	}
	cgroup, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cgroup.Close() }()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.CGroupSKB, AttachType: ebpf.AttachCGroupInetEgress, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = program.Close() }()
	handle, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroup.Fd()), Program: program, Attach: ebpf.AttachCGroupInetEgress})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	if err := CheckGuardParents(root, parents); err == nil || !strings.Contains(err.Error(), "already has a directly attached BPF program") {
		t.Fatalf("expected the existing program to block preflight, got %v", err)
	}
}

// This proof intentionally uses an independent minimal guard. It establishes
// socket identity and inheritance before the production classification ABI is
// chosen; passing it alone does not establish new-container policy coverage.
func feasibilityGuardProgram(known, seen *ebpf.Map, direction uint32) *ebpf.ProgramSpec {
	attach := ebpf.AttachCGroupInetEgress
	if direction == 1 {
		attach = ebpf.AttachCGroupInetIngress
	}
	return &ebpf.ProgramSpec{Name: "ztap_guard_probe", Type: ebpf.CGroupSKB, AttachType: attach, License: "GPL", Instructions: asm.Instructions{
		asm.FnSkbCgroupId.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, -8, int64(direction), asm.Word),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Imm(asm.R0, 1),
		asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, seen.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(),
		asm.LoadMapPtr(asm.R1, known.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "deny"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.JNE.Imm(asm.R0, 1, "deny"),
		asm.Mov.Imm(asm.R0, 1), asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("deny"), asm.Return(),
	}}
}

func TestInheritedGuardOwnerHelper(t *testing.T) {
	if os.Getenv("ZTAP_GUARD_OWNER") != "1" {
		t.Skip("helper")
	}
	parent, pinRoot := os.Getenv("ZTAP_GUARD_PARENT"), os.Getenv("ZTAP_GUARD_PINS")
	cgroup, _, err := openValidatedCgroup("/sys/fs/cgroup", parent, mustCgroupID(t, parent))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cgroup.Close() }()
	known, err := ebpf.NewMap(&ebpf.MapSpec{Name: "guard_known", Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = known.Close() }()
	seen, err := ebpf.NewMap(&ebpf.MapSpec{Name: "guard_seen", Type: ebpf.Hash, KeySize: 16, ValueSize: 8, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = seen.Close() }()
	if err := known.Pin(filepath.Join(pinRoot, "known")); err != nil {
		t.Fatal(err)
	}
	if err := seen.Pin(filepath.Join(pinRoot, "seen")); err != nil {
		t.Fatal(err)
	}
	for direction := uint32(0); direction < 2; direction++ {
		spec := feasibilityGuardProgram(known, seen, direction)
		program, err := ebpf.NewProgram(spec)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = program.Close() }()
		if err := program.Pin(filepath.Join(pinRoot, fmt.Sprintf("program_%d", direction))); err != nil {
			t.Fatal(err)
		}
		handle, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroup.Fd()), Program: program, Attach: spec.AttachType})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = handle.Close() }()
		if err := handle.Pin(filepath.Join(pinRoot, fmt.Sprintf("link_%d", direction))); err != nil {
			t.Fatal(err)
		}
	}
	ready := os.NewFile(3, "guard installed")
	if _, err := ready.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	_ = ready.Close()
	for {
		time.Sleep(time.Hour)
	}
}

func TestLinuxInheritedGuardUsesDescendantSocketIdentity(t *testing.T) {
	requireLinuxEBPFRoot(t)
	for _, layout := range []string{"kubepods.slice", "kubelet.slice/kubelet-kubepods.slice"} {
		t.Run(layout, func(t *testing.T) {
			root := createTestCgroup(t)
			var parent string
			// Split the supported nested systemd path using filesystem separators.
			if layout == "kubepods.slice" {
				parent = createSubCgroup(t, root, "kubepods.slice")
			} else {
				parent = createSubCgroup(t, createSubCgroup(t, root, "kubelet.slice"), "kubelet-kubepods.slice")
			}
			pinRoot := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ztap-guard-proof-%d", time.Now().UnixNano()))
			if err := os.Mkdir(pinRoot, 0o750); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, name := range []string{"link_0", "link_1", "program_0", "program_1", "known", "seen"} {
					if err := os.Remove(filepath.Join(pinRoot, name)); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
				}
				if err := os.Remove(pinRoot); err != nil {
					t.Error(err)
				}
			})
			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = readyRead.Close(); _ = readyWrite.Close() })
			owner := exec.Command(os.Args[0], "-test.run=^TestInheritedGuardOwnerHelper$")
			owner.Env = append(os.Environ(), "ZTAP_GUARD_OWNER=1", "ZTAP_GUARD_PARENT="+parent, "ZTAP_GUARD_PINS="+pinRoot)
			owner.ExtraFiles = []*os.File{readyWrite}
			owner.Stdout, owner.Stderr = os.Stdout, os.Stderr
			if err := owner.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = owner.Process.Kill()
					_ = owner.Wait()
				}
			})
			_ = readyWrite.Close()
			_ = readyRead.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(readyRead, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			known, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "known"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = known.Close() }()
			baseline := createSubCgroup(t, parent, "known-before-outage.scope")
			baselineID := mustCgroupID(t, baseline)
			one := uint32(1)
			if err := known.Put(&baselineID, &one); err != nil {
				t.Fatal(err)
			}
			control := restartproof.Start(t, baseline, "TestRestartTrafficHelper")
			control.Begin()
			time.Sleep(300 * time.Millisecond)
			before := control.Snapshot()
			if before.IngressAllowed == 0 || before.Replies == 0 || control.Egress[0].Load() == 0 {
				t.Fatal("guard baseline lacks allowed controls")
			}
			beforeEgress := control.Egress[0].Load()
			if err := owner.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = owner.Wait()
			waited = true
			// Both the scope and its sockets are created after the guard owner dies.
			unknown := createSubCgroup(t, parent, "unknown-during-outage.scope")
			unknownID := mustCgroupID(t, unknown)
			traffic := restartproof.Start(t, unknown, "TestRestartTrafficHelper")
			traffic.Begin()
			outageStarted := time.Now()
			time.Sleep(1500 * time.Millisecond)
			during := traffic.Snapshot()
			if during.IngressAllowed != 0 || during.IngressDenied != 0 || during.Replies != 0 || traffic.Egress[0].Load() != 0 || traffic.Egress[1].Load() != 0 {
				t.Fatalf("unknown descendant leaked traffic: %+v", during)
			}
			afterControl := control.Snapshot()
			if afterControl.IngressAllowed <= before.IngressAllowed || afterControl.Replies <= before.Replies || control.Egress[0].Load() <= beforeEgress {
				t.Fatal("guard outage lost allowed controls")
			}
			seen, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "seen"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = seen.Close() }()
			for direction := uint32(0); direction < 2; direction++ {
				key := struct {
					Cgroup    uint64
					Direction uint32
					Padding   uint32
				}{Cgroup: unknownID, Direction: direction}
				var observed uint64
				if err := seen.Lookup(&key, &observed); err != nil || observed != 1 {
					t.Fatalf("direction %d did not observe the actual descendant socket identity %d: %v", direction, unknownID, err)
				}
			}

			if err := known.Put(&unknownID, &one); err != nil {
				t.Fatal(err)
			}
			time.Sleep(500 * time.Millisecond)
			classified := traffic.Snapshot()
			if classified.IngressAllowed == 0 || classified.Replies == 0 || traffic.Egress[0].Load() == 0 {
				t.Fatal("explicit classification did not release descendant")
			}
			t.Logf("guard-feasibility-v1 layout=%s parent=%d descendant=%d outage=%s ingress_unknown=0 egress_unknown=0 ingress_classified=%d egress_classified=%d", layout, mustCgroupID(t, parent), unknownID, time.Since(outageStarted), classified.IngressAllowed, traffic.Egress[0].Load())
		})
	}
}
