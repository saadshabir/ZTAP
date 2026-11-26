//go:build linux && integration

package enforcer

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/saadshabir/ZTAP/internal/policy"
	"github.com/saadshabir/ZTAP/internal/restartproof"
	"golang.org/x/sys/unix"
)

func productionGuardTestOptions(t *testing.T, parent, bootstrap, pins string, paths map[uint64]string) LinuxEngineOptions {
	t.Helper()
	identity := func(id uint64, path string) WorkloadIdentity {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel("/sys/fs/cgroup", path)
		if err != nil {
			t.Fatal(err)
		}
		return WorkloadIdentity{CgroupID: id, Device: uint64(st.Dev), Path: relative, PodUID: "11111111-2222-3333-4444-555555555555", ContainerID: strings.Repeat("a", 64)}
	}
	parentRelative, err := filepath.Rel("/sys/fs/cgroup", parent)
	if err != nil {
		t.Fatal(err)
	}
	return LinuxEngineOptions{CgroupRoot: "/sys/fs/cgroup", BPFFSRoot: pins,
		ResolveCgroupPath: func(_ context.Context, id uint64) (string, error) {
			if paths[id] == "" {
				return "", fmt.Errorf("unresolved cgroup %d", id)
			}
			return paths[id], nil
		},
		ResolveIdentity: func(_ context.Context, id uint64) (WorkloadIdentity, error) { return identity(id, paths[id]), nil },
		Guard:           &WorkloadGuardOptions{Parents: []string{parentRelative}, HostNetnsCookie: ^uint64(0), BootstrapIdentity: identity(mustCgroupID(t, bootstrap), bootstrap), APIPeers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}},
	}
}

func TestProductionGuardOwnerHelper(t *testing.T) {
	if os.Getenv("ZTAP_PRODUCTION_GUARD_OWNER") != "1" {
		t.Skip("helper")
	}
	parent, bootstrap, pins, known := os.Getenv("ZTAP_GUARD_PARENT"), os.Getenv("ZTAP_GUARD_BOOTSTRAP"), os.Getenv("ZTAP_GUARD_PINS"), os.Getenv("ZTAP_GUARD_KNOWN")
	id := mustCgroupID(t, known)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	options := productionGuardTestOptions(t, parent, bootstrap, pins, map[uint64]string{id: known})
	var spec *ebpf.CollectionSpec
	if target := os.Getenv("ZTAP_GUARD_CHECKPOINT"); target != "" {
		spec = compatibleRestartProgramSpec(t)
		options.ObserveCheckpoint = func(name string) {
			if name != target {
				return
			}
			ready := os.NewFile(3, "guard update checkpoint")
			if _, err := ready.Write([]byte{'c'}); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Hour)
			}
		}
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
	set := policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ClassifiedCgroups: []uint64{id}}
	if err := engine.Apply(ctx, set); err != nil {
		t.Fatal(err)
	}
	ready := os.NewFile(3, "guard ready")
	if _, err := ready.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	_ = ready.Close()
	<-ctx.Done()
}

func TestLinuxGuardCompatibleUpgradeCheckpointRecovery(t *testing.T) {
	requireLinuxEBPFRoot(t)
	for _, checkpoint := range []string{"ztap_socket_namespace-updated", "ztap_guard_egress-updated", "ztap_guard_ingress-updated"} {
		t.Run(checkpoint, func(t *testing.T) {
			root := createTestCgroup(t)
			parent := createSubCgroup(t, root, "kubepods.slice")
			known := createSubCgroup(t, parent, "known.scope")
			bootstrap := createSubCgroup(t, parent, "agent.scope")
			pins := createEngineTestBPFFSRoot(t)
			knownID := mustCgroupID(t, known)
			options := productionGuardTestOptions(t, parent, bootstrap, pins, map[uint64]string{knownID: known})
			engine, err := NewLinuxEngine(t.Context(), options)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Apply(t.Context(), policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ClassifiedCgroups: []uint64{knownID}}); err != nil {
				t.Fatal(err)
			}
			original, err := engine.store.programGeneration()
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
			control := restartproof.Start(t, known, "TestRestartTrafficHelper")
			control.Begin()
			time.Sleep(200 * time.Millisecond)
			before := control.Snapshot()
			beforeEgress := control.Egress[0].Load()
			unknown := createSubCgroup(t, parent, "new-during-upgrade.scope")
			traffic := restartproof.Start(t, unknown, "TestRestartTrafficHelper")
			traffic.Begin()
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = read.Close(); _ = write.Close() }()
			owner := exec.Command(os.Args[0], "-test.run=^TestProductionGuardOwnerHelper$")
			owner.Env = append(os.Environ(), "ZTAP_PRODUCTION_GUARD_OWNER=1", "ZTAP_GUARD_PARENT="+parent, "ZTAP_GUARD_BOOTSTRAP="+bootstrap, "ZTAP_GUARD_PINS="+pins, "ZTAP_GUARD_KNOWN="+known, "ZTAP_GUARD_CHECKPOINT="+checkpoint)
			owner.ExtraFiles = []*os.File{write}
			owner.Stdout, owner.Stderr = os.Stdout, os.Stderr
			if err := owner.Start(); err != nil {
				t.Fatal(err)
			}
			_ = write.Close()
			if err := read.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = owner.Process.Kill()
					_ = owner.Wait()
				}
			})
			if _, err := io.ReadFull(read, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			_ = owner.Process.Kill()
			_ = owner.Wait()
			waited = true
			time.Sleep(1500 * time.Millisecond)
			during := traffic.Snapshot()
			if during.IngressAllowed != 0 || during.IngressDenied != 0 || during.Replies != 0 || traffic.Egress[0].Load() != 0 || traffic.Egress[1].Load() != 0 {
				t.Fatalf("guard upgrade exposed new workload: %+v", during)
			}
			after := control.Snapshot()
			if after.IngressAllowed <= before.IngressAllowed || after.Replies <= before.Replies || control.Egress[0].Load() <= beforeEgress {
				t.Fatal("classified control stopped during mixed guard generations")
			}
			replacement, err := NewLinuxEngine(t.Context(), options)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = replacement.Close() }()
			generation, err := replacement.store.programGeneration()
			if err != nil {
				t.Fatal(err)
			}
			if generation != original || replacement.active.PolicyEpoch != 1 {
				t.Fatal("compatible downgrade lost generation or committed epoch")
			}
			t.Logf("guard-checkpoint-v2 checkpoint=%s outage_ms=1500 ingress_unknown=0 egress_unknown=0", checkpoint)
		})
	}
}

func TestLinuxProductionGuardBlocksNewWorkloadsAcrossOwnerLoss(t *testing.T) {
	requireLinuxEBPFRoot(t)
	for _, mode := range []string{"SIGTERM", "SIGKILL", "SIGSTOP"} {
		t.Run(mode, func(t *testing.T) {
			root := createTestCgroup(t)
			parent := createSubCgroup(t, root, "kubepods.slice")
			pins := createEngineTestBPFFSRoot(t)
			relative, err := filepath.Rel("/sys/fs/cgroup", parent)
			if err != nil {
				t.Fatal(err)
			}
			if err := InstallBootGuard(t.Context(), "/sys/fs/cgroup", pins, []string{relative}, ^uint64(0)); err != nil {
				t.Fatalf("install guard before the runtime: %v", err)
			}
			known := createSubCgroup(t, parent, "known.scope")
			bootstrap := createSubCgroup(t, parent, "agent.scope")
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
			owner := exec.Command(os.Args[0], "-test.run=^TestProductionGuardOwnerHelper$")
			owner.Env = append(os.Environ(), "ZTAP_PRODUCTION_GUARD_OWNER=1", "ZTAP_GUARD_PARENT="+parent, "ZTAP_GUARD_BOOTSTRAP="+bootstrap, "ZTAP_GUARD_PINS="+pins, "ZTAP_GUARD_KNOWN="+known)
			owner.ExtraFiles = []*os.File{write}
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
			_ = write.Close()
			_ = read.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(read, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			control := restartproof.Start(t, known, "TestRestartTrafficHelper")
			control.Begin()
			time.Sleep(300 * time.Millisecond)
			before := control.Snapshot()
			beforeEgress := control.Egress[0].Load()
			if before.IngressAllowed == 0 || before.Replies == 0 || beforeEgress == 0 {
				t.Fatal("missing classified baseline controls")
			}
			sig := syscall.SIGKILL
			if mode == "SIGTERM" {
				sig = syscall.SIGTERM
			}
			if mode == "SIGSTOP" {
				sig = syscall.SIGSTOP
			}
			if err := owner.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if mode != "SIGSTOP" {
				_ = owner.Wait()
				waited = true
			}
			unknown := createSubCgroup(t, parent, "created-during-outage.scope")
			traffic := restartproof.Start(t, unknown, "TestRestartTrafficHelper")
			traffic.Begin()
			time.Sleep(1500 * time.Millisecond)
			during := traffic.Snapshot()
			if during.IngressAllowed != 0 || during.IngressDenied != 0 || during.Replies != 0 || traffic.Egress[0].Load() != 0 || traffic.Egress[1].Load() != 0 {
				t.Fatalf("unknown workload leaked: %+v", during)
			}
			after := control.Snapshot()
			if after.IngressAllowed <= before.IngressAllowed || after.Replies <= before.Replies || control.Egress[0].Load() <= beforeEgress {
				t.Fatal("classified control stopped during outage")
			}
			if !waited {
				_ = owner.Process.Kill()
				_ = owner.Wait()
				waited = true
			}
			knownID, unknownID := mustCgroupID(t, known), mustCgroupID(t, unknown)
			engine, err := NewLinuxEngine(context.Background(), productionGuardTestOptions(t, parent, bootstrap, pins, map[uint64]string{knownID: known, unknownID: unknown}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = engine.Close() })
			for direction := uint32(0); direction < 2; direction++ {
				key := struct {
					Cgroup, Epoch      uint64
					Direction, Padding uint32
				}{Cgroup: unknownID, Epoch: 1, Direction: direction}
				var counters []uint64
				err := engine.store.maps["guard_blocks"].Lookup(&key, &counters)
				blocked, sumErr := sumCounterValues(counters)
				if sumErr != nil {
					t.Fatal(sumErr)
				}
				if err != nil || blocked == 0 {
					t.Fatalf("missing actual socket/direction/epoch guard counter: %d %v", blocked, err)
				}
			}
			set := policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ClassifiedCgroups: []uint64{knownID, unknownID}}
			if err := engine.Apply(context.Background(), set); err != nil {
				t.Fatal(err)
			}
			time.Sleep(400 * time.Millisecond)
			classified := traffic.Snapshot()
			if classified.IngressAllowed == 0 || classified.Replies == 0 || traffic.Egress[0].Load() == 0 {
				t.Fatal("explicit unisolated classification failed to release new workload")
			}
			t.Logf("production-guard-v2 mode=%s cgroup=%d outage_ms=1500 ingress_unknown=0 egress_unknown=0 ingress_classified=%d egress_classified=%d", mode, unknownID, classified.IngressAllowed, traffic.Egress[0].Load())
		})
	}
}

func TestLinuxBootGuardPartialPublication(t *testing.T) {
	requireLinuxEBPFRoot(t)
	if root := os.Getenv("ZTAP_BOOT_TEST_PARTIAL_ROOT"); root != "" {
		_, err := NewLinuxEngine(t.Context(), LinuxEngineOptions{
			BPFFSRoot: root,
			ResolveCgroupPath: func(context.Context, uint64) (string, error) {
				return "", fmt.Errorf("workload resolution is unavailable before the runtime")
			},
			ObserveCheckpoint: func(name string) {
				if name == "durable-metadata-pinned" {
					os.Exit(86)
				}
			},
		})
		t.Fatalf("engine exited before the publication checkpoint: %v", err)
	}

	const cgroupRoot = "/sys/fs/cgroup"
	parent, err := filepath.Rel(cgroupRoot, createTestCgroup(t))
	if err != nil {
		t.Fatal(err)
	}
	root := createEngineTestBPFFSRoot(t)
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestLinuxBootGuardPartialPublication$")
	child.Env = append(os.Environ(), "ZTAP_BOOT_TEST_PARTIAL_ROOT="+root)
	if output, err := child.CombinedOutput(); child.ProcessState == nil || child.ProcessState.ExitCode() != 86 {
		t.Fatalf("interrupt pin publication: %v, output %s", err, output)
	}
	parents := []string{parent}
	if err := InstallBootGuard(t.Context(), cgroupRoot, root, parents, ^uint64(0)); err == nil || !strings.Contains(err.Error(), "validate map pin") {
		t.Fatalf("retry with partially published maps: %v", err)
	}
	if err := RemoveEnforcement(t.Context(), root); err != nil {
		t.Fatalf("clean up the interrupted installation: %v", err)
	}
	if err := InstallBootGuard(t.Context(), cgroupRoot, root, parents, ^uint64(0)); err != nil {
		t.Fatalf("install after cleanup: %v", err)
	}
	for direction := range guardAttachTypes {
		id := mustCgroupID(t, filepath.Join(cgroupRoot, parent))
		if _, err := os.Stat(filepath.Join(root, "ztap", guardPinName(id, direction))); err != nil {
			t.Fatalf("recovered guard link %d: %v", direction, err)
		}
	}
}

// TestLinuxBootGuardFirstTraffic is called by the VM's first runtime jobs.
// The two jobs exercise both parent layouts, in host and private namespaces.
func TestLinuxBootGuardFirstTraffic(t *testing.T) {
	parent := os.Getenv("ZTAP_BOOT_TEST_PARENT")
	if parent == "" {
		t.Skip("requires the disposable systemd reboot fixture")
	}
	requireLinuxEBPFRoot(t)
	private := os.Getenv("ZTAP_BOOT_TEST_PRIVATE") == "1"
	parentID := mustCgroupID(t, parent)
	for direction := range guardAttachTypes {
		if _, err := os.Stat(filepath.Join("/sys/fs/bpf/ztap", guardPinName(parentID, direction))); err != nil {
			t.Fatalf("runtime started before guard pin %d: %v", direction, err)
		}
	}
	subject := createSubCgroup(t, parent, "ztap-reboot-probe.scope")
	traffic := restartproof.Start(t, subject, "TestRestartTrafficHelper")
	traffic.Begin()
	time.Sleep(550 * time.Millisecond)
	report := traffic.Snapshot()
	if !private {
		if report.IngressAllowed == 0 || report.IngressDenied == 0 || report.Replies == 0 || traffic.Egress[0].Load() == 0 || traffic.Egress[1].Load() == 0 {
			t.Fatalf("host-network traffic did not bootstrap: %+v", report)
		}
		return
	}
	if report.IngressAllowed != 0 || report.IngressDenied != 0 || report.Replies != 0 || traffic.Egress[0].Load() != 0 || traffic.Egress[1].Load() != 0 {
		t.Fatalf("ordinary workload traffic escaped the guard: %+v", report)
	}
	blocks, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ztap/guard_blocks", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocks.Close() })
	for direction := uint32(0); direction < 2; direction++ {
		key := struct {
			Cgroup, Epoch      uint64
			Direction, Padding uint32
		}{Cgroup: mustCgroupID(t, subject), Direction: direction}
		var counters []uint64
		if err := blocks.Lookup(&key, &counters); err != nil {
			t.Fatalf("no pre-reconciliation blocks in direction %d: %v", direction, err)
		}
		blocked, err := sumCounterValues(counters)
		if err != nil || blocked == 0 {
			t.Fatalf("pre-reconciliation blocks in direction %d = %d, error %v", direction, blocked, err)
		}
		t.Logf("pre-reconciliation direction=%d blocked=%d", direction, blocked)
	}
}
