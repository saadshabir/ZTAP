//go:build linux

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/policy"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func nilContextForTest() context.Context { return nil }

func TestLinuxEngineStoreRejectsNilPopulateContext(t *testing.T) {
	store := &linuxEngineStore{}
	if err := store.PopulateSlot(nilContextForTest(), 0, policy.PolicySet{}); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil populate context error = %v, want context validation", err)
	}
}

func TestLockEngineMutexHonorsCancellation(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := lockEngineMutex(ctx, &mu); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("metrics mutex lock error = %v, want context deadline", err)
	}
}

func TestLinuxSubjectLinkerRejectsNilAndCancelledContext(t *testing.T) {
	linker := &linuxSubjectLinker{}
	if err := func() error {
		_, err := linker.Attach(nilContextForTest(), 1)
		return err
	}(); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil attach context error = %v, want context validation", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := func() error {
		_, err := linker.Attach(ctx, 1)
		return err
	}(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled attach context error = %v, want context.Canceled", err)
	}
}

func TestValidateCgroupTargetRequiresDirectoryInsideRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "subject")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create cgroup target: %v", err)
	}
	expectedID, err := cgroupInodeID(target)
	if err != nil {
		t.Fatalf("read cgroup target ID: %v", err)
	}
	if resolved, err := validateCgroupTarget(root, target, expectedID); err != nil || resolved != target {
		t.Fatalf("validateCgroupTarget = %q, %v; want %q", resolved, err, target)
	}

	file := filepath.Join(root, "not-a-cgroup")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("create non-directory target: %v", err)
	}
	if _, err := validateCgroupTarget(root, file, 1); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("validateCgroupTarget accepted non-directory target: %v", err)
	}
}

func TestValidateCgroupTargetRejectsOutsideRootAndIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "subject")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatalf("create cgroup target: %v", err)
	}
	expectedID, err := cgroupInodeID(inside)
	if err != nil {
		t.Fatalf("read cgroup target ID: %v", err)
	}
	if _, err := validateCgroupTarget(root, inside, expectedID+1); err == nil || !strings.Contains(err.Error(), "has ID") {
		t.Fatalf("validateCgroupTarget accepted mismatched identity: %v", err)
	}

	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "subject")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatalf("create outside cgroup target: %v", err)
	}
	outsideID, err := cgroupInodeID(outside)
	if err != nil {
		t.Fatalf("read outside cgroup ID: %v", err)
	}
	if _, err := validateCgroupTarget(root, outside, outsideID); err == nil || !strings.Contains(err.Error(), "outside mounted root") {
		t.Fatalf("validateCgroupTarget accepted outside target: %v", err)
	}
}

func TestOpenValidatedCgroupReturnsDescriptorForValidatedDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "kubepods", "subject")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("create nested cgroup target: %v", err)
	}
	expectedID, err := cgroupInodeID(target)
	if err != nil {
		t.Fatalf("read cgroup target ID: %v", err)
	}

	cgroup, resolved, err := openValidatedCgroup(root, target, expectedID)
	if err != nil {
		t.Fatalf("openValidatedCgroup: %v", err)
	}
	t.Cleanup(func() {
		if err := cgroup.Close(); err != nil {
			t.Errorf("close cgroup descriptor: %v", err)
		}
	})
	if resolved != target {
		t.Fatalf("resolved cgroup path = %q, want %q", resolved, target)
	}
	info, err := cgroup.Stat()
	if err != nil {
		t.Fatalf("stat retained cgroup descriptor: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("retained cgroup descriptor is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Ino) != expectedID {
		t.Fatalf("retained cgroup descriptor inode = %v, want %d", info.Sys(), expectedID)
	}
}

func TestOpenValidatedCgroupRejectsTargetEscapingRoot(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	target := filepath.Join(outsideRoot, "subject")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create outside cgroup target: %v", err)
	}
	if _, _, err := openValidatedCgroup(root, target, 1); err == nil || !strings.Contains(err.Error(), "outside mounted root") {
		t.Fatalf("openValidatedCgroup accepted outside target: %v", err)
	}
}

func TestRemoveStalePinsRemovesOnlyOwnedMaps(t *testing.T) {
	root := t.TempDir()
	pinDir := filepath.Join(root, "ztap")
	if err := os.Mkdir(pinDir, 0o750); err != nil {
		t.Fatalf("create pin directory: %v", err)
	}
	for _, name := range []string{"flow_events", "agent_status", "unrelated"} {
		if err := os.WriteFile(filepath.Join(pinDir, name), []byte("pin"), 0o600); err != nil {
			t.Fatalf("create %s pin: %v", name, err)
		}
	}

	if err := RemoveStalePins(root); err != nil {
		t.Fatalf("RemoveStalePins: %v", err)
	}
	for _, name := range []string{"flow_events", "agent_status"} {
		if _, err := os.Stat(filepath.Join(pinDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned pin %q remains: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(pinDir, "unrelated")); err != nil {
		t.Fatalf("unrelated pin was removed: %v", err)
	}
}

func TestRemoveStalePinsRejectsOwnedDirectory(t *testing.T) {
	root := t.TempDir()
	pinDir := filepath.Join(root, "ztap")
	if err := os.Mkdir(pinDir, 0o750); err != nil {
		t.Fatalf("create pin directory: %v", err)
	}
	ownedDirectory := filepath.Join(pinDir, engineFlowEventsPinName)
	if err := os.Mkdir(ownedDirectory, 0o750); err != nil {
		t.Fatalf("create owned-name directory: %v", err)
	}
	sentinel := filepath.Join(ownedDirectory, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("create directory sentinel: %v", err)
	}

	err := RemoveStalePins(root)
	if err == nil || !strings.Contains(err.Error(), "path is a directory") {
		t.Fatalf("RemoveStalePins error = %v, want directory rejection", err)
	}
	if _, statErr := os.Stat(sentinel); statErr != nil {
		t.Fatalf("owned-name directory contents were removed: %v", statErr)
	}
}

func TestRemoveStalePinsRejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, engineFlowEventsPinName), []byte("preserve"), 0o600); err != nil {
		t.Fatalf("create redirected pin: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "ztap")); err != nil {
		t.Fatalf("create pin-directory symlink: %v", err)
	}

	err := RemoveStalePins(root)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("RemoveStalePins error = %v, want symlink rejection", err)
	}
	if _, err := os.Stat(filepath.Join(target, engineFlowEventsPinName)); err != nil {
		t.Fatalf("redirected pin was removed: %v", err)
	}
}

func TestRemoveOwnedEnginePinUnlinksSymlinkWithoutFollowingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("create symlink target: %v", err)
	}
	linkPath := filepath.Join(root, "owned")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("create owned symlink: %v", err)
	}

	if err := removeOwnedEnginePin(linkPath); err != nil {
		t.Fatalf("removeOwnedEnginePin: %v", err)
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned symlink remains: %v", err)
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "preserve" {
		t.Fatalf("symlink target changed or disappeared: contents=%q error=%v", contents, err)
	}
}

func TestRemoveOwnedEnginePinRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, engineFlowEventsPinName), []byte("preserve"), 0o600); err != nil {
		t.Fatalf("create redirected pin: %v", err)
	}
	linkedDirectory := filepath.Join(root, "ztap")
	if err := os.Symlink(target, linkedDirectory); err != nil {
		t.Fatalf("create pin-directory symlink: %v", err)
	}

	err := removeOwnedEnginePin(filepath.Join(linkedDirectory, engineFlowEventsPinName))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("removeOwnedEnginePin error = %v, want parent symlink rejection", err)
	}
	if _, err := os.Stat(filepath.Join(target, engineFlowEventsPinName)); err != nil {
		t.Fatalf("redirected pin was removed: %v", err)
	}
}

func TestRemoveOwnedEnginePinRejectsSymlinkedParentComponent(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create intermediate directory symlink: %v", err)
	}
	pinPath := filepath.Join(link, "ztap", engineFlowEventsPinName)
	if err := os.MkdirAll(filepath.Join(target, "ztap"), 0o750); err != nil {
		t.Fatalf("create redirected pin directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "ztap", engineFlowEventsPinName), []byte("preserve"), 0o600); err != nil {
		t.Fatalf("create redirected pin: %v", err)
	}

	err := removeOwnedEnginePin(pinPath)
	if err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("removeOwnedEnginePin error = %v, want symlink-component rejection", err)
	}
	if _, err := os.Stat(filepath.Join(target, "ztap", engineFlowEventsPinName)); err != nil {
		t.Fatalf("redirected pin was removed: %v", err)
	}
}

func TestEnsureEnginePinDirectoryCreatesDirectory(t *testing.T) {
	root := t.TempDir()
	if err := ensureEnginePinDirectory(root); err != nil {
		t.Fatalf("ensureEnginePinDirectory: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "ztap"))
	if err != nil {
		t.Fatalf("stat created pin directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("created pin path is not a directory")
	}
}

func TestOpenEnginePinDirectoryRetainsValidatedDirectory(t *testing.T) {
	root := t.TempDir()
	pinDirectory, err := openOrCreateEnginePinDirectory(root)
	if err != nil {
		t.Fatalf("openOrCreateEnginePinDirectory: %v", err)
	}
	t.Cleanup(func() {
		if err := pinDirectory.Close(); err != nil {
			t.Errorf("close pin directory: %v", err)
		}
	})

	original := filepath.Join(root, "ztap-original")
	if err := os.Rename(filepath.Join(root, "ztap"), original); err != nil {
		t.Fatalf("rename validated pin directory: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "ztap"), 0o750); err != nil {
		t.Fatalf("create replacement pin directory: %v", err)
	}
	pinPath, err := enginePinPathAt(pinDirectory, "sentinel")
	if err != nil {
		t.Fatalf("enginePinPathAt: %v", err)
	}
	if err := os.WriteFile(pinPath, []byte("retained"), 0o600); err != nil {
		t.Fatalf("write through retained pin directory: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(original, "sentinel")); err != nil || string(contents) != "retained" {
		t.Fatalf("retained directory contents = %q, %v; want retained", contents, err)
	}
	if _, err := os.Stat(filepath.Join(root, "ztap", "sentinel")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received pin: %v", err)
	}
	if err := removeOwnedEnginePinAt(int(pinDirectory.Fd()), "sentinel"); err != nil {
		t.Fatalf("remove pin through retained directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(original, "sentinel")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained-directory cleanup left pin behind: %v", err)
	}
}

func TestEnginePinPathAtRejectsInvalidName(t *testing.T) {
	root := t.TempDir()
	pinDirectory, err := openOrCreateEnginePinDirectory(root)
	if err != nil {
		t.Fatalf("openOrCreateEnginePinDirectory: %v", err)
	}
	t.Cleanup(func() {
		if err := pinDirectory.Close(); err != nil {
			t.Errorf("close pin directory: %v", err)
		}
	})

	for _, name := range []string{".", "..", "nested/pin"} {
		if _, err := enginePinPathAt(pinDirectory, name); err == nil {
			t.Fatalf("enginePinPathAt accepted invalid name %q", name)
		}
	}
}

func TestEnsureEnginePinDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "ztap")); err != nil {
		t.Fatalf("create pin-directory symlink: %v", err)
	}
	if err := ensureEnginePinDirectory(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ensureEnginePinDirectory error = %v, want symlink rejection", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received pin entries: %v", entries)
	}
}

func TestOpenEngineDirectoryNoFollowRejectsSymlinkComponent(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create intermediate directory symlink: %v", err)
	}

	if _, err := openEngineDirectoryNoFollow(filepath.Join(link, "bpffs"), "test directory"); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("openEngineDirectoryNoFollow error = %v, want symlink-component rejection", err)
	}
}

func TestEnsureEnginePinDirectoryRejectsSymlinkedRootComponent(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create intermediate directory symlink: %v", err)
	}

	if err := ensureEnginePinDirectory(filepath.Join(link, "bpffs")); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("ensureEnginePinDirectory error = %v, want symlink-component rejection", err)
	}
}

func TestTryLegacyCgroupAttachFallsBackToOverride(t *testing.T) {
	for _, unsupported := range []error{
		link.ErrNotSupported,
		fmt.Errorf("multi attach: %w", unix.EINVAL),
		fmt.Errorf("multi attach: %w", unix.EOPNOTSUPP),
	} {
		t.Run(unsupported.Error(), func(t *testing.T) {
			var flags []uint32
			err := tryLegacyCgroupAttach(func(flag uint32) error {
				flags = append(flags, flag)
				if flag == cgroupAttachAllowMulti {
					return unsupported
				}
				return nil
			})
			if err != nil {
				t.Fatalf("tryLegacyCgroupAttach: %v", err)
			}
			want := []uint32{cgroupAttachAllowMulti, cgroupAttachAllowOverride}
			if !reflect.DeepEqual(flags, want) {
				t.Fatalf("attach flags = %v, want %v", flags, want)
			}
		})
	}
}

func TestTryLegacyCgroupAttachDoesNotMaskOtherErrors(t *testing.T) {
	wantErr := fmt.Errorf("multi attach: %w", unix.EPERM)
	var flags []uint32
	err := tryLegacyCgroupAttach(func(flag uint32) error {
		flags = append(flags, flag)
		return wantErr
	})
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("tryLegacyCgroupAttach error = %v, want EPERM", err)
	}
	wantFlags := []uint32{cgroupAttachAllowMulti}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Fatalf("attach flags = %v, want %v", flags, wantFlags)
	}
}

func TestLinuxEngineAgentStatusWriteSerializesLifecycleChanges(t *testing.T) {
	store := &linuxEngineStore{
		statusState: engineStateStarting,
		agentEpoch:  42,
	}
	firstWriteEntered := make(chan struct{})
	releaseFirstWrite := make(chan struct{})
	enforcingPublished := make(chan struct{})
	var mu sync.Mutex
	var calls int
	var published []bpfAgentStatus
	write := func(status bpfAgentStatus) error {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			close(firstWriteEntered)
			<-releaseFirstWrite
		}
		mu.Lock()
		published = append(published, status)
		if status.LifecycleState == engineStateEnforcing {
			close(enforcingPublished)
		}
		mu.Unlock()
		return nil
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.updateAgentStatus(write)
	}()
	<-firstWriteEntered

	stateChangeStarted := make(chan struct{})
	stateChangeDone := make(chan error, 1)
	go func() {
		close(stateChangeStarted)
		store.setLifecycleState(engineStateEnforcing)
		stateChangeDone <- store.updateAgentStatus(write)
	}()
	<-stateChangeStarted

	select {
	case <-enforcingPublished:
		close(releaseFirstWrite)
		<-firstDone
		<-stateChangeDone
		t.Fatal("enforcing status was published before the in-progress starting write completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirstWrite)
	if err := <-firstDone; err != nil {
		t.Fatalf("publish starting status: %v", err)
	}
	if err := <-stateChangeDone; err != nil {
		t.Fatalf("publish enforcing status: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(published) != 2 {
		t.Fatalf("published %d status snapshots, want 2", len(published))
	}
	if published[0].LifecycleState != engineStateStarting || published[1].LifecycleState != engineStateEnforcing {
		t.Fatalf("status publication order = [%d %d], want starting then enforcing",
			published[0].LifecycleState, published[1].LifecycleState)
	}
}
