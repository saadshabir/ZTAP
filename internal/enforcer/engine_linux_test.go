//go:build linux

package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ztap/internal/policy"
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
