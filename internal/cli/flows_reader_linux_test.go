//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"
)

func TestMapOwningReaderStartRejectsCanceledContextBeforeOwnershipChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (&mapOwningReader{}).Start(ctx, make(chan flow.RawFlowEvent)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pinned flow reader start error = %v, want context.Canceled", err)
	}
}

func TestMapOwningReaderStartRechecksCancellationAfterWaitingForLock(t *testing.T) {
	reader := &mapOwningReader{inner: &startupCleanupFlowReader{}}
	reader.mu.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- reader.Start(ctx, make(chan flow.RawFlowEvent))
	}()
	cancel()
	reader.mu.Unlock()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("locked canceled pinned reader start error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pinned reader start did not return after lock release")
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.running || reader.done != nil {
		t.Fatalf("canceled startup created reader state: running=%t done=%v", reader.running, reader.done)
	}
}

func TestStreamFlowsRejectsCanceledContextBeforeLockOrPinnedMapOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runDir := filepath.Join(t.TempDir(), "run")
	if err := streamFlows(ctx, flow.FlowFilter{}, "json", runDir, filepath.Join(t.TempDir(), "bpffs")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled flow command error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("canceled flow command created run directory or stat failed: %v", err)
	}
}

func TestMonitorPinnedAgentStatusRejectsCanceledContextBeforeMapLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := monitorPinnedAgentStatus(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pinned status monitor error = %v, want context.Canceled", err)
	}
}

func TestJoinPinnedFlowReaderErrorsPreservesTerminalStatusFailures(t *testing.T) {
	readerErr := errors.New("reader stopped")
	statusErr := errors.New("agent heartbeat expired")
	stopErr := errors.New("reader close failed")

	tests := []struct {
		name       string
		ctx        context.Context
		readerErr  error
		statusErr  error
		stopErr    error
		wantErrors []error
		wantNil    bool
	}{
		{name: "reader and status errors", ctx: context.Background(), readerErr: readerErr, statusErr: statusErr, wantErrors: []error{readerErr, statusErr}},
		{name: "status error after clean reader exit", ctx: context.Background(), statusErr: statusErr, wantErrors: []error{statusErr}},
		{name: "stop error", ctx: context.Background(), statusErr: statusErr, stopErr: stopErr, wantErrors: []error{statusErr, stopErr}},
		{name: "internal cancellation is suppressed", ctx: context.Background(), readerErr: context.Canceled, statusErr: context.Canceled, wantNil: true},
		{name: "caller cancellation wins", ctx: canceledFlowReaderContext(), readerErr: readerErr, statusErr: statusErr, wantErrors: []error{context.Canceled}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := joinPinnedFlowReaderErrors(test.ctx, test.readerErr, test.statusErr, test.stopErr)
			if test.wantNil {
				if err != nil {
					t.Fatalf("joined error = %v, want nil", err)
				}
				return
			}
			for _, want := range test.wantErrors {
				if !errors.Is(err, want) {
					t.Fatalf("joined error = %v, does not contain %v", err, want)
				}
			}
		})
	}
}

func canceledFlowReaderContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestValidatePinnedAgentStatus(t *testing.T) {
	now := uint64(100 * time.Second)
	base := pinnedAgentStatus{
		SchemaVersion:  flowAgentStatusSchema,
		LifecycleState: flowAgentStateEnforcing,
		AgentEpoch:     7,
		HeartbeatNS:    now - uint64(time.Second),
	}

	epoch, err := validatePinnedAgentStatus(base, 0, false, now)
	if err != nil || epoch != 7 {
		t.Fatalf("initial status validation = epoch %d, error %v; want epoch 7 and nil error", epoch, err)
	}
	if _, err := validatePinnedAgentStatus(base, 7, true, now); err != nil {
		t.Fatalf("matching status validation: %v", err)
	}

	cases := []struct {
		name   string
		status pinnedAgentStatus
		expect string
	}{
		{name: "schema", status: pinnedAgentStatus{SchemaVersion: 2, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: base.HeartbeatNS}, expect: "unsupported agent status schema"},
		{name: "lifecycle", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: 1, AgentEpoch: 7, HeartbeatNS: base.HeartbeatNS}, expect: "not enforcing"},
		{name: "epoch", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 8, HeartbeatNS: base.HeartbeatNS}, expect: "agent epoch changed"},
		{name: "missing heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7}, expect: "heartbeat is missing"},
		{name: "future heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: now + uint64(time.Second)}, expect: "heartbeat is in the future"},
		{name: "heartbeat", status: pinnedAgentStatus{SchemaVersion: flowAgentStatusSchema, LifecycleState: flowAgentStateEnforcing, AgentEpoch: 7, HeartbeatNS: now - uint64(6*time.Second)}, expect: "heartbeat is older"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validatePinnedAgentStatus(test.status, 7, true, now); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("validation error = %v, want %q", err, test.expect)
			}
		})
	}
}

func TestOpenPinnedFlowReaderRejectsRelativeRoot(t *testing.T) {
	if _, err := openPinnedFlowReader("relative/bpffs"); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("openPinnedFlowReader error = %v, want an absolute-path validation error", err)
	}
}

func TestOpenPinnedFlowReaderRejectsSymlinkedRootComponent(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create intermediate root symlink: %v", err)
	}

	root := filepath.Join(link, "bpffs")
	if err := os.MkdirAll(filepath.Join(target, "bpffs"), 0o755); err != nil {
		t.Fatalf("create symlink target root: %v", err)
	}
	if _, err := openPinnedFlowReader(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("openPinnedFlowReader error = %v, want an intermediate symlink rejection", err)
	}
}

func TestLoadPinnedFlowMapAtRejectsPathNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../flow_events", "nested/flow_events"} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadPinnedFlowMapAt(-1, name, name); err == nil || !strings.Contains(err.Error(), "invalid pinned flow map name") {
				t.Fatalf("loadPinnedFlowMapAt error = %v, want invalid-name rejection", err)
			}
		})
	}
}

func TestOpenPinnedFlowReaderRejectsSymlinkedPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{
			name: "root",
			setup: func(t *testing.T, root string) {
				target := t.TempDir()
				if err := os.Symlink(target, root); err != nil {
					t.Fatalf("create bpffs-root symlink: %v", err)
				}
			},
		},
		{
			name: "pin directory",
			setup: func(t *testing.T, root string) {
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatalf("create bpffs root: %v", err)
				}
				target := t.TempDir()
				if err := os.Symlink(target, filepath.Join(root, "ztap")); err != nil {
					t.Fatalf("create pin-directory symlink: %v", err)
				}
			},
		},
		{
			name: "flow pin",
			setup: func(t *testing.T, root string) {
				pinDirectory := filepath.Join(root, "ztap")
				if err := os.MkdirAll(pinDirectory, 0o755); err != nil {
					t.Fatalf("create pin directory: %v", err)
				}
				target := filepath.Join(t.TempDir(), "flow_events")
				if err := os.WriteFile(target, []byte("not a BPF pin"), 0o600); err != nil {
					t.Fatalf("create pin target: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(pinDirectory, "flow_events")); err != nil {
					t.Fatalf("create flow pin symlink: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "bpffs")
			test.setup(t, root)
			if _, err := openPinnedFlowReader(root); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("openPinnedFlowReader error = %v, want a symlink rejection", err)
			}
		})
	}
}
