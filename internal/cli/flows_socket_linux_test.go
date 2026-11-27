//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"
	"golang.org/x/sys/unix"
)

type socketTestReader struct{ send <-chan flow.RawFlowEvent }

func (r socketTestReader) Available() bool { return true }
func (r socketTestReader) Stop() error     { return nil }
func (r socketTestReader) Start(ctx context.Context, dst chan<- flow.RawFlowEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-r.send:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case dst <- event:
			}
		}
	}
}

func TestSlowFlowSubscriberCannotBlockExporter(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	kernel := make(chan flow.RawFlowEvent)
	monitor := flow.NewMonitor(socketTestReader{send: kernel})
	export := monitor.SubscribeBeforeStart(ctx)
	var dropped atomic.Int32
	slow := monitor.SubscribeWithDrops(ctx, true, func() { dropped.Add(1) })
	if err := monitor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = monitor.Stop() }()
	// A full subscriber must never hold up fan-out to the export consumer.
	for i := range cap(slow) + 20 {
		want := uint64(i + 1) // #nosec G115 -- loop indexes are nonnegative
		select {
		case kernel <- flow.RawFlowEvent{CgroupID: want}:
		case <-ctx.Done():
			t.Fatal("monitor stopped accepting events")
		}
		select {
		case got := <-export:
			if got.CgroupID != want {
				t.Fatalf("export delivered cgroup %d, want %d", got.CgroupID, want)
			}
		case <-ctx.Done():
			t.Fatal("stalled subscriber blocked export")
		}
	}
	// Stop acquires the fan-out mutex, so the final drop is now observable.
	if err := monitor.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := dropped.Load(); got != 20 {
		t.Fatalf("slow subscriber drops = %d, want 20", got)
	}
}

func TestAgentFlowSocketFanOutAndRestart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("flow socket requires root peer credentials")
	}
	runDir := t.TempDir()
	oldLock, err := acquireFlowReaderLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireFlowReaderLock(runDir); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("a second reader could acquire lock, err=%v", err)
	}
	if err := oldLock(); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireFlowReaderLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()

	stalePath := filepath.Join(runDir, flowSocketName)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: stalePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := listenAgentFlows(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	stat, err := os.Lstat(stalePath)
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("expected owner-only agent flow socket, stat=%v err=%v", stat, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	kernel := make(chan flow.RawFlowEvent)
	monitor := flow.NewMonitor(socketTestReader{send: kernel})
	export := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = monitor.Stop() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serveAgentFlows(ctx, listener, monitor, func() {}); err != nil {
			t.Error(err)
		}
	}()
	stream, err := openAgentFlowSocket(ctx, runDir)
	if err != nil || stream == nil {
		t.Fatalf("open agent socket: %v", err)
	}
	defer func() { _ = stream.Close() }()

	probe := flow.RawFlowEvent{TimestampNs: 1, PolicyEpoch: 9, CgroupID: 43, Action: flow.ActionBlocked}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case kernel <- probe:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	conn := stream.(*net.UnixConn)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(stream)
	var ready, received agentFlowMessage
	if err := decoder.Decode(&ready); err != nil || !ready.Ready {
		t.Fatalf("expected subscription acknowledgement, got %+v, err %v", ready, err)
	}
	if err := decoder.Decode(&received); err != nil || received.Event == nil {
		t.Fatalf("expected flow event, got %+v, err %v", received, err)
	}
	select {
	case event := <-export:
		if received.Event.PolicyEpoch != event.PolicyEpoch || received.Event.CgroupID != event.CgroupID || received.Event.Action != event.Action {
			t.Fatalf("CLI saw %+v, exporter saw %+v", received, event)
		}
	case <-ctx.Done():
		t.Fatal("export subscriber did not receive traffic")
	}
	for i := 1; i < maxFlowClients; i++ {
		client, err := openAgentFlowSocket(ctx, runDir)
		if err != nil || client == nil {
			t.Fatalf("open flow subscription %d: %v", i+1, err)
		}
		defer func() { _ = client.Close() }()
		if err := client.(*net.UnixConn).SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var response agentFlowMessage
		if err := json.NewDecoder(client).Decode(&response); err != nil || !response.Ready {
			t.Fatalf("subscription %d was not acknowledged: %+v, err %v", i+1, response, err)
		}
	}
	rejected, err := openAgentFlowSocket(ctx, runDir)
	if err != nil || rejected == nil {
		t.Fatalf("open socket for rejected subscription: %v", err)
	}
	if err := streamAgentFlows(ctx, rejected, flow.FlowFilter{}, "json"); err == nil || !strings.Contains(err.Error(), "subscriptions are in use") {
		t.Fatalf("expected an explicit subscription error, got %v", err)
	}
	cancel()
	<-done
	// Records already written may still be buffered in the socket.
	for {
		if err := decoder.Decode(&received); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
	}
	if _, err := os.Lstat(stalePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after shutdown: %v", err)
	}
}

func TestLongRunDirFallsBackToDirectReader(t *testing.T) {
	runDir := filepath.Join(t.TempDir(), strings.Repeat("d", maxFlowSocketPath))
	err := streamFlows(t.Context(), flow.FlowFilter{}, "json", runDir, filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "open live flow stream") {
		t.Fatalf("expected direct reader to attempt opening the missing map, got %v", err)
	}
}

func TestAgentFlowStreamUnexpectedEOF(t *testing.T) {
	stream := io.NopCloser(strings.NewReader("{\"ready\":true}\n"))
	err := streamAgentFlows(t.Context(), stream, flow.FlowFilter{}, "json")
	if err == nil || !strings.Contains(err.Error(), "closed unexpectedly") {
		t.Fatalf("expected unexpected EOF error, got %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	reader, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	cancel()
	if err := streamAgentFlows(ctx, reader, flow.FlowFilter{}, "json"); err != nil {
		t.Fatalf("caller cancellation returned %v", err)
	}
}

type interruptedFlowListener struct {
	*net.UnixListener
	attempts int
}

func (l *interruptedFlowListener) AcceptUnix() (*net.UnixConn, error) {
	l.attempts++
	if l.attempts == 1 {
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: unix.EMFILE}
	}
	return nil, net.ErrClosed
}

func TestFlowSocketRetriesTransientAccept(t *testing.T) {
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "flow.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener := &interruptedFlowListener{UnixListener: socket}
	err = serveAgentFlows(t.Context(), listener, nil, nil)
	if !errors.Is(err, net.ErrClosed) || listener.attempts != 2 {
		t.Fatalf("accept attempts = %d, terminal error = %v", listener.attempts, err)
	}
}

func TestFlowClientTimeoutCountsPendingRecords(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	raw := make(chan flow.RawFlowEvent)
	monitor := flow.NewMonitor(socketTestReader{send: raw})
	observed := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = monitor.Stop() }()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	var lost atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAgentFlowClient(ctx, server, monitor, func() { lost.Add(1) })
	}()
	var ready agentFlowMessage
	if err := json.NewDecoder(client).Decode(&ready); err != nil || !ready.Ready {
		t.Fatalf("ready = %v, err = %v", ready.Ready, err)
	}
	// Leave the first event blocked on the pipe and queue the rest.
	const count = 5
	for range count {
		select {
		case raw <- flow.RawFlowEvent{}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case <-observed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := lost.Load(); got != count {
		t.Fatalf("lost = %d, want %d", got, count)
	}
}
