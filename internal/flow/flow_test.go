package flow

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFlowEventConversion(t *testing.T) {
	bootTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		raw      RawFlowEvent
		expected FlowEvent
	}{
		{
			name: "TCP egress allowed",
			raw: RawFlowEvent{
				TimestampNs: uint64(1 * time.Second),
				SrcIP:       [4]uint32{0x0A000101}, // 10.0.1.1 in big-endian
				DestIP:      [4]uint32{0x0A000201}, // 10.0.2.1
				SrcPort:     45678,
				DestPort:    5432,
				Protocol:    ProtocolTCP,
				Direction:   DirectionEgress,
				Action:      ActionAllowed,
				Family:      4,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(10, 0, 1, 1),
				DestIP:     net.IPv4(10, 0, 2, 1),
				SourcePort: 45678,
				DestPort:   5432,
				Protocol:   "TCP",
				Direction:  "egress",
				Action:     "allowed",
			},
		},
		{
			name: "UDP ingress blocked",
			raw: RawFlowEvent{
				TimestampNs: uint64(2 * time.Second),
				SrcIP:       [4]uint32{0xC0A80164}, // 192.168.1.100
				DestIP:      [4]uint32{0x0A000101},
				SrcPort:     53421,
				DestPort:    53,
				Protocol:    ProtocolUDP,
				Direction:   DirectionIngress,
				Action:      ActionBlocked,
				Family:      4,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(192, 168, 1, 100),
				DestIP:     net.IPv4(10, 0, 1, 1),
				SourcePort: 53421,
				DestPort:   53,
				Protocol:   "UDP",
				Direction:  "ingress",
				Action:     "blocked",
			},
		},
		{
			name: "ICMP egress",
			raw: RawFlowEvent{
				TimestampNs: uint64(3 * time.Second),
				SrcIP:       [4]uint32{0x0A000101},
				DestIP:      [4]uint32{0x08080808}, // 8.8.8.8
				SrcPort:     0,
				DestPort:    0,
				Protocol:    ProtocolICMP,
				Direction:   DirectionEgress,
				Action:      ActionAllowed,
				Family:      4,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(10, 0, 1, 1),
				DestIP:     net.IPv4(8, 8, 8, 8),
				SourcePort: 0,
				DestPort:   0,
				Protocol:   "ICMP",
				Direction:  "egress",
				Action:     "allowed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.raw.ToFlowEvent(bootTime)
			if !result.SourceIP.Equal(tt.expected.SourceIP) {
				t.Errorf("SourceIP = %v, want %v", result.SourceIP, tt.expected.SourceIP)
			}
			if !result.DestIP.Equal(tt.expected.DestIP) {
				t.Errorf("DestIP = %v, want %v", result.DestIP, tt.expected.DestIP)
			}
			if result.SourcePort != tt.expected.SourcePort {
				t.Errorf("SourcePort = %d, want %d", result.SourcePort, tt.expected.SourcePort)
			}
			if result.DestPort != tt.expected.DestPort {
				t.Errorf("DestPort = %d, want %d", result.DestPort, tt.expected.DestPort)
			}
			if result.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol = %s, want %s", result.Protocol, tt.expected.Protocol)
			}
			if result.Direction != tt.expected.Direction {
				t.Errorf("Direction = %s, want %s", result.Direction, tt.expected.Direction)
			}
			if result.Action != tt.expected.Action {
				t.Errorf("Action = %s, want %s", result.Action, tt.expected.Action)
			}
		})
	}
}

func TestFlowFilter(t *testing.T) {
	event := FlowEvent{
		Timestamp:  time.Now(),
		SourceIP:   net.IPv4(10, 0, 1, 1),
		DestIP:     net.IPv4(10, 0, 2, 1),
		SourcePort: 45678,
		DestPort:   5432,
		Protocol:   "TCP",
		Direction:  "egress",
		Action:     "allowed",
	}

	tests := []struct {
		name    string
		filter  FlowFilter
		matches bool
	}{
		{
			name:    "empty filter matches all",
			filter:  FlowFilter{},
			matches: true,
		},
		{
			name:    "action filter matches",
			filter:  FlowFilter{Action: "allowed"},
			matches: true,
		},
		{
			name:    "action filter no match",
			filter:  FlowFilter{Action: "blocked"},
			matches: false,
		},
		{
			name:    "protocol filter matches",
			filter:  FlowFilter{Protocol: "TCP"},
			matches: true,
		},
		{
			name:    "protocol filter no match",
			filter:  FlowFilter{Protocol: "UDP"},
			matches: false,
		},
		{
			name:    "direction filter matches",
			filter:  FlowFilter{Direction: "egress"},
			matches: true,
		},
		{
			name:    "direction filter no match",
			filter:  FlowFilter{Direction: "ingress"},
			matches: false,
		},
		{
			name:    "source IP filter matches",
			filter:  FlowFilter{SourceIP: net.IPv4(10, 0, 1, 1)},
			matches: true,
		},
		{
			name:    "source IP filter no match",
			filter:  FlowFilter{SourceIP: net.IPv4(192, 168, 1, 1)},
			matches: false,
		},
		{
			name:    "port filter matches source",
			filter:  FlowFilter{Port: 45678},
			matches: true,
		},
		{
			name:    "port filter matches dest",
			filter:  FlowFilter{Port: 5432},
			matches: true,
		},
		{
			name:    "port filter no match",
			filter:  FlowFilter{Port: 80},
			matches: false,
		},
		{
			name:    "combined filters match",
			filter:  FlowFilter{Action: "allowed", Protocol: "TCP", Direction: "egress"},
			matches: true,
		},
		{
			name:    "combined filters partial no match",
			filter:  FlowFilter{Action: "allowed", Protocol: "UDP", Direction: "egress"},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Matches(event)
			if result != tt.matches {
				t.Errorf("Matches() = %v, want %v", result, tt.matches)
			}
		})
	}
}

// testReader is a simple reader for testing that sends pre-configured events.
type testReader struct {
	mu      sync.Mutex
	events  []RawFlowEvent
	running bool
}

func (r *testReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	for _, event := range r.events {
		event.TimestampNs = uint64(time.Now().UnixNano())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case eventCh <- event:
		}
	}
	// Keep running until context cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (r *testReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	return nil
}

func (r *testReader) Available() bool {
	return true
}

type terminalReader struct {
	err error
}

func (r *terminalReader) Start(context.Context, chan<- RawFlowEvent) error {
	return r.err
}

func (*terminalReader) Stop() error {
	return nil
}

func (*terminalReader) Available() bool {
	return true
}

type unavailableReader struct{}

func (*unavailableReader) Start(context.Context, chan<- RawFlowEvent) error {
	return errors.New("unavailable reader must not start")
}

func (*unavailableReader) Stop() error { return nil }

func (*unavailableReader) Available() bool { return false }

func TestMonitorRejectsUnavailableReaderBeforeStarting(t *testing.T) {
	monitor := NewMonitor(&unavailableReader{})
	if err := monitor.Start(context.Background()); err == nil {
		t.Fatal("monitor.Start accepted an unavailable flow reader")
	} else if !strings.Contains(err.Error(), "reader is unavailable") {
		t.Fatalf("unavailable reader error = %v, want availability failure", err)
	}
	if monitor.IsRunning() {
		t.Fatal("monitor became running with an unavailable reader")
	}
}

func TestMonitorRejectsCanceledContextBeforeStarting(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	monitor := NewMonitor(&testReader{})

	if err := monitor.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("monitor.Start error = %v, want context.Canceled", err)
	}
	if monitor.IsRunning() {
		t.Fatal("monitor became running with an already-canceled context")
	}
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	if monitor.readerInvoked || monitor.readerDone != nil {
		t.Fatalf("canceled monitor start created reader state: invoked=%t done=%v", monitor.readerInvoked, monitor.readerDone)
	}
}

type gatedStartReader struct {
	startGate chan struct{}
	stopOnce  sync.Once
	stopCh    chan struct{}
	mu        sync.Mutex
	started   bool
}

func newGatedStartReader() *gatedStartReader {
	return &gatedStartReader{startGate: make(chan struct{}), stopCh: make(chan struct{})}
}

func (r *gatedStartReader) Start(ctx context.Context, _ chan<- RawFlowEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.startGate:
	case <-r.stopCh:
		return nil
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopCh:
		return nil
	}
}

func (r *gatedStartReader) Stop() error {
	r.stopOnce.Do(func() { close(r.stopCh) })
	r.mu.Lock()
	r.started = false
	r.mu.Unlock()
	return nil
}

func (r *gatedStartReader) Available() bool { return true }

func (r *gatedStartReader) isStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}

type slowStopReader struct {
	started   chan struct{}
	stopped   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func newSlowStopReader() *slowStopReader {
	return &slowStopReader{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *slowStopReader) Start(_ context.Context, _ chan<- RawFlowEvent) error {
	r.startOnce.Do(func() { close(r.started) })
	<-r.stopped
	<-r.release
	return nil
}

func (r *slowStopReader) Stop() error {
	r.stopOnce.Do(func() { close(r.stopped) })
	return nil
}

func (*slowStopReader) Available() bool { return true }

type contextBlockingReader struct {
	started   chan struct{}
	startOnce sync.Once
}

func (r *contextBlockingReader) Start(ctx context.Context, _ chan<- RawFlowEvent) error {
	r.startOnce.Do(func() { close(r.started) })
	<-ctx.Done()
	return ctx.Err()
}

func (*contextBlockingReader) Stop() error { return nil }

func (*contextBlockingReader) Available() bool { return true }

func TestMonitorStopCannotStartReaderAfterOwnershipEnds(t *testing.T) {
	reader := newGatedStartReader()
	monitor := NewMonitor(reader)
	ctx := t.Context()
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := monitor.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	// Release a reader goroutine if it entered Start before Stop acquired the
	// monitor lock. A reader that had not been invoked must never start now.
	close(reader.startGate)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !reader.isStarted() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("flow reader remained started after monitor Stop")
}

func TestMonitorStopWaitsForReaderGoroutine(t *testing.T) {
	reader := newSlowStopReader()
	monitor := NewMonitor(reader)
	if err := monitor.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("reader did not start")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- monitor.Stop() }()
	select {
	case <-reader.stopped:
	case <-time.After(time.Second):
		t.Fatal("monitor did not ask reader to stop")
	}
	select {
	case err := <-stopped:
		t.Fatalf("Stop() returned before reader goroutine unwound: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(reader.release)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop() did not return after reader goroutine unwound")
	}
}

func TestMonitorStopCancelsReaderContext(t *testing.T) {
	reader := &contextBlockingReader{started: make(chan struct{})}
	monitor := NewMonitor(reader)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("reader did not start")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- monitor.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	case <-time.After(time.Second):
		// Keep the test goroutine from leaking if the regression is present:
		// canceling the caller context releases a reader that ignores Stop.
		cancel()
		select {
		case <-stopped:
		case <-time.After(time.Second):
		}
		t.Fatal("Stop() did not cancel the reader context")
	}
}

func TestMonitorReportsTerminalReaderErrorAndClosesSubscribers(t *testing.T) {
	wantErr := errors.New("pinned agent stopped enforcing")
	monitor := NewMonitor(&terminalReader{err: wantErr})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("subscriber received an event from a terminal reader")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber was not closed after reader termination")
	}
	if !errors.Is(monitor.Err(), wantErr) {
		t.Fatalf("monitor.Err() = %v, want %v", monitor.Err(), wantErr)
	}
	if monitor.IsRunning() {
		t.Fatal("monitor remains running after reader termination")
	}
	if err := monitor.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestMonitorNilSubscriptionContextReturnsClosedChannel(t *testing.T) {
	monitor := NewMonitor(&testReader{})

	for name, subscribe := range map[string]func(context.Context) <-chan FlowEvent{
		"running subscription":      monitor.Subscribe,
		"before-start subscription": monitor.SubscribeBeforeStart,
	} {
		t.Run(name, func(t *testing.T) {
			events := subscribe(nil)
			select {
			case _, ok := <-events:
				if ok {
					t.Fatal("nil-context subscription returned an event")
				}
			case <-time.After(time.Second):
				t.Fatal("nil-context subscription was not closed")
			}
		})
	}

	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	if len(monitor.subscribers) != 0 {
		t.Fatalf("nil-context subscriptions were registered: %d", len(monitor.subscribers))
	}
}

func TestMonitorNonCancellableSubscriptionClosesWithMonitor(t *testing.T) {
	monitor := NewMonitor(&testReader{})
	events := monitor.SubscribeBeforeStart(context.Background())

	monitor.mu.RLock()
	if got := len(monitor.subscribers); got != 1 {
		monitor.mu.RUnlock()
		t.Fatalf("non-cancellable subscription count = %d, want 1", got)
	}
	monitor.mu.RUnlock()

	if err := monitor.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("non-cancellable subscription remained open after monitor Stop")
		}
	case <-time.After(time.Second):
		t.Fatal("non-cancellable subscription was not closed by monitor Stop")
	}
}

func TestMonitorStaleEventProcessorCannotStopNewRun(t *testing.T) {
	monitor := NewMonitor(&terminalReader{})
	currentStop := make(chan struct{})
	staleStop := make(chan struct{})
	staleEvents := make(chan RawFlowEvent, 1)
	staleEvents <- RawFlowEvent{DestPort: 443, Protocol: ProtocolTCP, Family: 4}
	close(staleEvents)

	monitor.mu.Lock()
	monitor.running = true
	monitor.started = true
	monitor.stopCh = currentStop
	monitor.runGeneration = 2
	monitor.mu.Unlock()
	currentEvents := monitor.Subscribe(t.Context())

	// This simulates the tail of generation 1 arriving after generation 2
	// has already taken ownership of the monitor state.
	monitor.processEvents(t.Context(), staleEvents, time.Now(), staleStop, 1)
	if !monitor.IsRunning() {
		t.Fatal("stale event processor stopped the current monitor run")
	}
	if stats := monitor.GetStats(); stats.TotalEvents != 0 {
		t.Fatalf("stale event processor changed current statistics: %+v", stats)
	}
	select {
	case event := <-currentEvents:
		t.Fatalf("stale event reached current subscriber: %+v", event)
	default:
	}
}

func TestMonitorIsRunning(t *testing.T) {
	monitor := NewMonitor(&testReader{})
	if monitor.IsRunning() {
		t.Fatal("new monitor should not be running")
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !monitor.IsRunning() {
		t.Fatal("started monitor should be running")
	}
	cancel()
	if err := monitor.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if monitor.IsRunning() {
		t.Fatal("stopped monitor should not be running")
	}
}

func TestMonitorContextCancellationStopsRunAndAllowsRestart(t *testing.T) {
	reader := &testReader{}
	monitor := NewMonitor(reader)
	ctx, cancel := context.WithCancel(t.Context())
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("subscriber remained open after monitor context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber was not closed after monitor context cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for monitor.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if monitor.IsRunning() {
		t.Fatal("monitor remained running after context cancellation")
	}

	restartCtx, restartCancel := context.WithCancel(t.Context())
	defer func() {
		restartCancel()
		_ = monitor.Stop()
	}()
	if err := monitor.Start(restartCtx); err != nil {
		t.Fatalf("restart Start() error = %v", err)
	}
	if !monitor.IsRunning() {
		t.Fatal("monitor did not restart after context cancellation")
	}
	restartCancel()
	deadline = time.Now().Add(time.Second)
	for monitor.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if monitor.IsRunning() {
		t.Fatal("restarted monitor remained running after context cancellation")
	}
}

func TestMonitorSubscribeBeforeStart(t *testing.T) {
	reader := &testReader{events: []RawFlowEvent{{
		SrcIP:     [4]uint32{0x0A000101},
		DestIP:    [4]uint32{0x0A000201},
		DestPort:  443,
		Protocol:  ProtocolTCP,
		Direction: DirectionEgress,
		Action:    ActionAllowed,
		Family:    4,
	}}}
	monitor := NewMonitor(reader)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() {
		cancel()
		_ = monitor.Stop()
	}()

	// Register before Start so an immediately-emitting reader cannot race the
	// subscriber setup.
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case event := <-events:
		if event.DestPort != 443 {
			t.Fatalf("unexpected startup event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for startup event")
	}
}

func TestMonitorSubscription(t *testing.T) {
	// Create a mock reader that sends events with delay
	events := []RawFlowEvent{
		{
			TimestampNs: uint64(time.Now().UnixNano()),
			SrcIP:       [4]uint32{0x0A000101},
			DestIP:      [4]uint32{0x0A000201},
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    ProtocolTCP,
			Direction:   DirectionEgress,
			Action:      ActionAllowed,
			Family:      4,
		},
		{
			TimestampNs: uint64(time.Now().UnixNano()),
			SrcIP:       [4]uint32{0xC0A80164},
			DestIP:      [4]uint32{0x0A000101},
			SrcPort:     53421,
			DestPort:    22,
			Protocol:    ProtocolTCP,
			Direction:   DirectionIngress,
			Action:      ActionBlocked,
			Family:      4,
		},
	}
	reader := &delayedReader{events: events, delay: 100 * time.Millisecond}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer func() {
		cancel()
		_ = monitor.Stop()
	}()

	// Start monitor first
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Subscribe after starting (monitor is now running)
	eventCh := monitor.Subscribe(ctx)

	// Collect events
	received := make([]FlowEvent, 0)
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				break loop
			}
			received = append(received, event)
			if len(received) >= len(events) {
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	// Verify we received events
	if len(received) == 0 {
		t.Error("Expected to receive events, got none")
	}

	// Check stats
	stats := monitor.GetStats()
	if stats.TotalEvents == 0 {
		t.Error("Expected TotalEvents > 0")
	}
}

// delayedReader sends events with a delay to allow subscribers to connect
type delayedReader struct {
	mu      sync.Mutex
	events  []RawFlowEvent
	delay   time.Duration
	running bool
}

func (r *delayedReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	// Wait a bit to ensure subscriber is connected
	time.Sleep(r.delay)
	for _, event := range r.events {
		event.TimestampNs = uint64(time.Now().UnixNano())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case eventCh <- event:
		}
		time.Sleep(10 * time.Millisecond) // Small delay between events
	}
	// Keep running until context cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (r *delayedReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	return nil
}

func (r *delayedReader) Available() bool {
	return true
}

func TestMonitorStats(t *testing.T) {
	reader := &testReader{events: []RawFlowEvent{
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionAllowed},
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionBlocked},
		{Protocol: ProtocolUDP, Direction: DirectionIngress, Action: ActionAllowed},
	}}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer func() {
		cancel()
		_ = monitor.Stop()
	}()

	_ = monitor.Start(ctx)

	// Subscribe and drain events
	eventCh := monitor.Subscribe(ctx)
	count := 0
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case _, ok := <-eventCh:
			if !ok {
				break loop
			}
			count++
			if count >= 3 {
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	stats := monitor.GetStats()
	if stats.AllowedEvents != 2 {
		t.Errorf("AllowedEvents = %d, want 2", stats.AllowedEvents)
	}
	if stats.BlockedEvents != 1 {
		t.Errorf("BlockedEvents = %d, want 1", stats.BlockedEvents)
	}
	if stats.EgressEvents != 2 {
		t.Errorf("EgressEvents = %d, want 2", stats.EgressEvents)
	}
	if stats.IngressEvents != 1 {
		t.Errorf("IngressEvents = %d, want 1", stats.IngressEvents)
	}
}

func TestProtocolToString(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{ProtocolTCP, "TCP"},
		{ProtocolUDP, "UDP"},
		{ProtocolICMP, "ICMP"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := protocolToString(tt.proto)
		if result != tt.expected {
			t.Errorf("protocolToString(%d) = %s, want %s", tt.proto, result, tt.expected)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		input    uint32
		expected net.IP
	}{
		{0x0A000101, net.IPv4(10, 0, 1, 1)},
		{0xC0A80164, net.IPv4(192, 168, 1, 100)},
		{0x08080808, net.IPv4(8, 8, 8, 8)},
		{0x00000000, net.IPv4(0, 0, 0, 0)},
		{0xFFFFFFFF, net.IPv4(255, 255, 255, 255)},
	}

	for _, tt := range tests {
		result := uint32ToIP(tt.input)
		if !result.Equal(tt.expected) {
			t.Errorf("uint32ToIP(0x%08X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestMonitor_SubscriberLifecycle_NoPanic(t *testing.T) {
	// This test verifies that stopping a monitor while a subscriber's context
	// is cancelled does not cause a double-close panic.
	reader := &delayedReader{events: []RawFlowEvent{
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionAllowed},
	}, delay: 50 * time.Millisecond}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Create multiple subscribers
	subCtx1, subCancel1 := context.WithCancel(ctx)
	subCtx2, subCancel2 := context.WithCancel(ctx)
	ch1 := monitor.Subscribe(subCtx1)
	ch2 := monitor.Subscribe(subCtx2)
	_ = ch1
	_ = ch2

	// Cancel one subscriber's context right before stopping
	subCancel1()
	time.Sleep(10 * time.Millisecond) // Give goroutine time to run

	// Stop the monitor - should close remaining subscribers without panic
	cancel()
	if err := monitor.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Cancel the second subscriber's context after stop
	subCancel2()
	time.Sleep(10 * time.Millisecond)

	// Verify channels are closed
	select {
	case _, ok := <-ch1:
		if ok {
			// Might receive a buffered event, drain
			for range ch1 {
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("ch1 should be closed")
	}

	select {
	case _, ok := <-ch2:
		if ok {
			for range ch2 {
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("ch2 should be closed")
	}
}

func TestMonitor_SubscribeAfterStop(t *testing.T) {
	reader := &testReader{events: nil}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithCancel(t.Context())
	_ = monitor.Start(ctx)
	cancel()
	_ = monitor.Stop()

	// Subscribing after stop should return a closed channel
	ch := monitor.Subscribe(ctx)
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected closed channel after stop")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("channel should be closed immediately")
	}
}

func TestMonitor_ConcurrentSubscribeUnsubscribe(t *testing.T) {
	reader := &delayedReader{events: []RawFlowEvent{
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionAllowed},
		{Protocol: ProtocolUDP, Direction: DirectionIngress, Action: ActionBlocked},
	}, delay: 50 * time.Millisecond}

	monitor := NewMonitor(reader)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	var wg sync.WaitGroup
	// Spin up multiple subscribers that cancel at different times
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			subCtx, subCancel := context.WithTimeout(ctx, time.Duration(50+n*10)*time.Millisecond)
			ch := monitor.Subscribe(subCtx)
			for range ch {
			}
			subCancel()
		}(i)
	}

	// Stop the monitor while subscribers are active
	time.Sleep(100 * time.Millisecond)
	cancel()
	_ = monitor.Stop()

	// Wait for all goroutines to finish without panic
	wg.Wait()
}
