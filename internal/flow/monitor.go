package flow

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// subscriber wraps a flow event channel with close-once semantics.
type subscriber struct {
	id     uint64
	ch     chan FlowEvent
	onDrop func()
	closed bool
}

// Monitor reads flow events and distributes them to subscribers.
type Monitor struct {
	mu            sync.RWMutex
	running       bool
	started       bool
	stopped       bool
	stopCh        chan struct{}
	subscribers   map[uint64]*subscriber
	nextSubID     uint64
	stats         FlowStats
	reader        FlowReader // Platform-specific reader
	readerErr     error
	readerInvoked bool
	readerStopped bool
	readerDone    chan struct{}
	readerCancel  context.CancelFunc
	runGeneration uint64
	onDiscard     func(int)
}

// SetDiscardObserver reports buffered raw records discarded when stopping.
// Configure it before starting the monitor.
func (m *Monitor) SetDiscardObserver(observer func(int)) { m.onDiscard = observer }

// FlowReader is the platform-specific interface for reading flow events.
type FlowReader interface {
	// Start begins reading flow events from the kernel.
	Start(ctx context.Context, eventCh chan<- RawFlowEvent) error
	// Stop stops the reader.
	Stop() error
	// Available returns true if the reader can be used on this platform.
	Available() bool
}

// NewMonitor creates a new flow monitor with the given reader.
func NewMonitor(reader FlowReader) *Monitor {
	return &Monitor{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*subscriber),
		reader:      reader,
	}
}

// Start begins monitoring flow events.
func (m *Monitor) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("flow monitor context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.reader == nil {
		return errors.New("flow monitor reader is nil")
	}
	if !m.reader.Available() {
		return errors.New("flow monitor reader is unavailable")
	}
	for {
		m.mu.Lock()
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return err
		}
		if m.running {
			m.mu.Unlock()
			return nil
		}
		if previousDone := m.readerDone; previousDone != nil {
			select {
			case <-previousDone:
				m.readerDone = nil
			default:
				m.mu.Unlock()
				<-previousDone
				continue
			}
		}
		break
	}
	m.running = true
	m.started = true
	m.stopped = false
	m.readerErr = nil
	m.readerInvoked = false
	m.readerStopped = false
	m.runGeneration++
	runGeneration := m.runGeneration
	readerDone := make(chan struct{})
	m.readerDone = readerDone
	readerCtx, readerCancel := context.WithCancel(ctx)
	m.readerCancel = readerCancel
	m.stats.MonitorStarted = time.Now()
	// Capture stopCh under lock to avoid race with Stop()
	stopCh := m.stopCh
	m.mu.Unlock()

	// Create channel for raw events from reader
	rawEvents := make(chan RawFlowEvent, 1000)

	// Get boot time for timestamp conversion
	bootTime := getBootTime()

	// Start the platform-specific reader
	go func() {
		defer close(readerDone)
		defer readerCancel()
		m.mu.Lock()
		// Stop may win the race after Start returned but before this goroutine
		// entered the reader. Do not invoke a reader after ownership ended.
		if readerCtx.Err() != nil || !m.running || m.readerStopped || m.stopCh != stopCh || m.runGeneration != runGeneration {
			m.mu.Unlock()
			close(rawEvents)
			return
		}
		m.readerInvoked = true
		m.mu.Unlock()

		err := m.reader.Start(readerCtx, rawEvents)
		m.mu.Lock()
		if m.readerDone == readerDone {
			m.readerCancel = nil
		}
		if err != nil && readerCtx.Err() == nil && m.stopCh == stopCh && m.runGeneration == runGeneration {
			m.readerErr = err
		}
		m.mu.Unlock()
		close(rawEvents)
	}()

	// Process events and distribute to subscribers
	go m.processEvents(ctx, rawEvents, bootTime, stopCh, runGeneration)

	slog.Default().Info("flow monitor started")
	return nil
}

// Stop stops the flow monitor.
func (m *Monitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.stopped = true
		m.closeSubscribersLocked()
		shouldStopReader := m.started && !m.readerStopped && m.readerInvoked
		readerDone := m.readerDone
		readerCancel := m.readerCancel
		m.readerCancel = nil
		m.readerStopped = true
		m.mu.Unlock()
		var stopErr error
		if readerCancel != nil {
			readerCancel()
		}
		if shouldStopReader {
			stopErr = m.reader.Stop()
		}
		if readerDone != nil {
			<-readerDone
		}
		return stopErr
	}
	m.running = false
	m.stopped = true

	// Close stopCh to signal processEvents to exit
	select {
	case <-m.stopCh:
		// Already closed
	default:
		close(m.stopCh)
	}

	// Close all subscriber channels under the lock
	m.closeSubscribersLocked()

	// Recreate stopCh for potential restart
	m.stopCh = make(chan struct{})
	shouldStopReader := m.readerInvoked
	readerDone := m.readerDone
	readerCancel := m.readerCancel
	m.readerCancel = nil
	m.readerStopped = true
	m.mu.Unlock()

	var stopErr error
	if readerCancel != nil {
		readerCancel()
	}
	if shouldStopReader {
		stopErr = m.reader.Stop()
	}
	if readerDone != nil {
		<-readerDone
	}
	if stopErr != nil {
		return stopErr
	}

	slog.Default().Info("flow monitor stopped")
	return nil
}

// Err reports a terminal reader error after the monitor's subscriptions have
// closed. Context cancellation and an intentional Stop are not reported as
// reader failures.
func (m *Monitor) Err() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.readerErr
}

// Subscribe returns a channel that receives flow events. The monitor must
// already be running; use SubscribeBeforeStart when a subscriber must be
// registered before the reader is started.
func (m *Monitor) Subscribe(ctx context.Context) <-chan FlowEvent {
	return m.SubscribeWithDrops(ctx, false, nil)
}

// SubscribeBeforeStart registers a subscriber before Start launches the
// reader. This prevents fast readers from dropping startup events between
// Start and a subsequent Subscribe call. It is closed if the monitor has
// already been stopped.
func (m *Monitor) SubscribeBeforeStart(ctx context.Context) <-chan FlowEvent {
	return m.SubscribeWithDrops(ctx, true, nil)
}

// SubscribeWithDrops observes full-channel losses for one consumer. onDrop
// runs during fan-out and must return immediately.
func (m *Monitor) SubscribeWithDrops(ctx context.Context, allowBeforeStart bool, onDrop func()) <-chan FlowEvent {
	ch := make(chan FlowEvent, 100)
	if ctx == nil {
		// A nil context cannot express cancellation. Do not create an
		// uncancellable subscriber or start a goroutine that would panic on
		// ctx.Done(); an invalid subscription is represented by a closed channel.
		close(ch)
		return ch
	}

	m.mu.Lock()
	if !m.running && (!allowBeforeStart || m.started || m.stopped) {
		m.mu.Unlock()
		close(ch)
		return ch
	}
	m.nextSubID++
	sub := &subscriber{id: m.nextSubID, ch: ch, onDrop: onDrop}
	m.subscribers[sub.id] = sub
	m.mu.Unlock()

	// A context without a Done channel is intentionally non-cancellable. The
	// monitor lifecycle still closes this subscription on Stop, so no watcher
	// goroutine is needed for the common context.Background() case.
	done := ctx.Done()
	if done == nil {
		return ch
	}

	// Handle context cancellation.
	go func() {
		<-done
		m.mu.Lock()
		defer m.mu.Unlock()

		// Remove this subscriber and close the channel if not already closed.
		if tracked, ok := m.subscribers[sub.id]; ok {
			delete(m.subscribers, sub.id)
			if !tracked.closed {
				tracked.closed = true
				close(tracked.ch)
			}
		}
	}()

	return ch
}

// GetStats returns current flow statistics.
func (m *Monitor) GetStats() FlowStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	if !stats.MonitorStarted.IsZero() {
		elapsed := time.Since(stats.MonitorStarted).Seconds()
		if elapsed > 0 {
			stats.EventsPerSec = float64(stats.TotalEvents) / elapsed
		}
	}
	return stats
}

// IsRunning returns true if the monitor is actively running.
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// processEvents converts raw events and distributes to subscribers.
func (m *Monitor) processEvents(ctx context.Context, rawEvents <-chan RawFlowEvent, bootTime time.Time, stopCh <-chan struct{}, runGeneration uint64) {
	discarded := 0
	if m.onDiscard != nil {
		defer func() {
			for range rawEvents {
				discarded++
			}
			if discarded > 0 {
				m.onDiscard(discarded)
			}
		}()
	}
	for {
		select {
		case <-stopCh:
			return
		case <-ctx.Done():
			// Context cancellation is an external shutdown request, not a
			// terminal reader error. Route it through the same lifecycle path
			// as an explicit Stop so subscribers are closed and a later Start
			// cannot inherit a run that only exists in the monitor's state.
			if err := m.Stop(); err != nil {
				slog.Default().Warn("flow monitor stopped with reader error", "error", err)
			}
			return
		case raw, ok := <-rawEvents:
			if !ok {
				m.mu.Lock()
				// A stopped monitor can be restarted before the old reader
				// goroutine has finished unwinding. Do not let that stale
				// goroutine close subscribers or change the new run's state.
				if m.stopCh == stopCh && m.runGeneration == runGeneration {
					m.running = false
					m.stopped = true
					m.closeSubscribersLocked()
				}
				m.mu.Unlock()
				return
			}

			event := observeFlowEvent(raw, bootTime, time.Now(), uptimeNsFunc())

			// Keep the generation check, stats update, and non-blocking
			// broadcast under one lock. A stale processor from a previous
			// run must not deliver into the replacement run after Stop/start.
			m.mu.Lock()
			if !m.running || m.stopCh != stopCh || m.runGeneration != runGeneration {
				m.mu.Unlock()
				discarded++
				return
			}
			m.stats.TotalEvents++
			m.stats.LastEventTime = event.Timestamp
			if event.Action == "allowed" {
				m.stats.AllowedEvents++
			} else {
				m.stats.BlockedEvents++
			}
			if event.Direction == "egress" {
				m.stats.EgressEvents++
			} else {
				m.stats.IngressEvents++
			}
			for _, sub := range m.subscribers {
				if !sub.closed {
					select {
					case sub.ch <- event:
					default:
						if sub.onDrop != nil {
							sub.onDrop()
						}
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

func observeFlowEvent(raw RawFlowEvent, bootTime, observedAt time.Time, observedNS int64) FlowEvent {
	// Sample the wall and monotonic clocks together. The difference between
	// two monotonic readings preserves time spent waiting in the ring or in
	// the reader channel, and CLOCK_MONOTONIC excludes suspend like BPF ktime.
	if observedNS > 0 && raw.TimestampNs <= uint64(observedNS) { // #nosec G115 -- observedNS is positive
		bootTime = observedAt.Add(-time.Duration(observedNS))
	}
	event := raw.ToFlowEvent(bootTime)
	event.ObservedAt = observedAt
	return event
}

func (m *Monitor) closeSubscribersLocked() {
	for _, sub := range m.subscribers {
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
	}
	m.subscribers = make(map[uint64]*subscriber)
}

// getBootTime anchors records from readers without a per-record clock sample.
func getBootTime() time.Time {
	return time.Now().Add(-time.Duration(uptimeNsFunc()))
}

var uptimeNsFunc = func() int64 { return 0 }
