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
	closed bool
}

// Monitor implements FlowMonitor with subscriber management.
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
	runGeneration uint64
}

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
	if m.reader == nil {
		return errors.New("flow monitor reader is nil")
	}
	for {
		m.mu.Lock()
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
		m.mu.Lock()
		// Stop may win the race after Start returned but before this goroutine
		// entered the reader. Do not invoke a reader after ownership ended.
		if !m.running || m.readerStopped || m.stopCh != stopCh || m.runGeneration != runGeneration {
			m.mu.Unlock()
			close(rawEvents)
			return
		}
		m.readerInvoked = true
		m.mu.Unlock()

		err := m.reader.Start(ctx, rawEvents)
		m.mu.Lock()
		if err != nil && ctx.Err() == nil && m.stopCh == stopCh && m.runGeneration == runGeneration {
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
		m.readerStopped = true
		m.mu.Unlock()
		var stopErr error
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
	m.readerStopped = true
	m.mu.Unlock()

	var stopErr error
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
	return m.subscribe(ctx, false)
}

// SubscribeBeforeStart registers a subscriber before Start launches the
// reader. This prevents fast readers from dropping startup events between
// Start and a subsequent Subscribe call. It is closed if the monitor has
// already been stopped.
func (m *Monitor) SubscribeBeforeStart(ctx context.Context) <-chan FlowEvent {
	return m.subscribe(ctx, true)
}

func (m *Monitor) subscribe(ctx context.Context, allowBeforeStart bool) <-chan FlowEvent {
	ch := make(chan FlowEvent, 100)

	m.mu.Lock()
	if !m.running && (!allowBeforeStart || m.started || m.stopped) {
		m.mu.Unlock()
		close(ch)
		return ch
	}
	m.nextSubID++
	sub := &subscriber{id: m.nextSubID, ch: ch}
	m.subscribers[sub.id] = sub
	m.mu.Unlock()

	// Handle context cancellation.
	go func() {
		<-ctx.Done()
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
	for {
		select {
		case <-stopCh:
			return
		case <-ctx.Done():
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

			event := raw.ToFlowEvent(bootTime)

			// Keep the generation check, stats update, and non-blocking
			// broadcast under one lock. A stale processor from a previous
			// run must not deliver into the replacement run after Stop/start.
			m.mu.Lock()
			if !m.running || m.stopCh != stopCh || m.runGeneration != runGeneration {
				m.mu.Unlock()
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
						// Drop event if subscriber is slow
					}
				}
			}
			m.mu.Unlock()
		}
	}
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

// getBootTime returns the system boot time for converting kernel timestamps.
func getBootTime() time.Time {
	// Kernel timestamps from bpf_ktime_get_ns() are nanoseconds since boot.
	// We need the boot time to convert to wall clock time.
	// This is a simplified approach - on Linux we could read /proc/uptime.
	return time.Now().Add(-time.Duration(uptimeNsFunc()))
}

var uptimeNsFunc = func() int64 { return 0 }
