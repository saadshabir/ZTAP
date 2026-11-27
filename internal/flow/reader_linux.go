//go:build linux
// +build linux

package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// LinuxReader reads flow events from the eBPF ring buffer on Linux.
type LinuxReader struct {
	mu        sync.Mutex
	ringbuf   linuxRingReader
	flowMap   *ebpf.Map
	newReader func(*ebpf.Map) (linuxRingReader, error)
	running   bool
	stopCh    chan struct{}
	onDrop    func(string)
}

// SetDropObserver configures loss reporting before the reader starts.
func (r *LinuxReader) SetDropObserver(observer func(string)) { r.onDrop = observer }

type linuxRingReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

// NewLinuxReader creates a new Linux flow reader.
// The flowEventsMap should be the "flow_events" ring buffer from the loaded eBPF program.
func NewLinuxReader(flowEventsMap *ebpf.Map) (*LinuxReader, error) {
	if flowEventsMap == nil {
		return nil, errors.New("flow_events map is nil")
	}

	// Verify it's a ring buffer
	info, err := flowEventsMap.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get map info: %w", err)
	}
	if info.Type != ebpf.RingBuf {
		return nil, fmt.Errorf("expected RingBuf map, got %s", info.Type)
	}

	return &LinuxReader{
		flowMap: flowEventsMap,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start begins reading flow events from the ring buffer.
func (r *LinuxReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	if ctx == nil {
		return errors.New("linux flow reader context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	// Cancellation may arrive while a concurrent Stop or lifecycle inspection
	// holds the reader lock. Recheck before opening a kernel ring reader so a
	// canceled startup cannot create externally visible reader state.
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
	if r.running {
		r.mu.Unlock()
		return nil
	}
	if r.flowMap == nil {
		r.mu.Unlock()
		return errors.New("flow_events map is unavailable")
	}

	newReader := r.newReader
	if newReader == nil {
		newReader = func(flowEventsMap *ebpf.Map) (linuxRingReader, error) {
			return ringbuf.NewReader(flowEventsMap)
		}
	}
	reader, err := newReader(r.flowMap)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	r.ringbuf = reader
	r.running = true
	stopCh := r.stopCh
	r.mu.Unlock()
	contextDone := make(chan struct{})
	contextWatcherDone := make(chan struct{})
	go func() {
		defer close(contextWatcherDone)
		select {
		case <-ctx.Done():
			// ringbuf.Reader.Read blocks in the kernel wait path. Closing the
			// reader makes cancellation observable even when no event arrives.
			_ = r.Stop()
		case <-contextDone:
		}
	}()
	defer func() {
		close(contextDone)
		<-contextWatcherDone
		// A caller may cancel Start without calling Stop. Release the reader and
		// make a later Start observe a clean, restartable state. Stop() may have
		// already closed the same reader; ringbuf.Reader.Close is idempotent.
		r.mu.Lock()
		if r.ringbuf == reader {
			r.ringbuf = nil
			r.running = false
			r.stopCh = make(chan struct{})
		}
		r.mu.Unlock()
		_ = reader.Close()
	}()

	slog.Default().Info("linux flow reader started")

	// Read events in a loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopCh:
			return nil
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					select {
					case <-stopCh:
						return nil
					default:
						return fmt.Errorf("flow ring buffer closed unexpectedly: %w", err)
					}
				}
				if errors.Is(err, ringbuf.ErrFlushed) {
					continue
				}
				return fmt.Errorf("read flow ring buffer: %w", err)
			}

			// Parse the raw event
			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				if r.onDrop != nil {
					r.onDrop("decode")
				} else {
					slog.Default().Warn("failed to parse flow event", "error", err)
				}
				continue
			}
			// Send to channel (non-blocking)
			select {
			case eventCh <- event:
			default:
				if r.onDrop != nil {
					r.onDrop("reader_full")
				}
			}
		}
	}
}

// Stop stops the reader.
func (r *LinuxReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}
	r.running = false
	close(r.stopCh)

	var closeErr error
	if r.ringbuf != nil {
		if err := r.ringbuf.Close(); err != nil {
			closeErr = fmt.Errorf("failed to close ring buffer: %w", err)
		}
		r.ringbuf = nil
	}
	// A monitor may be restarted after a clean stop. Keep the closed channel
	// private to the completed reader and give the next Start call a fresh one.
	r.stopCh = make(chan struct{})
	if closeErr != nil {
		return closeErr
	}

	slog.Default().Info("linux flow reader stopped")
	return nil
}

// Available reports whether the reader has a flow map to open. A zero-value or
// nil reader must fail closed before Monitor starts its reader lifecycle.
func (r *LinuxReader) Available() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flowMap != nil
}

// CreateFlowReader creates a flow reader for the given eBPF flow_events map.
// This is the entry point for platform-specific reader creation.
func CreateFlowReader(flowEventsMap *ebpf.Map) (FlowReader, error) {
	return NewLinuxReader(flowEventsMap)
}

func linuxMonotonicNS() int64 {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0
	}
	return now.Nano()
}

func init() {
	uptimeNsFunc = linuxMonotonicNS
}
