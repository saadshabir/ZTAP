//go:build linux

package flow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func TestLinuxReaderAvailabilityFailsClosedWithoutFlowMap(t *testing.T) {
	var nilReader *LinuxReader
	if nilReader.Available() {
		t.Fatal("nil LinuxReader reported availability")
	}
	if (&LinuxReader{}).Available() {
		t.Fatal("zero-value LinuxReader reported availability")
	}
}

func TestLinuxReaderStartRejectsUnavailableZeroValue(t *testing.T) {
	reader := &LinuxReader{}
	if err := reader.Start(t.Context(), make(chan RawFlowEvent)); err == nil {
		t.Fatal("zero-value LinuxReader started without a flow map")
	}
}

func TestLinuxReaderStartRejectsCanceledContextBeforeOpeningFlowMap(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (&LinuxReader{}).Start(ctx, make(chan RawFlowEvent)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled LinuxReader start error = %v, want context.Canceled", err)
	}
}

func TestLinuxReaderStartRechecksCancellationAfterWaitingForStateLock(t *testing.T) {
	reader := &LinuxReader{flowMap: &ebpf.Map{}, stopCh: make(chan struct{})}
	reader.mu.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- reader.Start(ctx, make(chan RawFlowEvent))
	}()
	cancel()
	reader.mu.Unlock()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("locked canceled LinuxReader start error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LinuxReader start did not return after lock release")
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.running || reader.ringbuf != nil {
		t.Fatalf("canceled startup created reader state: running=%t ringbuf=%v", reader.running, reader.ringbuf)
	}
}

type blockingLinuxRingReader struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (r *blockingLinuxRingReader) Read() (ringbuf.Record, error) {
	select {
	case <-r.started:
	default:
		close(r.started)
	}
	<-r.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *blockingLinuxRingReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func TestLinuxReaderContextCancellationClosesBlockedRingReader(t *testing.T) {
	ringReader := &blockingLinuxRingReader{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	reader := &LinuxReader{
		flowMap: &ebpf.Map{},
		stopCh:  make(chan struct{}),
		newReader: func(*ebpf.Map) (linuxRingReader, error) {
			return ringReader, nil
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- reader.Start(ctx, make(chan RawFlowEvent))
	}()
	select {
	case <-ringReader.started:
	case <-time.After(time.Second):
		t.Fatal("LinuxReader did not enter the blocking ring read")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("LinuxReader cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LinuxReader did not stop after context cancellation")
	}
	select {
	case <-ringReader.closed:
	default:
		t.Fatal("context cancellation did not close the ring reader")
	}
}
