//go:build linux
// +build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"ztap/internal/enforcer"
	"ztap/internal/flow"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	flowAgentStatusSchema     = enforcer.AgentStatusSchemaVersion
	flowAgentStateEnforcing   = enforcer.AgentLifecycleEnforcing
	flowAgentHeartbeatMaxAge  = 5 * time.Second
	flowAgentStatusPollPeriod = time.Second
)

type pinnedAgentStatus struct {
	SchemaVersion  uint32
	LifecycleState uint32
	AgentEpoch     uint64
	HeartbeatNS    uint64
}

type mapOwningReader struct {
	mu        sync.Mutex
	inner     flow.FlowReader
	flowMap   *ebpf.Map
	statusMap *ebpf.Map
	running   bool
	done      chan struct{}
	closed    bool
}

func (r *mapOwningReader) Start(ctx context.Context, eventCh chan<- flow.RawFlowEvent) error {
	if ctx == nil {
		return errors.New("pinned flow reader context is nil")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("pinned flow reader is closed")
	}
	if r.running {
		r.mu.Unlock()
		return nil
	}
	if r.statusMap == nil {
		r.mu.Unlock()
		return errors.New("agent status map is unavailable")
	}
	if r.inner == nil {
		r.mu.Unlock()
		return errors.New("pinned flow reader is unavailable")
	}
	r.running = true
	done := make(chan struct{})
	r.done = done
	inner := r.inner
	statusMap := r.statusMap
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		if r.done == done {
			r.done = nil
		}
		close(done)
		r.mu.Unlock()
	}()

	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	readerDone := make(chan error, 1)
	go func() {
		readerDone <- inner.Start(readCtx, eventCh)
	}()
	statusDone := make(chan error, 1)
	go func() {
		statusDone <- monitorPinnedAgentStatus(readCtx, statusMap)
	}()

	select {
	case err := <-readerDone:
		cancel()
		<-statusDone
		return err
	case statusErr := <-statusDone:
		cancel()
		// LinuxReader blocks in ringbuf.Reader.Read, so close the reader to
		// wake it when the agent status becomes invalid or stale.
		stopErr := inner.Stop()
		readerErr := <-readerDone
		if errors.Is(statusErr, context.Canceled) && ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.Join(statusErr, stopErr, readerErr)
	}
}

func (r *mapOwningReader) Stop() error {
	r.mu.Lock()
	inner := r.inner
	done := r.done
	statusMap := r.statusMap
	flowMap := r.flowMap
	r.closed = true
	r.statusMap = nil
	r.flowMap = nil
	r.mu.Unlock()

	var err error
	if inner != nil {
		err = inner.Stop()
	}
	if done != nil {
		<-done
	}
	if statusMap != nil {
		if closeErr := statusMap.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	if flowMap != nil {
		if closeErr := flowMap.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	return err
}

func (r *mapOwningReader) Available() bool {
	return r.inner.Available()
}

func openPinnedFlowReader() (flow.FlowReader, error) {
	m, err := ebpf.LoadPinnedMap(enforcer.DefaultFlowEventsPinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("loading pinned flow map %s: %w", enforcer.DefaultFlowEventsPinPath, err)
	}
	statusMap, err := ebpf.LoadPinnedMap(enforcer.DefaultAgentStatusPinPath, nil)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("loading pinned agent status map %s: %w", enforcer.DefaultAgentStatusPinPath, err)
	}

	reader, err := flow.CreateFlowReader(m)
	if err != nil {
		_ = statusMap.Close()
		if closeErr := m.Close(); closeErr != nil {
			return nil, fmt.Errorf("creating linux flow reader: %w (closing map: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("creating linux flow reader: %w", err)
	}

	return &mapOwningReader{inner: reader, flowMap: m, statusMap: statusMap}, nil
}

func monitorPinnedAgentStatus(ctx context.Context, statusMap *ebpf.Map) error {
	if ctx == nil {
		return errors.New("flow status context is nil")
	}
	if statusMap == nil {
		return errors.New("flow status map is nil")
	}
	var expectedEpoch uint64
	first := true
	ticker := time.NewTicker(flowAgentStatusPollPeriod)
	defer ticker.Stop()
	for {
		status, err := readPinnedAgentStatus(statusMap)
		if err != nil {
			return err
		}
		now, err := monotonicNowNS()
		if err != nil {
			return err
		}
		var statusErr error
		expectedEpoch, statusErr = validatePinnedAgentStatus(status, expectedEpoch, !first, now)
		if statusErr != nil {
			return statusErr
		}
		first = false

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func validatePinnedAgentStatus(status pinnedAgentStatus, expectedEpoch uint64, haveExpectedEpoch bool, now uint64) (uint64, error) {
	if status.SchemaVersion != flowAgentStatusSchema {
		return expectedEpoch, fmt.Errorf("unsupported agent status schema %d", status.SchemaVersion)
	}
	if status.LifecycleState != flowAgentStateEnforcing {
		return expectedEpoch, fmt.Errorf("agent is not enforcing (lifecycle state %d)", status.LifecycleState)
	}
	if haveExpectedEpoch && status.AgentEpoch != expectedEpoch {
		return expectedEpoch, fmt.Errorf("agent epoch changed from %d to %d", expectedEpoch, status.AgentEpoch)
	}
	if status.HeartbeatNS == 0 {
		return expectedEpoch, errors.New("agent heartbeat is missing")
	}
	if status.HeartbeatNS > now {
		return expectedEpoch, errors.New("agent heartbeat is in the future")
	}
	if now-status.HeartbeatNS > uint64(flowAgentHeartbeatMaxAge) {
		return expectedEpoch, fmt.Errorf("agent heartbeat is older than %s", flowAgentHeartbeatMaxAge)
	}
	if !haveExpectedEpoch {
		return status.AgentEpoch, nil
	}
	return expectedEpoch, nil
}

func readPinnedAgentStatus(statusMap *ebpf.Map) (pinnedAgentStatus, error) {
	var status pinnedAgentStatus
	zero := uint32(0)
	if err := statusMap.Lookup(&zero, &status); err != nil {
		return pinnedAgentStatus{}, fmt.Errorf("read pinned agent status: %w", err)
	}
	return status, nil
}

func monotonicNowNS() (uint64, error) {
	var current unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &current); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	return uint64(current.Sec)*uint64(time.Second) + uint64(current.Nsec), nil
}

// openStreamingFlowReader is the only reader used by the live `flows`
// command. The pinned maps are intentionally opened eagerly so missing maps,
// permissions, and an inactive agent are reported to the caller.
func openStreamingFlowReader() (flow.FlowReader, error) {
	return openPinnedFlowReader()
}

// createAnomalyFlowReader returns a reader that waits for the real pinned map
// to become available. This covers agent startup, where policy enforcement may
// pin the map shortly after the anomaly runner starts, without ever emitting
// synthetic events.
func createAnomalyFlowReader() (flow.FlowReader, error) {
	return &retryingAnomalyReader{}, nil
}

type retryingAnomalyReader struct {
	mu     sync.Mutex
	inner  flow.FlowReader
	stopCh chan struct{}
}

func (r *retryingAnomalyReader) Start(ctx context.Context, eventCh chan<- flow.RawFlowEvent) error {
	r.mu.Lock()
	stopCh := make(chan struct{})
	r.stopCh = stopCh
	r.mu.Unlock()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastLog time.Time

	for {
		reader, err := openPinnedFlowReader()
		if err == nil {
			r.mu.Lock()
			r.inner = reader
			r.mu.Unlock()

			startErr := reader.Start(ctx, eventCh)
			_ = reader.Stop()
			r.mu.Lock()
			if r.inner == reader {
				r.inner = nil
			}
			if r.stopCh == stopCh {
				r.stopCh = nil
			}
			r.mu.Unlock()
			return startErr
		}

		if lastLog.IsZero() || time.Since(lastLog) >= 10*time.Second {
			fmt.Fprintf(os.Stderr, "note: anomaly flow reader waiting for %s: %v\n", enforcer.DefaultFlowEventsPinPath, err)
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopCh:
			return nil
		case <-ticker.C:
		}
	}
}

func (r *retryingAnomalyReader) Stop() error {
	r.mu.Lock()
	stopCh := r.stopCh
	if stopCh != nil {
		close(stopCh)
		r.stopCh = nil
	}
	inner := r.inner
	r.inner = nil
	r.mu.Unlock()
	if inner != nil {
		return inner.Stop()
	}
	return nil
}

func (r *retryingAnomalyReader) Available() bool {
	return true // It can become available when enforcement pins the map.
}
