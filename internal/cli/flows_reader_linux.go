//go:build linux
// +build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/flow"

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
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	// The caller may cancel while another lifecycle operation holds the map
	// owner lock. Recheck before marking the reader running so cancellation
	// cannot launch the inner reader or status poll after ownership wait.
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
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
	case readerErr := <-readerDone:
		cancel()
		statusErr := <-statusDone
		return joinPinnedFlowReaderErrors(ctx, readerErr, statusErr, nil)
	case statusErr := <-statusDone:
		cancel()
		// LinuxReader blocks in ringbuf.Reader.Read, so close the reader to
		// wake it when the agent status becomes invalid or stale.
		stopErr := inner.Stop()
		readerErr := <-readerDone
		return joinPinnedFlowReaderErrors(ctx, readerErr, statusErr, stopErr)
	}
}

func joinPinnedFlowReaderErrors(ctx context.Context, readerErr, statusErr, stopErr error) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	var errs []error
	for _, err := range []error{readerErr, statusErr, stopErr} {
		if err != nil && !errors.Is(err, context.Canceled) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	if r == nil {
		return false
	}
	r.mu.Lock()
	inner := r.inner
	closed := r.closed
	r.mu.Unlock()
	return !closed && inner != nil && inner.Available()
}

func openPinnedFlowReader(bpffsRoot string) (result flow.FlowReader, resultErr error) {
	if bpffsRoot == "" {
		bpffsRoot = "/sys/fs/bpf"
	}
	if !filepath.IsAbs(bpffsRoot) {
		return nil, fmt.Errorf("bpffs root %q is not absolute", bpffsRoot)
	}
	rootPath := filepath.Clean(bpffsRoot)
	rootFD, err := openExistingDirectory(rootPath, "pinned flow bpffs root")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unix.Close(rootFD); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close pinned flow bpffs root: %w", err))
			if result != nil {
				resultErr = errors.Join(resultErr, result.Stop())
				result = nil
			}
		}
	}()

	pinDirectory := filepath.Join(rootPath, "ztap")
	pinDirectoryFD, err := unix.Openat(rootFD, "ztap", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("pinned flow path %q is a symlink", pinDirectory)
		}
		if errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("pinned flow path %q is not a directory", pinDirectory)
		}
		return nil, fmt.Errorf("open pinned flow directory %q: %w", pinDirectory, err)
	}
	defer func() {
		if err := unix.Close(pinDirectoryFD); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close pinned flow directory: %w", err))
			if result != nil {
				resultErr = errors.Join(resultErr, result.Stop())
				result = nil
			}
		}
	}()

	flowEventsPath := filepath.Join(pinDirectory, "flow_events")
	m, err := loadPinnedFlowMapAt(pinDirectoryFD, "flow_events", flowEventsPath)
	if err != nil {
		return nil, err
	}
	agentStatusPath := filepath.Join(pinDirectory, "agent_status")
	statusMap, err := loadPinnedFlowMapAt(pinDirectoryFD, "agent_status", agentStatusPath)
	if err != nil {
		_ = m.Close()
		return nil, err
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

// loadPinnedFlowMapAt opens one stable pin through a descriptor-relative
// no-follow handle, then asks the BPF loader to resolve the already-opened
// object through procfs. Keeping the O_PATH descriptor open across BPF_OBJ_GET
// closes the check-then-open race that a path-only symlink check would leave.
func loadPinnedFlowMapAt(directoryFD int, name, displayPath string) (*ebpf.Map, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid pinned flow map name %q", name)
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("pinned flow path %q is a symlink", displayPath)
		}
		return nil, fmt.Errorf("open pinned flow map %q: %w", displayPath, err)
	}
	closeFD := func() error { return unix.Close(fd) }
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, errors.Join(fmt.Errorf("inspect pinned flow map %q: %w", displayPath, err), closeFD())
	}
	if info.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, errors.Join(fmt.Errorf("pinned flow path %q is a symlink", displayPath), closeFD())
	}

	procPath := "/proc/self/fd/" + strconv.Itoa(fd)
	m, err := ebpf.LoadPinnedMap(procPath, nil)
	closeErr := closeFD()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("loading pinned flow map %s: %w", displayPath, err), closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(fmt.Errorf("close pinned flow map handle %q: %w", displayPath, closeErr), m.Close())
	}
	return m, nil
}

func monitorPinnedAgentStatus(ctx context.Context, statusMap *ebpf.Map) error {
	if ctx == nil {
		return errors.New("flow status context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if statusMap == nil {
		return errors.New("flow status map is nil")
	}
	var expectedEpoch uint64
	first := true
	ticker := time.NewTicker(flowAgentStatusPollPeriod)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
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
	if current.Sec < 0 || current.Nsec < 0 {
		return 0, errors.New("monotonic clock returned a negative value")
	}
	return uint64(current.Sec)*uint64(time.Second) + uint64(current.Nsec), nil // #nosec G115 -- clock_gettime returns non-negative seconds and nanoseconds after the checks above.
}

// openStreamingFlowReader is the only reader used by the live `flows`
// command. The pinned maps are intentionally opened eagerly so missing maps,
// permissions, and an inactive agent are reported to the caller.
func openStreamingFlowReader(bpffsRoot string) (flow.FlowReader, error) {
	return openPinnedFlowReader(bpffsRoot)
}
