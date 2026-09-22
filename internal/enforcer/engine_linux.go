//go:build linux

package enforcer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/saadshabir/ZTAP/internal/policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	engineFlowEventsPinName  = "flow_events"
	engineAgentStatusPinName = "agent_status"
	engineAgentStatusSchema  = AgentStatusSchemaVersion
	cgroup2SuperMagic        = int64(0x63677270)
	bpfSuperMagic            = int64(0xcafe4a11)

	engineStateStarting  = AgentLifecycleStarting
	engineStateEnforcing = AgentLifecycleEnforcing
	engineStateStopping  = AgentLifecycleStopping
)

var engineDecisionReasons = [...]string{
	"unisolated",
	"node_bypass",
	"self_bypass",
	"connection",
	"rule",
	"quarantine",
	"default_deny",
	"malformed",
	"fragment",
	"ipv6",
	"unsupported",
	"config",
}

var engineEventDropReasons = [...]string{"rate_limited", "ring_full"}

// EngineDecisionMetricLabels returns the complete bounded label set so a
// Prometheus endpoint can expose zero-valued series before the first packet.
func EngineDecisionMetricLabels() []EngineDecisionMetric {
	labels := make([]EngineDecisionMetric, 0, len(engineDecisionReasons)*4)
	for reason := range engineDecisionReasons {
		for direction := uint8(0); direction <= 1; direction++ {
			for action := uint8(0); action <= 1; action++ {
				actionName := "blocked"
				if action == 1 {
					actionName = "allowed"
				}
				directionName := "egress"
				if direction == 1 {
					directionName = "ingress"
				}
				labels = append(labels, EngineDecisionMetric{
					Action:    actionName,
					Direction: directionName,
					Reason:    engineDecisionReasons[reason],
				})
			}
		}
	}
	return labels
}

// EngineEventDropMetricLabels returns the complete bounded flow-drop label
// set for zero-valued Prometheus series at startup.
func EngineEventDropMetricLabels() []EngineEventDropMetric {
	labels := make([]EngineEventDropMetric, 0, len(engineEventDropReasons))
	for _, reason := range engineEventDropReasons {
		labels = append(labels, EngineEventDropMetric{Reason: reason})
	}
	return labels
}

type LinuxEngine struct {
	*engineCore
	store *linuxEngineStore
}

type linuxEngineStore struct {
	collection       *ebpf.Collection
	maps             map[string]*ebpf.Map
	activeConfigSpec *ebpf.MapSpec
	activeConfigMap  *ebpf.Map
	logger           *slog.Logger
	flowEventsPin    string
	agentStatusPin   string
	pinDirectory     *os.File
	pinDirectoryPath string
	ownedPins        []string
	slotCounts       [2]slotMapCounts
	statusMu         sync.Mutex
	statusState      uint32
	agentEpoch       uint64
	heartbeatCancel  context.CancelFunc
	heartbeatDone    chan struct{}
}

type slotMapCounts struct {
	subjects int
	rules    int
	nodes    int
	self     int
}

type subjectLinkPair struct {
	mu      sync.Mutex
	egress  io.Closer
	ingress io.Closer
}

type linuxSubjectLinker struct {
	cgroupRoot    string
	resolvePath   CgroupPathResolver
	egress        *ebpf.Program
	ingress       *ebpf.Program
	cgroupStorage *ebpf.Map
}

type bpfAgentStatus struct {
	SchemaVersion  uint32
	LifecycleState uint32
	AgentEpoch     uint64
	HeartbeatNS    uint64
}

// RemoveStalePins removes only the two stable maps owned by the agent. It
// never walks the directory or deletes unrelated bpffs entries. The caller
// must hold the node-level agent lock before calling this at startup.
func RemoveStalePins(bpffsRoot string) error {
	root, err := absoluteDirectoryPath(bpffsRoot, "/sys/fs/bpf")
	if err != nil {
		return err
	}
	pinDirectory := filepath.Join(root, "ztap")
	rootFD, err := openEngineDirectoryNoFollow(root, "ZTAP bpffs root")
	if err != nil {
		return fmt.Errorf("open ZTAP bpffs root: %w", err)
	}
	defer unix.Close(rootFD)

	pinDirectoryFD, err := unix.Openat(rootFD, "ztap", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return fmt.Errorf("ZTAP bpffs path %q is a symlink", pinDirectory)
		}
		if errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("ZTAP bpffs path %q is not a directory", pinDirectory)
		}
		return fmt.Errorf("open ZTAP bpffs directory: %w", err)
	}
	defer unix.Close(pinDirectoryFD)

	for _, name := range []string{engineFlowEventsPinName, engineAgentStatusPinName} {
		if err := removeOwnedEnginePinAt(pinDirectoryFD, name); err != nil {
			return fmt.Errorf("remove stale ZTAP pin %q: %w", filepath.Join(pinDirectory, name), err)
		}
	}
	return nil
}

// removeOwnedEnginePin removes one stable path without treating a real
// directory at that name as an owned eBPF pin. The parent directory is
// traversed without following any component, and the entry is inspected and
// unlinked relative to that descriptor.
func removeOwnedEnginePin(path string) error {
	parent := filepath.Dir(path)
	name := filepath.Base(path)
	directoryFD, err := openEngineDirectoryNoFollow(parent, "pin directory")
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open pin directory: %w", err)
	}
	defer unix.Close(directoryFD)
	return removeOwnedEnginePinAt(directoryFD, name)
}

func removeOwnedEnginePinAt(directoryFD int, name string) error {
	var info unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if info.Mode&unix.S_IFMT == unix.S_IFDIR {
		return errors.New("path is a directory")
	}
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return err
	}
	return nil
}

// NewLinuxEngine creates one collection and keeps its programs and maps for
// the engine lifetime. The caller must hold the agent lock before construction,
// because construction removes stale flow/status pins from bpffsRoot.
func NewLinuxEngine(ctx context.Context, options LinuxEngineOptions) (*LinuxEngine, error) {
	if ctx == nil {
		return nil, errors.New("engine context is nil")
	}
	if options.ResolveCgroupPath == nil {
		return nil, errors.New("cgroup path resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cgroupRoot, err := absoluteDirectoryPath(options.CgroupRoot, "/sys/fs/cgroup")
	if err != nil {
		return nil, fmt.Errorf("cgroup root: %w", err)
	}
	if err := requireFilesystemType(cgroupRoot, cgroup2SuperMagic, "cgroup v2"); err != nil {
		return nil, err
	}
	bpffsRoot, err := absoluteDirectoryPath(options.BPFFSRoot, "/sys/fs/bpf")
	if err != nil {
		return nil, fmt.Errorf("bpffs root: %w", err)
	}
	if err := requireFilesystemType(bpffsRoot, bpfSuperMagic, "bpffs"); err != nil {
		return nil, err
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if options.AgentEpoch == 0 {
		options.AgentEpoch, err = newAgentEpoch()
		if err != nil {
			return nil, fmt.Errorf("create agent epoch: %w", err)
		}
	}
	if err := RemoveStalePins(bpffsRoot); err != nil {
		return nil, err
	}
	// The engine owns several large maps (including the two policy slots and
	// the ring buffer). Raise the process memlock limit before asking the
	// kernel to create the collection; the DaemonSet grants SYS_RESOURCE for
	// this operation.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	spec, err := loadEngine()
	if err != nil {
		return nil, fmt.Errorf("load embedded engine collection spec: %w", err)
	}
	if err := validateEngineCollectionSpec(spec); err != nil {
		return nil, err
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load instance-owned eBPF collection: %w", err)
	}
	pinDirectoryPath := filepath.Join(bpffsRoot, "ztap")
	pinDirectory, err := openOrCreateEnginePinDirectory(bpffsRoot)
	if err != nil {
		collection.Close()
		return nil, fmt.Errorf("create ZTAP bpffs directory: %w", err)
	}
	store := &linuxEngineStore{
		collection:       collection,
		maps:             collection.Maps,
		activeConfigSpec: spec.Maps["active_config"].InnerMap.Copy(),
		logger:           logger,
		flowEventsPin:    filepath.Join(pinDirectoryPath, engineFlowEventsPinName),
		agentStatusPin:   filepath.Join(pinDirectoryPath, engineAgentStatusPinName),
		pinDirectory:     pinDirectory,
		pinDirectoryPath: pinDirectoryPath,
		statusState:      engineStateStarting,
		agentEpoch:       options.AgentEpoch,
	}
	if err := store.initializeActiveConfig(); err != nil {
		return nil, errors.Join(fmt.Errorf("initialize active policy config: %w", err), store.Close())
	}
	if err := store.pinStableMaps(); err != nil {
		return nil, errors.Join(fmt.Errorf("pin stable engine maps: %w", err), store.Close())
	}
	if err := store.writeAgentStatus(); err != nil {
		return nil, errors.Join(fmt.Errorf("write initial agent status: %w", err), store.Close())
	}
	store.startHeartbeat()

	linker := &linuxSubjectLinker{
		cgroupRoot:    cgroupRoot,
		resolvePath:   options.ResolveCgroupPath,
		egress:        collection.Programs["ztap_egress"],
		ingress:       collection.Programs["ztap_ingress"],
		cgroupStorage: collection.Maps["attached_cgroup"],
	}
	return &LinuxEngine{engineCore: newEngineCore(store, linker, logger), store: store}, nil
}

func ensureEnginePinDirectory(root string) error {
	pinDirectory, err := openOrCreateEnginePinDirectory(root)
	if err != nil {
		return err
	}
	return pinDirectory.Close()
}

func openOrCreateEnginePinDirectory(root string) (*os.File, error) {
	rootFD, err := openEngineDirectoryNoFollow(root, "ZTAP bpffs root")
	if err != nil {
		return nil, fmt.Errorf("open bpffs root %q: %w", root, err)
	}
	defer unix.Close(rootFD)

	openDirectory := func() (int, error) {
		return unix.Openat(rootFD, "ztap", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	pinFD, err := openDirectory()
	if errors.Is(err, unix.ENOENT) {
		if mkdirErr := unix.Mkdirat(rootFD, "ztap", 0o750); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			return nil, fmt.Errorf("create ztap directory: %w", mkdirErr)
		}
		pinFD, err = openDirectory()
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("ztap pin directory is a symlink")
		}
		if errors.Is(err, unix.ENOTDIR) {
			return nil, errors.New("ztap pin path is not a directory")
		}
		return nil, fmt.Errorf("open ztap directory: %w", err)
	}
	pinDirectory := os.NewFile(uintptr(pinFD), filepath.Join(root, "ztap"))
	if pinDirectory == nil {
		_ = unix.Close(pinFD)
		return nil, errors.New("create ZTAP bpffs directory handle")
	}
	return pinDirectory, nil
}

func (e *LinuxEngine) FlowEventsMap() *ebpf.Map {
	return e.store.maps["flow_events"]
}

func (e *LinuxEngine) DecisionCountsMap() *ebpf.Map {
	return e.store.maps["decision_counts"]
}

func (e *LinuxEngine) EpochDecisionCountsMap() *ebpf.Map {
	return e.store.maps["decision_epoch_counts"]
}

func (e *LinuxEngine) EventDropsMap() *ebpf.Map {
	return e.store.maps["event_drops"]
}

func (e *LinuxEngine) EpochEventDropsMap() *ebpf.Map {
	return e.store.maps["event_drop_epoch_counts"]
}

func (e *LinuxEngine) AgentStatusMap() *ebpf.Map {
	return e.store.maps["agent_status"]
}

// MetricsSnapshot reads the stable aggregate counters without consuming the
// flow ring buffer. The engine mutex keeps the active inner-map handle and
// slot-cleanup count consistent with concurrent Apply and Close calls.
func (e *LinuxEngine) MetricsSnapshot(ctx context.Context) (EngineMetricsSnapshot, error) {
	if ctx == nil {
		return EngineMetricsSnapshot{}, errors.New("engine metrics context is nil")
	}
	if err := ctx.Err(); err != nil {
		return EngineMetricsSnapshot{}, err
	}
	if err := lockEngineMutex(ctx, &e.mu); err != nil {
		return EngineMetricsSnapshot{}, err
	}
	defer e.mu.Unlock()
	if e.store == nil || e.storeClosed {
		return EngineMetricsSnapshot{}, errors.New("engine metrics are unavailable after close")
	}
	snapshot, err := e.store.metricsSnapshot(ctx)
	if err != nil {
		return EngineMetricsSnapshot{}, err
	}
	snapshot.SlotCleanupFailures = e.slotCleanupFailures
	return snapshot, nil
}

func (s *linuxEngineStore) metricsSnapshot(ctx context.Context) (EngineMetricsSnapshot, error) {
	if ctx == nil {
		return EngineMetricsSnapshot{}, errors.New("engine metrics context is nil")
	}
	if err := ctx.Err(); err != nil {
		return EngineMetricsSnapshot{}, err
	}
	if s.activeConfigMap == nil {
		return EngineMetricsSnapshot{}, errors.New("active policy config is unavailable")
	}
	zero := uint32(0)
	var active bpfActiveConfig
	if err := s.activeConfigMap.Lookup(&zero, &active); err != nil {
		return EngineMetricsSnapshot{}, fmt.Errorf("read active policy config: %w", err)
	}

	snapshot := EngineMetricsSnapshot{
		ActivePolicyEpoch: active.PolicyEpoch,
		Decisions:         EngineDecisionMetricLabels(),
		EventDrops:        EngineEventDropMetricLabels(),
	}
	decisionMap := s.maps["decision_counts"]
	for reason := range engineDecisionReasons {
		for direction := uint8(0); direction <= 1; direction++ {
			for action := uint8(0); action <= 1; action++ {
				if err := ctx.Err(); err != nil {
					return EngineMetricsSnapshot{}, err
				}
				index := (reason*2+int(direction))*2 + int(action)
				count, err := lookupPerCPUCounter(decisionMap, uint32(index)) // #nosec G115 -- index is bounded by the fixed decision-label dimensions above.
				if err != nil {
					return EngineMetricsSnapshot{}, fmt.Errorf("read decision counter %d: %w", index, err)
				}
				metric := &snapshot.Decisions[index]
				metric.Count = count
			}
		}
	}

	dropMap := s.maps["event_drops"]
	for reason := range engineEventDropReasons {
		if err := ctx.Err(); err != nil {
			return EngineMetricsSnapshot{}, err
		}
		count, err := lookupPerCPUCounter(dropMap, uint32(reason)) // #nosec G115 -- reason indexes the fixed event-drop label array.
		if err != nil {
			return EngineMetricsSnapshot{}, fmt.Errorf("read event-drop counter %d: %w", reason, err)
		}
		snapshot.EventDrops[reason].Count = count
	}
	return snapshot, nil
}

func lookupPerCPUCounter(m *ebpf.Map, key uint32) (uint64, error) {
	if m == nil {
		return 0, errors.New("counter map is missing")
	}
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	return sumCounterValues(values)
}

func validateEngineCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("engine collection spec is nil")
	}
	for _, name := range []string{"ztap_egress", "ztap_ingress"} {
		if spec.Programs[name] == nil {
			return fmt.Errorf("engine collection is missing program %q", name)
		}
	}
	wanted := map[string]struct {
		typ       ebpf.MapType
		max       uint32
		flags     uint32
		keySize   uint32
		valueSize uint32
	}{
		"policy_rules":            {typ: ebpf.LPMTrie, max: 2 * policy.MaxPolicyRules, flags: enginePolicyRulesMapFlags, keySize: 24, valueSize: 1},
		"subject_state":           {typ: ebpf.Hash, max: 2 * policy.MaxPolicySubjects, keySize: 16, valueSize: 8},
		"node_bypass":             {typ: ebpf.Hash, max: 2 * policy.MaxPolicyRules, keySize: 8, valueSize: 1},
		"self_bypass":             {typ: ebpf.Hash, max: 2 * policy.MaxPolicyRules, keySize: 16, valueSize: 1},
		"conn_state":              {typ: ebpf.LRUHash, max: 65_536, keySize: 32, valueSize: 8},
		"flow_events":             {typ: ebpf.RingBuf, max: 1 << 20, keySize: 0, valueSize: 0},
		"decision_counts":         {typ: ebpf.PerCPUArray, max: 48, keySize: 4, valueSize: 8},
		"decision_epoch_counts":   {typ: ebpf.LRUCPUHash, max: 4096, keySize: 16, valueSize: 8},
		"event_drops":             {typ: ebpf.PerCPUArray, max: 2, keySize: 4, valueSize: 8},
		"event_drop_epoch_counts": {typ: ebpf.LRUCPUHash, max: 1024, keySize: 16, valueSize: 8},
		"event_limiter":           {typ: ebpf.PerCPUArray, max: 1, keySize: 4, valueSize: 16},
		"in_flight":               {typ: ebpf.PerCPUArray, max: 2, keySize: 4, valueSize: 8},
		"attached_cgroup":         {typ: ebpf.CGroupStorage, keySize: 16, valueSize: 8},
		"agent_status":            {typ: ebpf.Array, max: 1, keySize: 4, valueSize: 24},
	}
	for name, requirement := range wanted {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("engine collection is missing map %q", name)
		}
		if mapSpec.Type != requirement.typ {
			return fmt.Errorf("engine map %q has type %s, want %s", name, mapSpec.Type, requirement.typ)
		}
		if requirement.max != 0 && mapSpec.MaxEntries != requirement.max {
			return fmt.Errorf("engine map %q has %d entries, want %d", name, mapSpec.MaxEntries, requirement.max)
		}
		if mapSpec.Flags != requirement.flags {
			return fmt.Errorf("engine map %q has flags %#x, want %#x", name, mapSpec.Flags, requirement.flags)
		}
		if mapSpec.KeySize != requirement.keySize || mapSpec.ValueSize != requirement.valueSize {
			return fmt.Errorf("engine map %q has key/value sizes %d/%d, want %d/%d", name,
				mapSpec.KeySize, mapSpec.ValueSize, requirement.keySize, requirement.valueSize)
		}
	}
	activeConfig := spec.Maps["active_config"]
	if activeConfig == nil || activeConfig.Type != ebpf.ArrayOfMaps || activeConfig.MaxEntries != 1 ||
		activeConfig.Flags != 0 || activeConfig.KeySize != 4 || activeConfig.ValueSize != 4 || activeConfig.InnerMap == nil {
		return errors.New("active_config must be a one-entry array-of-maps with an inner config map")
	}
	if activeConfig.InnerMap.Type != ebpf.Array || activeConfig.InnerMap.KeySize != 4 ||
		activeConfig.InnerMap.Flags != 0 || activeConfig.InnerMap.ValueSize != 16 || activeConfig.InnerMap.MaxEntries != 1 {
		return errors.New("active_config inner map must be a one-entry array of 16-byte config values")
	}
	return nil
}

func (s *linuxEngineStore) initializeActiveConfig() error {
	activeMap := s.maps["active_config"]
	if activeMap == nil || s.activeConfigSpec == nil {
		return errors.New("active_config map or inner map spec is missing")
	}
	inner, err := ebpf.NewMap(s.activeConfigSpec)
	if err != nil {
		return fmt.Errorf("create initial active-config inner map: %w", err)
	}
	zero := uint32(0)
	initial := bpfActiveConfig{ActiveSlot: 0, PolicyEpoch: 0}
	if err := inner.Put(&zero, &initial); err != nil {
		_ = inner.Close()
		return fmt.Errorf("write initial active config: %w", err)
	}
	if err := activeMap.Put(&zero, inner); err != nil {
		_ = inner.Close()
		return fmt.Errorf("publish initial active config: %w", err)
	}
	s.activeConfigMap = inner
	return nil
}

func (s *linuxEngineStore) pinStableMaps() error {
	if s.pinDirectory == nil {
		return errors.New("ZTAP bpffs directory handle is missing")
	}
	pins := []struct {
		name        string
		displayPath string
	}{
		{name: engineFlowEventsPinName, displayPath: s.flowEventsPin},
		{name: engineAgentStatusPinName, displayPath: s.agentStatusPin},
	}
	for _, pin := range pins {
		m := s.maps[pin.name]
		if m == nil {
			return fmt.Errorf("map %q is missing", pin.name)
		}
		pinPath, err := enginePinPathAt(s.pinDirectory, pin.name)
		if err != nil {
			return err
		}
		if err := m.Pin(pinPath); err != nil {
			return fmt.Errorf("pin map %q at %q: %w", pin.name, pin.displayPath, err)
		}
		s.ownedPins = append(s.ownedPins, pin.name)
	}
	return nil
}

func enginePinPathAt(directory *os.File, name string) (string, error) {
	if directory == nil {
		return "", errors.New("ZTAP bpffs directory handle is missing")
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("invalid engine pin name %q", name)
	}
	return filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(directory.Fd()), 10), name), nil
}

func (s *linuxEngineStore) PopulateSlot(ctx context.Context, slot uint32, set policy.PolicySet) error {
	if ctx == nil {
		return errors.New("populate policy context is nil")
	}
	if slot > 1 {
		return fmt.Errorf("policy slot %d is outside 0..1", slot)
	}
	encoded, err := encodePolicySet(slot, set)
	if err != nil {
		return err
	}
	if s.slotCounts[slot] != (slotMapCounts{}) {
		return fmt.Errorf("policy slot %d was not empty before population", slot)
	}
	otherSlot := 1 - slot
	counts := slotMapCounts{
		subjects: len(encoded.Subjects),
		rules:    len(encoded.Rules),
		nodes:    len(encoded.Nodes),
		self:     len(encoded.Self),
	}
	for name, usage := range map[string]int{
		"subject_state": counts.subjects + s.slotCounts[otherSlot].subjects,
		"policy_rules":  counts.rules + s.slotCounts[otherSlot].rules,
		"node_bypass":   counts.nodes + s.slotCounts[otherSlot].nodes,
		"self_bypass":   counts.self + s.slotCounts[otherSlot].self,
	} {
		if err := ensureMapCapacity(s.maps[name], name, usage); err != nil {
			return err
		}
	}
	// Store intended counts before the first write. A partial failure is then
	// conservatively accounted for until ClearSlot completes.
	s.slotCounts[slot] = counts

	for _, entry := range encoded.Subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.maps["subject_state"].Put(&entry.Key, &entry.Value); err != nil {
			return fmt.Errorf("write subject state for cgroup %d: %w", entry.Key.CgroupID, err)
		}
	}
	present := uint8(1)
	for _, key := range encoded.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.maps["node_bypass"].Put(&key, &present); err != nil {
			return fmt.Errorf("write Node bypass entry: %w", err)
		}
	}
	for _, key := range encoded.Self {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.maps["self_bypass"].Put(&key, &present); err != nil {
			return fmt.Errorf("write self bypass for cgroup %d: %w", key.CgroupID, err)
		}
	}
	for _, key := range encoded.Rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.maps["policy_rules"].Put(&key, &present); err != nil {
			return fmt.Errorf("write policy rule for cgroup %d: %w", key.CgroupID, err)
		}
	}
	return nil
}

func ensureMapCapacity(m *ebpf.Map, name string, observed int) error {
	if m == nil {
		return fmt.Errorf("engine map %q is missing", name)
	}
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("inspect engine map %q capacity: %w", name, err)
	}
	if observed < 0 || uint64(observed) > uint64(info.MaxEntries) {
		return fmt.Errorf("engine map %q capacity exceeded: observed %d, allowed %d", name, observed, info.MaxEntries)
	}
	return nil
}

func (s *linuxEngineStore) ClearSlot(slot uint32) error {
	if slot > 1 {
		return fmt.Errorf("policy slot %d is outside 0..1", slot)
	}
	var clearErrors []error
	if err := clearSubjectMap(s.maps["subject_state"], slot); err != nil {
		clearErrors = append(clearErrors, err)
	}
	if err := clearNodeMap(s.maps["node_bypass"], slot); err != nil {
		clearErrors = append(clearErrors, err)
	}
	if err := clearSelfMap(s.maps["self_bypass"], slot); err != nil {
		clearErrors = append(clearErrors, err)
	}
	if err := clearRuleMap(s.maps["policy_rules"], slot); err != nil {
		clearErrors = append(clearErrors, err)
	}
	if err := errors.Join(clearErrors...); err != nil {
		return fmt.Errorf("clear policy slot %d: %w", slot, err)
	}
	s.slotCounts[slot] = slotMapCounts{}
	return nil
}

func clearSubjectMap(m *ebpf.Map, slot uint32) error {
	var keys []subjectStateKey
	iter := m.Iterate()
	var key subjectStateKey
	var value subjectStateValue
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate subject_state: %w", err)
	}
	return deleteMapKeys(m, "subject_state", keys)
}

func clearNodeMap(m *ebpf.Map, slot uint32) error {
	var keys []nodeBypassKey
	iter := m.Iterate()
	var key nodeBypassKey
	var value uint8
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate node_bypass: %w", err)
	}
	return deleteMapKeys(m, "node_bypass", keys)
}

func clearSelfMap(m *ebpf.Map, slot uint32) error {
	var keys []selfBypassKey
	iter := m.Iterate()
	var key selfBypassKey
	var value uint8
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate self_bypass: %w", err)
	}
	return deleteMapKeys(m, "self_bypass", keys)
}

func clearRuleMap(m *ebpf.Map, slot uint32) error {
	var keys []policyRuleKey
	iter := m.Iterate()
	var key policyRuleKey
	var value uint8
	for iter.Next(&key, &value) {
		if key.Meta>>31 == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate policy_rules: %w", err)
	}
	return deleteMapKeys(m, "policy_rules", keys)
}

func deleteMapKeys[T any](m *ebpf.Map, name string, keys []T) error {
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil {
			return fmt.Errorf("delete %s entry %d: %w", name, i, err)
		}
	}
	return nil
}

func (s *linuxEngineStore) Flip(config activeConfiguration) error {
	if config.Slot > 1 {
		return fmt.Errorf("policy slot %d is outside 0..1", config.Slot)
	}
	if s.activeConfigSpec == nil || s.maps["active_config"] == nil {
		return errors.New("active_config map is missing")
	}
	newConfig, err := ebpf.NewMap(s.activeConfigSpec)
	if err != nil {
		return fmt.Errorf("create candidate active-config map: %w", err)
	}
	zero := uint32(0)
	value := bpfActiveConfig{ActiveSlot: config.Slot, PolicyEpoch: config.PolicyEpoch}
	if err := newConfig.Put(&zero, &value); err != nil {
		_ = newConfig.Close()
		return fmt.Errorf("write candidate active config: %w", err)
	}
	if err := s.maps["active_config"].Put(&zero, newConfig); err != nil {
		_ = newConfig.Close()
		return fmt.Errorf("atomically publish candidate active config: %w", err)
	}
	oldConfig := s.activeConfigMap
	s.activeConfigMap = newConfig
	if oldConfig != nil {
		if err := oldConfig.Close(); err != nil {
			// The pointer swap already committed. Keep it a success so the caller
			// never rolls back links or policy state after a published config.
			s.logger.Warn("close replaced active-config handle", "error", err)
		}
	}
	return nil
}

func (s *linuxEngineStore) WaitQuiescent(ctx context.Context, slot uint32) error {
	if ctx == nil {
		return errors.New("quiescence context is nil")
	}
	if slot > 1 {
		return fmt.Errorf("policy slot %d is outside 0..1", slot)
	}
	waitCtx, cancel := context.WithTimeout(ctx, slotQuiescenceTimeout)
	defer cancel()
	counterMap := s.maps["in_flight"]
	if counterMap == nil {
		return errors.New("in_flight map is missing")
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var counts []uint64
	for {
		if err := counterMap.Lookup(&slot, &counts); err != nil {
			return fmt.Errorf("read in_flight counters for slot %d: %w", slot, err)
		}
		busy := false
		for _, count := range counts {
			if count != 0 {
				busy = true
				break
			}
		}
		if !busy {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for eBPF packet readers: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (s *linuxEngineStore) MarkEnforcing() error {
	s.setLifecycleState(engineStateEnforcing)
	return s.writeAgentStatus()
}

func (s *linuxEngineStore) MarkStopping() error {
	s.setLifecycleState(engineStateStopping)
	return s.writeAgentStatus()
}

func (s *linuxEngineStore) setLifecycleState(state uint32) {
	s.statusMu.Lock()
	s.statusState = state
	s.statusMu.Unlock()
}

func (s *linuxEngineStore) startHeartbeat() {
	ctx, cancel := context.WithCancel(context.Background())
	s.heartbeatCancel = cancel
	s.heartbeatDone = make(chan struct{})
	go func() {
		defer close(s.heartbeatDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.writeAgentStatus(); err != nil {
					s.logger.Warn("update agent heartbeat", "error", err)
				}
			}
		}
	}()
}

func (s *linuxEngineStore) writeAgentStatus() error {
	statusMap := s.maps["agent_status"]
	if statusMap == nil {
		return errors.New("agent_status map is missing")
	}
	zero := uint32(0)
	return s.updateAgentStatus(func(status bpfAgentStatus) error {
		if err := statusMap.Put(&zero, &status); err != nil {
			return fmt.Errorf("write agent_status map: %w", err)
		}
		return nil
	})
}

// updateAgentStatus holds statusMu through publication so a delayed heartbeat
// cannot overwrite a newer lifecycle state after taking an older snapshot.
func (s *linuxEngineStore) updateAgentStatus(write func(bpfAgentStatus) error) error {
	if write == nil {
		return errors.New("agent status writer is nil")
	}
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	heartbeat, err := monotonicNowNS()
	if err != nil {
		return err
	}
	status := bpfAgentStatus{
		SchemaVersion:  engineAgentStatusSchema,
		LifecycleState: s.statusState,
		AgentEpoch:     s.agentEpoch,
		HeartbeatNS:    heartbeat,
	}
	return write(status)
}

func (s *linuxEngineStore) Close() error {
	if s.heartbeatCancel != nil {
		s.heartbeatCancel()
		<-s.heartbeatDone
		s.heartbeatCancel = nil
	}
	var closeErrors []error
	if s.collection != nil {
		s.setLifecycleState(engineStateStopping)
		if s.maps["agent_status"] != nil {
			if err := s.writeAgentStatus(); err != nil {
				closeErrors = append(closeErrors, fmt.Errorf("write stopping status: %w", err))
			}
		}
	}
	remainingPins := make([]string, 0, len(s.ownedPins))
	for i := len(s.ownedPins) - 1; i >= 0; i-- {
		name := s.ownedPins[i]
		displayPath := filepath.Join(s.pinDirectoryPath, name)
		if s.pinDirectory == nil {
			closeErrors = append(closeErrors, fmt.Errorf("remove engine pin %q: ZTAP bpffs directory handle is missing", displayPath))
			remainingPins = append(remainingPins, name)
			continue
		}
		if err := removeOwnedEnginePinAt(int(s.pinDirectory.Fd()), name); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("remove engine pin %q: %w", displayPath, err))
			remainingPins = append(remainingPins, name)
		}
	}
	s.ownedPins = remainingPins
	if len(s.ownedPins) == 0 && s.pinDirectory != nil {
		pinDirectory := s.pinDirectory
		s.pinDirectory = nil
		if err := pinDirectory.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close ZTAP bpffs directory: %w", err))
		}
	}
	if s.activeConfigMap != nil {
		if err := s.activeConfigMap.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close active-config map: %w", err))
		} else {
			s.activeConfigMap = nil
		}
	}
	if s.collection != nil {
		s.collection.Close()
		s.collection = nil
	}
	return errors.Join(closeErrors...)
}

func (l *linuxSubjectLinker) Attach(ctx context.Context, cgroupID uint64) (io.Closer, error) {
	if ctx == nil {
		return nil, errors.New("attach cgroup context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := l.resolvePath(ctx, cgroupID)
	if err != nil {
		return nil, fmt.Errorf("resolve cgroup %d path: %w", cgroupID, err)
	}
	cgroup, _, err := openValidatedCgroup(l.cgroupRoot, path, cgroupID)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cgroup.Close()
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rejectIncompatibleCgroupProgram(cgroup, ebpf.AttachCGroupInetEgress, l.egress); err != nil {
		return nil, fmt.Errorf("inspect egress attachments for cgroup %d: %w", cgroupID, err)
	}
	egress, err := attachCgroupProgram(cgroup, ebpf.AttachCGroupInetEgress, l.egress)
	if err != nil {
		return nil, fmt.Errorf("attach egress program to cgroup %d: %w", cgroupID, err)
	}
	if err := ctx.Err(); err != nil {
		return &subjectLinkPair{egress: egress}, err
	}
	if err := rejectIncompatibleCgroupProgram(cgroup, ebpf.AttachCGroupInetEgress, l.egress); err != nil {
		return &subjectLinkPair{egress: egress}, fmt.Errorf("validate egress attachments for cgroup %d: %w", cgroupID, err)
	}
	if err := rejectIncompatibleCgroupProgram(cgroup, ebpf.AttachCGroupInetIngress, l.ingress); err != nil {
		return &subjectLinkPair{egress: egress}, fmt.Errorf("inspect ingress attachments for cgroup %d: %w", cgroupID, err)
	}
	ingress, err := attachCgroupProgram(cgroup, ebpf.AttachCGroupInetIngress, l.ingress)
	if err != nil {
		return &subjectLinkPair{egress: egress}, fmt.Errorf("attach ingress program to cgroup %d: %w", cgroupID, err)
	}
	if err := ctx.Err(); err != nil {
		return &subjectLinkPair{egress: egress, ingress: ingress}, err
	}
	if err := rejectIncompatibleCgroupProgram(cgroup, ebpf.AttachCGroupInetIngress, l.ingress); err != nil {
		return &subjectLinkPair{egress: egress, ingress: ingress}, fmt.Errorf("validate ingress attachments for cgroup %d: %w", cgroupID, err)
	}
	pair := &subjectLinkPair{
		egress:  egress,
		ingress: ingress,
	}
	if err := ctx.Err(); err != nil {
		return pair, err
	}
	if l.cgroupStorage == nil {
		return pair, errors.New("attached_cgroup storage map is missing")
	}
	egressKey := cgroupStorageKey{CgroupID: cgroupID, AttachType: uint32(ebpf.AttachCGroupInetEgress)}
	if err := l.cgroupStorage.Put(&egressKey, &cgroupID); err != nil {
		return pair, fmt.Errorf("record attached egress cgroup %d identity: %w", cgroupID, err)
	}
	if err := ctx.Err(); err != nil {
		return pair, err
	}
	ingressKey := cgroupStorageKey{CgroupID: cgroupID, AttachType: uint32(ebpf.AttachCGroupInetIngress)}
	if err := l.cgroupStorage.Put(&ingressKey, &cgroupID); err != nil {
		return pair, fmt.Errorf("record attached ingress cgroup %d identity: %w", cgroupID, err)
	}
	if err := ctx.Err(); err != nil {
		return pair, err
	}
	return pair, nil
}

const (
	cgroupAttachAllowOverride = 1 << iota
	cgroupAttachAllowMulti
)

// legacyCgroupAttachment retains the cgroup and cloned program handles needed
// by the legacy BPF_PROG_ATTACH fallback. bpf_link attachments are returned as
// the package's raw link and do not need to retain the target descriptor.
type legacyCgroupAttachment struct {
	cgroup  *os.File
	program *ebpf.Program
	attach  ebpf.AttachType
}

func (a *legacyCgroupAttachment) Close() error {
	if a == nil {
		return nil
	}
	var closeErrors []error
	if a.program != nil {
		if a.cgroup == nil {
			return errors.New("cgroup handle is missing while program is attached")
		}
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  int(a.cgroup.Fd()),
			Program: a.program,
			Attach:  a.attach,
		}); err != nil {
			// Retain both handles so an engine retry can attempt the detach again.
			return fmt.Errorf("detach cgroup program: %w", err)
		}
		if err := a.program.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close cgroup program: %w", err))
		}
		a.program = nil
	}
	if a.cgroup != nil {
		if err := a.cgroup.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close cgroup handle: %w", err))
		}
		a.cgroup = nil
	}
	return errors.Join(closeErrors...)
}

func attachCgroupProgram(cgroup *os.File, attach ebpf.AttachType, program *ebpf.Program) (io.Closer, error) {
	if cgroup == nil {
		return nil, errors.New("cgroup handle is nil")
	}
	if program == nil {
		return nil, errors.New("cgroup program is nil")
	}
	raw, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Program: program,
		Attach:  attach,
	})
	if err == nil {
		return raw, nil
	}
	if !errors.Is(err, link.ErrNotSupported) {
		return nil, err
	}

	clone, err := program.Clone()
	if err != nil {
		return nil, err
	}
	lastErr := tryLegacyCgroupAttach(func(flags uint32) error {
		return link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  int(cgroup.Fd()),
			Program: clone,
			Attach:  attach,
			Flags:   flags,
		})
	})
	if lastErr != nil {
		_ = clone.Close()
		return nil, lastErr
	}
	dupFD, dupErr := unix.Dup(int(cgroup.Fd()))
	if dupErr != nil {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  int(cgroup.Fd()),
			Program: clone,
			Attach:  attach,
		})
		_ = clone.Close()
		return nil, fmt.Errorf("duplicate cgroup handle: %w", dupErr)
	}
	return &legacyCgroupAttachment{
		cgroup:  os.NewFile(uintptr(dupFD), "ztap cgroup attachment"),
		program: clone,
		attach:  attach,
	}, nil
}

func tryLegacyCgroupAttach(attach func(uint32) error) error {
	if attach == nil {
		return errors.New("legacy cgroup attach function is nil")
	}
	if err := attach(cgroupAttachAllowMulti); err != nil {
		if !cgroupMultiAttachUnsupported(err) {
			return err
		}
		return attach(cgroupAttachAllowOverride)
	}
	return nil
}

func cgroupMultiAttachUnsupported(err error) bool {
	return errors.Is(err, link.ErrNotSupported) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)
}

// rejectIncompatibleCgroupProgram verifies that the target has no direct
// cgroup-skb attachment other than the program this engine is about to use.
// AttachCgroup intentionally supports multi-attach, but accepting an
// unrelated program would make the resulting verdict and local-storage
// ownership dependent on another controller. Querying before and after the
// attach also closes the small race where a second controller attaches while
// this engine is creating its link; the caller then closes only its own link.
func rejectIncompatibleCgroupProgram(cgroup *os.File, attach ebpf.AttachType, expected *ebpf.Program) error {
	if expected == nil {
		return errors.New("expected cgroup program is missing")
	}
	if cgroup == nil {
		return errors.New("cgroup handle is nil")
	}
	info, err := expected.Info()
	if err != nil {
		return fmt.Errorf("inspect expected program: %w", err)
	}
	expectedID, ok := info.ID()
	if !ok {
		return errors.New("expected cgroup program has no kernel ID")
	}
	result, err := link.QueryPrograms(link.QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: attach,
	})
	if err != nil {
		return fmt.Errorf("query programs: %w", err)
	}
	for _, program := range result.Programs {
		if program.ID != expectedID {
			return fmt.Errorf("incompatible program %d is already attached (expected %d)", program.ID, expectedID)
		}
	}
	return nil
}

func (p *subjectLinkPair) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Cgroup-local storage is kernel-owned. It is updated after attach and is
	// released with the map/cgroup lifecycle; userspace cannot delete entries.
	var closeErrors []error
	if p.egress != nil {
		if err := p.egress.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close egress link: %w", err))
		} else {
			p.egress = nil
		}
	}
	if p.ingress != nil {
		if err := p.ingress.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close ingress link: %w", err))
		} else {
			p.ingress = nil
		}
	}
	return errors.Join(closeErrors...)
}

func validateCgroupTarget(root, target string, expectedID uint64) (string, error) {
	cgroup, resolved, err := openValidatedCgroup(root, target, expectedID)
	if err != nil {
		return "", err
	}
	if err := cgroup.Close(); err != nil {
		return "", fmt.Errorf("close validated cgroup %q: %w", resolved, err)
	}
	return resolved, nil
}

func openValidatedCgroup(root, target string, expectedID uint64) (*os.File, string, error) {
	if !filepath.IsAbs(target) {
		return nil, "", fmt.Errorf("cgroup path %q is not absolute", target)
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, "", fmt.Errorf("resolve cgroup path %q: %w", target, err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", fmt.Errorf("resolve cgroup root %q: %w", root, err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) ||
		(len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("cgroup path %q is outside mounted root %q", resolved, resolvedRoot)
	}
	rootFD, err := openEngineDirectoryNoFollow(resolvedRoot, "cgroup root")
	if err != nil {
		return nil, "", fmt.Errorf("open cgroup root %q: %w", resolvedRoot, err)
	}
	currentFD := rootFD
	closeCurrent := true
	defer func() {
		if closeCurrent {
			_ = unix.Close(currentFD)
		}
	}()
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return nil, "", fmt.Errorf("cgroup path %q contains invalid component %q", resolved, component)
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) {
				return nil, "", fmt.Errorf("cgroup path %q contains symlink component %q", resolved, component)
			}
			if errors.Is(openErr, unix.ENOTDIR) {
				return nil, "", fmt.Errorf("cgroup path %q component %q is not a directory", resolved, component)
			}
			return nil, "", fmt.Errorf("open cgroup path %q component %q: %w", resolved, component, openErr)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	var stat unix.Stat_t
	if err := unix.Fstat(currentFD, &stat); err != nil {
		return nil, "", fmt.Errorf("stat validated cgroup %q: %w", resolved, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, "", fmt.Errorf("cgroup path %q is not a directory", resolved)
	}
	cgroupID := uint64(stat.Ino)
	if cgroupID != expectedID {
		return nil, "", fmt.Errorf("cgroup path %q has ID %d, want %d", resolved, cgroupID, expectedID)
	}
	cgroup := os.NewFile(uintptr(currentFD), "ztap validated cgroup")
	if cgroup == nil {
		return nil, "", errors.New("create validated cgroup handle")
	}
	closeCurrent = false
	return cgroup, resolved, nil
}

func cgroupInodeID(cgroupPath string) (uint64, error) {
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("cgroup path %q is not a directory", cgroupPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type %T", info.Sys())
	}
	return uint64(stat.Ino), nil
}

func absoluteDirectoryPath(path, fallback string) (string, error) {
	if path == "" {
		path = fallback
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q is not absolute", path)
	}
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", clean, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", resolved)
	}
	return resolved, nil
}

// openEngineDirectoryNoFollow walks an already-canonical absolute directory
// path through descriptor-relative handles. Keeping each parent descriptor
// makes later component replacement unable to redirect the caller through a
// symlink between validation and the final open.
func openEngineDirectoryNoFollow(path, owner string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("%s path %q is not absolute", owner, path)
	}
	clean := filepath.Clean(path)
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open root for %s %q: %w", owner, clean, err)
	}
	currentFD := rootFD
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			_ = unix.Close(currentFD)
			return -1, fmt.Errorf("%s path %q contains parent component", owner, clean)
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = unix.Close(currentFD)
			if errors.Is(openErr, unix.ELOOP) {
				return -1, fmt.Errorf("%s path %q contains symlink component %q", owner, clean, component)
			}
			if errors.Is(openErr, unix.ENOTDIR) {
				return -1, fmt.Errorf("%s path %q component %q is not a directory", owner, clean, component)
			}
			return -1, fmt.Errorf("open %s path %q component %q: %w", owner, clean, component, openErr)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}

func requireFilesystemType(path string, want int64, name string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return fmt.Errorf("inspect %s filesystem %q: %w", name, path, err)
	}
	if stat.Type != want {
		return fmt.Errorf("%s path %q is not %s (filesystem magic %#x)", name, path, name, stat.Type)
	}
	return nil
}

func newAgentEpoch() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	epoch := binary.LittleEndian.Uint64(raw[:])
	if epoch == 0 {
		epoch = 1
	}
	return epoch, nil
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
