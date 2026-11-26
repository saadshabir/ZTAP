//go:build linux

package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/saadshabir/ZTAP/internal/policy"
	"golang.org/x/sys/unix"
)

const (
	durableSchema = 3
	// Changing packet semantics incompatibly requires a migration, even if
	// the map layouts still match. Compatible programs may coexist on links.
	durableSemantics           = 2
	durableMagic        uint64 = 0x5a54415044555233
	durableMetadataPin         = "durable_v3"
	ownerMapName               = "subject_owners"
	programRegistryName        = "program_registry"
	maxDurableMaps             = 32
)

type durableMetadata struct {
	Magic     uint64
	Schema    uint32
	Semantics uint32
	Boot      [32]byte
	Names     [32]byte
	Flags     uint32
	_         uint32
	MapIDs    [maxDurableMaps]uint32
}

type durableOwner struct {
	CgroupID    uint64
	Device      uint64
	PodUID      [64]byte
	ContainerID [64]byte
	Path        [512]byte
}

type durableProgram struct {
	Semantics uint32
	Attach    uint32
	Name      [32]byte
	Tag       [16]byte
}

// durableLinkPair keeps the directory descriptor until its pins have either
// been removed explicitly or its local handles have been released.
type durableLinkPair struct {
	store    *linuxEngineStore
	cgroupID uint64
	links    [2]link.Link
}

func durableMapSpecs(spec *ebpf.CollectionSpec) {
	spec.Maps[durableMetadataPin] = &ebpf.MapSpec{Name: durableMetadataPin, Type: ebpf.Array, KeySize: 4, ValueSize: uint32(binary.Size(durableMetadata{})), MaxEntries: 1}
	spec.Maps[ownerMapName] = &ebpf.MapSpec{Name: ownerMapName, Type: ebpf.Hash, KeySize: 8, ValueSize: uint32(binary.Size(durableOwner{})), MaxEntries: 2 * policy.MaxPolicySubjects}
	spec.Maps[programRegistryName] = &ebpf.MapSpec{Name: programRegistryName, Type: ebpf.Hash, KeySize: 4, ValueSize: uint32(binary.Size(durableProgram{})), MaxEntries: 1024}
	spec.Maps[guardOwnerMapName] = &ebpf.MapSpec{Name: guardOwnerMapName, Type: ebpf.Hash, KeySize: 8, ValueSize: uint32(binary.Size(durableGuardOwner{})), MaxEntries: 4}
	// Reopen committed configuration through owned pins. Opening a map by
	// global kernel ID requires SYS_ADMIN even when BPF/PERFMON are available.
	// The inactive slot is quiescent before reuse, and its epoch prevents ABA.
	for slot := range 2 {
		name := configurationMapName(uint32(slot))
		inner := spec.Maps["active_config"].InnerMap.Copy()
		inner.Name = name
		spec.Maps[name] = inner
	}
}

func configurationMapName(slot uint32) string {
	return "configuration_" + strconv.FormatUint(uint64(slot), 10)
}

func durableMapNames(spec *ebpf.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func currentBootIdentity() ([32]byte, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return [32]byte{}, fmt.Errorf("read kernel boot identity: %w", err)
	}
	if len(strings.TrimSpace(string(boot))) != 36 {
		return [32]byte{}, errors.New("invalid kernel boot identity")
	}
	return sha256.Sum256(boot), nil
}

func trustedPinDirectory(directory *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Uid) != uint64(os.Geteuid()) || st.Mode&0o022 != 0 {
		return errors.New("ZTAP pin directory has a foreign owner or writable permissions")
	}
	return nil
}

func trustedPinAt(directory *os.File, name string) (string, error) {
	path, err := enginePinPathAt(directory, name)
	if err != nil {
		return "", err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Uid) != uint64(os.Geteuid()) || st.Mode&0o022 != 0 {
		return "", fmt.Errorf("pin %q has an unsafe type, owner, or permissions", name)
	}
	return path, nil
}

func newPersistentLinuxEngine(ctx context.Context, options LinuxEngineOptions) (_ *LinuxEngine, resultErr error) {
	return newPersistentLinuxEngineWithSpec(ctx, options, nil, false)
}

// A supplied spec is internal to the loader and Linux compatibility tests;
// deployment never accepts arbitrary programs or a caller-supplied ABI.
func newPersistentLinuxEngineWithSpec(ctx context.Context, options LinuxEngineOptions, spec *ebpf.CollectionSpec, beforeRuntime bool) (_ *LinuxEngine, resultErr error) {
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
		return nil, err
	}
	if err := requireFilesystemType(cgroupRoot, cgroup2SuperMagic, "cgroup v2"); err != nil {
		return nil, err
	}
	bpffsRoot, err := absoluteDirectoryPath(options.BPFFSRoot, "/sys/fs/bpf")
	if err != nil {
		return nil, err
	}
	if err := requireFilesystemType(bpffsRoot, bpfSuperMagic, "bpffs"); err != nil {
		return nil, err
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.AgentEpoch == 0 {
		options.AgentEpoch, err = newAgentEpoch()
		if err != nil {
			return nil, err
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	if spec == nil {
		spec, err = loadEngine()
		if err != nil {
			return nil, err
		}
	}
	if err := validateEngineCollectionSpec(spec); err != nil {
		return nil, err
	}
	durableMapSpecs(spec)
	directory, err := openOrCreateEnginePinDirectory(bpffsRoot)
	if err != nil {
		return nil, err
	}
	store := &linuxEngineStore{
		pinDirectory: directory, pinDirectoryPath: filepath.Join(bpffsRoot, "ztap"),
		flowEventsPin:    filepath.Join(bpffsRoot, "ztap", engineFlowEventsPinName),
		agentStatusPin:   filepath.Join(bpffsRoot, "ztap", engineAgentStatusPinName),
		activeConfigSpec: spec.Maps["active_config"].InnerMap.Copy(), logger: options.Logger,
		agentEpoch: options.AgentEpoch, statusState: engineStateStarting,
		cgroupRoot: cgroupRoot, resolveIdentity: options.ResolveIdentity, validateIdentity: options.ValidateIdentity,
		owners: make(map[uint64]WorkloadIdentity), programs: make(map[ebpf.ProgramID]*ebpf.Program),
		checkpoint: options.ObserveCheckpoint,
		guard:      options.Guard, guardOwners: make(map[uint64]durableGuardOwner), guardLinks: make(map[uint64][3]link.Link), resolvePath: options.ResolveCgroupPath,
	}
	// No failure path unpins kernel state or rewrites its active configuration.
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, store.Close())
		}
	}()
	if err := trustedPinDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	fresh := len(entries) == 0
	if fresh {
		store.collection, err = ebpf.NewCollection(spec)
		if err != nil {
			return nil, fmt.Errorf("load durable collection: %w", err)
		}
		store.maps = store.collection.Maps
		if err := store.initializeActiveConfig(); err != nil {
			return nil, err
		}
		if err := store.publishDurableMaps(spec); err != nil {
			return nil, err
		}
	} else {
		maps, err := openDurableMaps(directory, spec, false)
		if err != nil {
			return nil, fmt.Errorf("recover durable maps (enforcement preserved): %w", err)
		}
		store.maps = maps
		// A replacement collection clones its map replacements. Retain the
		// original descriptors until every existing link has been validated.
		defer func() {
			for _, m := range maps {
				_ = m.Close()
			}
		}()
		if err := store.recoverPrograms(spec); err != nil {
			return nil, err
		}
		store.collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: maps})
		if err != nil {
			return nil, fmt.Errorf("load compatible replacement programs: %w", err)
		}
		store.maps = store.collection.Maps
		if err := store.recoverActiveConfig(); err != nil {
			return nil, err
		}
	}
	active, encoded, err := store.recoverPolicySlots()
	if err != nil {
		return nil, err
	}
	if err := store.recoverOwners(); err != nil {
		return nil, err
	}
	if err := store.validateHostOwners(); err != nil {
		return nil, err
	}
	if err := store.recoverGuardLinks(spec); err != nil {
		return nil, err
	}
	links, candidates, err := store.recoverLinks(active, encoded)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			for _, handle := range links {
				_ = handle.Close()
			}
			for _, handle := range candidates {
				_ = handle.Close()
			}
		}
	}()
	if err := store.validatePinInventory(entries, spec); err != nil {
		return nil, err
	}
	// Register/pin the generation before any link can reference it. A crash
	// between directional updates is recoverable from link info and registry.
	if err := store.publishPrograms(spec); err != nil {
		return nil, err
	}
	store.ObserveCheckpoint("programs-pinned")
	if err := store.updateRecoveredLinks(links, candidates); err != nil {
		return nil, err
	}
	if err := store.installGuard(ctx, options.Guard, beforeRuntime); err != nil {
		return nil, err
	}
	if err := store.retirePrograms(links, candidates); err != nil {
		return nil, err
	}
	linker := &linuxSubjectLinker{cgroupRoot: cgroupRoot, resolvePath: options.ResolveCgroupPath,
		egress: store.collection.Programs["ztap_egress"], ingress: store.collection.Programs["ztap_ingress"],
		cgroupStorage: store.maps["attached_cgroup"], store: store}
	core := newEngineCore(store, linker, options.Logger)
	if err := core.recover(active, encoded, links); err != nil {
		return nil, err
	}
	for id, handle := range candidates {
		core.orphanLinks[id] = []io.Closer{handle}
	}
	if err := store.writeAgentStatus(); err != nil {
		return nil, err
	}
	store.startHeartbeat()
	return &LinuxEngine{engineCore: core, store: store}, nil
}

func (s *linuxEngineStore) publishDurableMaps(spec *ebpf.CollectionSpec) error {
	names := durableMapNames(spec)
	if len(names) > maxDurableMaps {
		return errors.New("too many durable maps for ABI")
	}
	boot, err := currentBootIdentity()
	if err != nil {
		return err
	}
	metadata := durableMetadata{Magic: durableMagic, Schema: durableSchema, Semantics: durableSemantics, Boot: boot, Names: sha256.Sum256([]byte(strings.Join(names, "\x00")))}
	for index, name := range names {
		info, err := s.maps[name].Info()
		if err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("map %s has no kernel identity", name)
		}
		metadata.MapIDs[index] = uint32(id)
	}
	zero := uint32(0)
	if err := s.maps[durableMetadataPin].Put(&zero, &metadata); err != nil {
		return err
	}
	// Publish the ownership journal first. Interrupted initial publication
	// can be intentionally cleaned up using its recorded kernel object IDs.
	names = append([]string{durableMetadataPin}, slices.DeleteFunc(names, func(name string) bool { return name == durableMetadataPin })...)
	for _, name := range names {
		path, err := enginePinPathAt(s.pinDirectory, name)
		if err != nil {
			return err
		}
		if err := s.maps[name].Pin(path); err != nil {
			return fmt.Errorf("pin durable map %s: %w", name, err)
		}
		if name == durableMetadataPin {
			s.ObserveCheckpoint("durable-metadata-pinned")
		}
	}
	return nil
}

func openDurableMaps(directory *os.File, spec *ebpf.CollectionSpec, allowMissing bool) (_ map[string]*ebpf.Map, resultErr error) {
	maps := make(map[string]*ebpf.Map)
	defer func() {
		if resultErr != nil {
			for _, m := range maps {
				_ = m.Close()
			}
		}
	}()
	path, err := trustedPinAt(directory, durableMetadataPin)
	if err != nil {
		return nil, fmt.Errorf("durable ownership metadata required: %w", err)
	}
	metadataMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, err
	}
	maps[durableMetadataPin] = metadataMap
	if err := spec.Maps[durableMetadataPin].Compatible(metadataMap); err != nil {
		return nil, err
	}
	var metadata durableMetadata
	zero := uint32(0)
	if err := metadataMap.Lookup(&zero, &metadata); err != nil {
		return nil, err
	}
	boot, err := currentBootIdentity()
	if err != nil {
		return nil, err
	}
	names := durableMapNames(spec)
	if len(names) > maxDurableMaps || metadata.Magic != durableMagic || metadata.Schema != durableSchema || metadata.Semantics != durableSemantics || metadata.Boot != boot || metadata.Names != sha256.Sum256([]byte(strings.Join(names, "\x00"))) {
		return nil, errors.New("incompatible durable ABI, program semantics, map inventory, or boot identity")
	}
	if metadata.Flags > 1 || (metadata.Flags != 0 && !allowMissing) {
		return nil, errors.New("intentional enforcement removal is incomplete; retry cleanup")
	}
	for index, name := range names {
		m := maps[name]
		if m == nil {
			path, err := trustedPinAt(directory, name)
			if allowMissing && errors.Is(err, unix.ENOENT) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("validate map pin %s: %w", name, err)
			}
			m, err = ebpf.LoadPinnedMap(path, nil)
			if err != nil {
				return nil, err
			}
			maps[name] = m
		}
		if err := spec.Maps[name].Compatible(m); err != nil {
			return nil, fmt.Errorf("incompatible map %s: %w", name, err)
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		id, ok := info.ID()
		if !ok || uint32(id) != metadata.MapIDs[index] {
			return nil, fmt.Errorf("map %s is not the recorded kernel object", name)
		}
	}
	return maps, nil
}

func (s *linuxEngineStore) recoverActiveConfig() error {
	zero := uint32(0)
	var id uint32
	if err := s.maps["active_config"].Lookup(&zero, &id); err != nil {
		return fmt.Errorf("read active configuration pointer: %w", err)
	}
	for slot := range uint32(2) {
		inner := s.maps[configurationMapName(slot)]
		info, err := inner.Info()
		if err != nil {
			return err
		}
		kernelID, ok := info.ID()
		if !ok || uint32(kernelID) != id {
			continue
		}
		var config bpfActiveConfig
		if err := inner.Lookup(&zero, &config); err != nil {
			return err
		}
		if config.ActiveSlot != slot {
			return errors.New("committed configuration targets a different policy slot")
		}
		s.activeConfigMap, err = inner.Clone()
		return err
	}
	return errors.New("active configuration does not reference a verified owned map")
}

func (s *linuxEngineStore) recoverPolicySlots() (activeConfiguration, encodedPolicySet, error) {
	zero := uint32(0)
	var config bpfActiveConfig
	if err := s.activeConfigMap.Lookup(&zero, &config); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	if config.ActiveSlot > 1 {
		return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable active slot")
	}
	sets := [2]policy.PolicySet{}
	subjectIndexes := [2]map[uint64]int{{}, {}}
	portRangeMasks := make(map[uint64][2]uint16)
	var sk subjectStateKey
	var sv subjectStateValue
	iter := s.maps["subject_state"].Iterate()
	for iter.Next(&sk, &sv) {
		if sk.Slot > 1 {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable subject slot")
		}
		subjectIndexes[sk.Slot][sk.CgroupID] = len(sets[sk.Slot].Subjects)
		sets[sk.Slot].Subjects = append(sets[sk.Slot].Subjects, policy.Subject{CgroupID: sk.CgroupID, Isolated: policy.Direction(sv.Isolated), Quarantined: policy.Direction(sv.Quarantined)})
		if sk.Slot == config.ActiveSlot && sv.PortRangeMasks != [2]uint16{} {
			portRangeMasks[sk.CgroupID] = sv.PortRangeMasks
		}
		s.slotCounts[sk.Slot].subjects++
	}
	if err := iter.Err(); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	var nk nodeBypassKey
	var present uint8
	iter = s.maps["workload_class"].Iterate()
	for iter.Next(&sk, &present) {
		if sk.Slot > 1 || sk.CgroupID == 0 || present != 1 {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable workload classification")
		}
		sets[sk.Slot].ClassifiedCgroups = append(sets[sk.Slot].ClassifiedCgroups, sk.CgroupID)
		s.slotCounts[sk.Slot].classified++
	}
	if err := iter.Err(); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	iter = s.maps["node_bypass"].Iterate()
	for iter.Next(&nk, &present) {
		if nk.Slot > 1 || present != 1 {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable node entry")
		}
		sets[nk.Slot].NodeIPs = append(sets[nk.Slot].NodeIPs, netip.AddrFrom4(nk.Address))
		s.slotCounts[nk.Slot].nodes++
	}
	if err := iter.Err(); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	var self selfBypassKey
	iter = s.maps["self_bypass"].Iterate()
	for iter.Next(&self, &present) {
		if self.Slot > 1 || present != 1 {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable self entry")
		}
		if index, found := subjectIndexes[self.Slot][self.CgroupID]; found {
			sets[self.Slot].Subjects[index].PodIPs = append(sets[self.Slot].Subjects[index].PodIPs, netip.AddrFrom4(self.Address))
		} else if self.Slot == config.ActiveSlot {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("committed self bypass has no subject")
		}
		s.slotCounts[self.Slot].self++
	}
	if err := iter.Err(); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	var rk policyRuleKey
	iter = s.maps["policy_rules"].Iterate()
	for iter.Next(&rk, &present) {
		slot := rk.Meta >> 31
		if rk.PrefixLength < 96 || rk.PrefixLength > 128 || present != 1 || rk.Meta&0x30000000 != 0 {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("invalid durable policy rule")
		}
		sets[slot].Rules = append(sets[slot].Rules, policy.Rule{
			CgroupID: rk.CgroupID, Direction: policy.DirectionEgress << rk.directionIndex(),
			Peer:     netip.PrefixFrom(netip.AddrFrom4(rk.Peer), int(rk.PrefixLength)-96),
			Protocol: uint8(rk.Meta >> 16), Port: uint16(rk.Meta), PortWildcardBits: rk.portWildcardBits(),
		})
		s.slotCounts[slot].rules++
	}
	if err := iter.Err(); err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	// The inactive slot may be partially populated. Validate only committed
	// contents; reclaim the inactive slot after its existing counters quiesce.
	if config.PolicyEpoch == 0 {
		if config.ActiveSlot != 0 || s.slotCounts[config.ActiveSlot] != (slotMapCounts{}) {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("uncommitted initial configuration has nonempty active policy")
		}
		return activeConfiguration{}, encodedPolicySet{}, nil
	}
	encoded, err := encodePolicySet(0, sets[config.ActiveSlot])
	if err != nil {
		return activeConfiguration{}, encodedPolicySet{}, err
	}
	for _, subject := range encoded.Subjects {
		if subject.Value.PortRangeMasks != portRangeMasks[subject.Key.CgroupID] {
			return activeConfiguration{}, encodedPolicySet{}, errors.New("durable subject port range masks do not match committed rules")
		}
	}
	return activeConfiguration{Slot: config.ActiveSlot, PolicyEpoch: config.PolicyEpoch}, encoded, nil
}

func ownerToDisk(owner WorkloadIdentity) (durableOwner, error) {
	if owner.CgroupID == 0 || owner.Path == "" || filepath.IsAbs(owner.Path) || filepath.Clean(owner.Path) != owner.Path || owner.Path == "." || owner.Path == ".." || strings.HasPrefix(owner.Path, "../") || strings.ContainsRune(owner.Path, 0) || len(owner.Path) >= 512 || len(owner.PodUID) >= 64 || len(owner.ContainerID) > 64 {
		return durableOwner{}, errors.New("invalid durable workload identity")
	}
	if strings.ContainsRune(owner.PodUID, 0) || strings.ContainsRune(owner.ContainerID, 0) {
		return durableOwner{}, errors.New("invalid durable runtime identity")
	}
	value := durableOwner{CgroupID: owner.CgroupID, Device: owner.Device}
	copy(value.PodUID[:], owner.PodUID)
	copy(value.ContainerID[:], owner.ContainerID)
	copy(value.Path[:], owner.Path)
	return value, nil
}

func ownerFromDisk(value durableOwner) (WorkloadIdentity, error) {
	owner := WorkloadIdentity{CgroupID: value.CgroupID, Device: value.Device, PodUID: strings.TrimRight(string(value.PodUID[:]), "\x00"), ContainerID: strings.TrimRight(string(value.ContainerID[:]), "\x00"), Path: strings.TrimRight(string(value.Path[:]), "\x00")}
	reencoded, err := ownerToDisk(owner)
	if err != nil || reencoded != value {
		return WorkloadIdentity{}, errors.New("corrupt durable workload identity")
	}
	return owner, nil
}

func (s *linuxEngineStore) recoverOwners() error {
	var id uint64
	var value durableOwner
	iter := s.maps[ownerMapName].Iterate()
	for iter.Next(&id, &value) {
		owner, err := ownerFromDisk(value)
		if err != nil || owner.CgroupID != id {
			return fmt.Errorf("invalid ownership metadata for cgroup %d", id)
		}
		s.owners[id] = owner
	}
	return iter.Err()
}

// Missing/replaced cgroups are kernel evidence of termination. An API omission
// or a permissions/read error is uncertainty and never authorizes removal.
func (s *linuxEngineStore) ownerLive(owner WorkloadIdentity) (bool, error) {
	file, _, err := openValidatedCgroup(s.cgroupRoot, filepath.Join(s.cgroupRoot, owner.Path), owner.CgroupID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errCgroupReplaced) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return false, err
	}
	if uint64(st.Dev) != owner.Device {
		return false, errors.New("committed cgroup filesystem identity changed")
	}
	return true, nil
}

func (s *linuxEngineStore) ValidateCandidate(ctx context.Context, candidate encodedPolicySet) error {
	if err := s.validateGuardCandidate(candidate); err != nil {
		return err
	}
	zero := uint32(0)
	var active bpfActiveConfig
	if err := s.activeConfigMap.Lookup(&zero, &active); err != nil {
		return err
	}
	committed := make(map[uint64]bool)
	var key subjectStateKey
	var value subjectStateValue
	iter := s.maps["subject_state"].Iterate()
	for iter.Next(&key, &value) {
		if key.Slot == active.ActiveSlot {
			committed[key.CgroupID] = true
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	var present uint8
	iter = s.maps["workload_class"].Iterate()
	for iter.Next(&key, &present) {
		if key.Slot == active.ActiveSlot {
			committed[key.CgroupID] = true
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for id := range committed {
		if err := ctx.Err(); err != nil {
			return err
		}
		owner, ok := s.owners[id]
		if !ok {
			return fmt.Errorf("committed cgroup %d has no durable ownership", id)
		}
		live, err := s.ownerLive(owner)
		if err != nil {
			return fmt.Errorf("%w: cgroup %d: %w", ErrIdentityUncertain, id, err)
		}
		if !live {
			continue
		}
		if s.validateIdentity != nil {
			if err := s.validateIdentity(ctx, owner); err != nil {
				return fmt.Errorf("%w: live cgroup %d: %w", ErrIdentityUncertain, id, err)
			}
		}
	}
	return nil
}

func (s *linuxEngineStore) rememberOwner(ctx context.Context, id uint64, path string) error {
	file, resolved, err := openValidatedCgroup(s.cgroupRoot, path, id)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return err
	}
	relative, err := filepath.Rel(s.cgroupRoot, resolved)
	if err != nil {
		return err
	}
	owner := WorkloadIdentity{CgroupID: id, Device: uint64(st.Dev), Path: relative}
	if s.resolveIdentity != nil {
		owner, err = s.resolveIdentity(ctx, id)
		if err != nil {
			return err
		}
		if owner.CgroupID != id || owner.Device != uint64(st.Dev) || owner.Path != relative || owner.PodUID == "" || len(owner.ContainerID) != 64 {
			return errors.New("resolver returned incomplete or inconsistent workload ownership")
		}
	}
	value, err := ownerToDisk(owner)
	if err != nil {
		return err
	}
	if existing, ok := s.owners[id]; ok && existing != owner {
		return errors.New("cgroup identity conflicts with persisted ownership")
	}
	if err := s.maps[ownerMapName].Put(&id, &value); err != nil {
		return err
	}
	s.owners[id] = owner
	return nil
}

func programPinName(id ebpf.ProgramID) string { return "program_" + strconv.FormatUint(uint64(id), 10) }
func subjectPinName(id uint64, direction int) string {
	suffix := "egress"
	if direction == 1 {
		suffix = "ingress"
	}
	return "subject_" + strconv.FormatUint(id, 10) + "_" + suffix
}

func expectedProgramMapIDs(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map) ([]ebpf.MapID, error) {
	seen := make(map[ebpf.MapID]bool)
	for _, instruction := range spec.Instructions {
		m := maps[instruction.Reference()]
		if m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		id, ok := info.ID()
		if !ok {
			return nil, errors.New("program map has no kernel ID")
		}
		seen[id] = true
	}
	ids := make([]ebpf.MapID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func verifyProgramMaps(program *ebpf.Program, expected *ebpf.ProgramSpec, maps map[string]*ebpf.Map) error {
	info, err := program.Info()
	if err != nil {
		return err
	}
	if info.Type != expected.Type {
		return errors.New("foreign program type")
	}
	actual, ok := info.MapIDs()
	if !ok {
		return errors.New("kernel cannot verify program-to-map references")
	}
	wanted, err := expectedProgramMapIDs(expected, maps)
	if err != nil {
		return err
	}
	slices.Sort(actual)
	if !slices.Equal(actual, wanted) {
		return errors.New("program does not reference exactly the verified enforcement maps")
	}
	return nil
}

func (s *linuxEngineStore) recoverPrograms(spec *ebpf.CollectionSpec) error {
	var id uint32
	var record durableProgram
	iter := s.maps[programRegistryName].Iterate()
	for iter.Next(&id, &record) {
		name := strings.TrimRight(string(record.Name[:]), "\x00")
		expected := spec.Programs[name]
		if expected == nil || record.Semantics != durableSemantics || record.Attach != uint32(expected.AttachType) {
			return errors.New("incompatible pinned program generation")
		}
		path, err := trustedPinAt(s.pinDirectory, programPinName(ebpf.ProgramID(id)))
		if errors.Is(err, unix.ENOENT) {
			// An interrupted publication/retirement leaves a registry record
			// without a pin. It is reclaimable only after every surviving link
			// has been checked and none refers to this missing generation.
			s.stalePrograms = append(s.stalePrograms, id)
			continue
		}
		if err != nil {
			return err
		}
		program, err := ebpf.LoadPinnedProgram(path, nil)
		if err != nil {
			return err
		}
		s.programs[ebpf.ProgramID(id)] = program
		info, err := program.Info()
		if err != nil {
			return err
		}
		kernelID, ok := info.ID()
		if !ok || uint32(kernelID) != id || info.Tag != strings.TrimRight(string(record.Tag[:]), "\x00") {
			return errors.New("pinned program is not the recorded kernel object")
		}
		if err := verifyProgramMaps(program, expected, s.maps); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (s *linuxEngineStore) publishPrograms(spec *ebpf.CollectionSpec) error {
	for name, program := range s.collection.Programs {
		info, err := program.Info()
		if err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok {
			return errors.New("program has no kernel ID")
		}
		record := durableProgram{Semantics: durableSemantics, Attach: uint32(spec.Programs[name].AttachType)}
		copy(record.Name[:], name)
		copy(record.Tag[:], info.Tag)
		path, err := enginePinPathAt(s.pinDirectory, programPinName(id))
		if err != nil {
			return err
		}
		key := uint32(id)
		if err := s.maps[programRegistryName].Put(&key, &record); err != nil {
			return err
		}
		if err := program.Pin(path); err != nil {
			return err
		}
	}
	return nil
}

func (s *linuxEngineStore) validatePinInventory(entries []os.DirEntry, spec *ebpf.CollectionSpec) error {
	expected := make(map[string]bool)
	for name := range spec.Maps {
		expected[name] = true
	}
	for id := range s.programs {
		expected[programPinName(id)] = true
	}
	for _, id := range s.stalePrograms {
		expected[programPinName(ebpf.ProgramID(id))] = true
	}
	for id := range s.owners {
		for direction := range 2 {
			expected[subjectPinName(id, direction)] = true
		}
	}
	for id := range s.guardOwners {
		for direction := range 3 {
			expected[guardPinName(id, direction)] = true
		}
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return fmt.Errorf("foreign or unjournaled pin %q; enforcement preserved", entry.Name())
		}
	}
	return nil
}

func (s *linuxEngineStore) retirePrograms(active map[uint64]io.Closer, candidates map[uint64]*durableLinkPair) error {
	used := make(map[ebpf.ProgramID]bool)
	for _, handles := range s.guardLinks {
		for _, handle := range handles {
			if handle != nil {
				info, err := handle.Info()
				if err != nil {
					return err
				}
				used[info.Program] = true
			}
		}
	}
	for _, program := range s.collection.Programs {
		info, err := program.Info()
		if err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok {
			return errors.New("new program has no kernel ID")
		}
		used[id] = true
	}
	pairs := make([]*durableLinkPair, 0, len(active)+len(candidates))
	for _, handle := range active {
		pairs = append(pairs, handle.(*durableLinkPair))
	}
	for _, handle := range candidates {
		pairs = append(pairs, handle)
	}
	for _, pair := range pairs {
		for _, handle := range pair.links {
			if handle != nil {
				info, err := handle.Info()
				if err != nil {
					return err
				}
				used[info.Program] = true
			}
		}
	}
	for id, program := range s.programs {
		if used[id] {
			continue
		}
		if err := removeOwnedEnginePinAt(int(s.pinDirectory.Fd()), programPinName(id)); err != nil {
			return err
		}
		key := uint32(id)
		if err := s.maps[programRegistryName].Delete(&key); err != nil {
			return err
		}
		if err := program.Close(); err != nil {
			return err
		}
		delete(s.programs, id)
	}
	for _, id := range s.stalePrograms {
		if used[ebpf.ProgramID(id)] {
			return errors.New("live link references a missing program pin")
		}
		if err := s.maps[programRegistryName].Delete(&id); err != nil {
			return err
		}
	}
	s.stalePrograms = nil
	return nil
}

func (s *linuxEngineStore) programGeneration() (string, error) {
	var tags []string
	for _, name := range []string{"ztap_egress", "ztap_ingress", "ztap_guard_egress", "ztap_guard_ingress", "ztap_socket_namespace"} {
		info, err := s.collection.Programs[name].Info()
		if err != nil {
			return "", err
		}
		tags = append(tags, info.Tag)
	}
	digest := sha256.Sum256([]byte(strings.Join(tags, ":")))
	return fmt.Sprintf("v%d-%x", durableSemantics, digest[:8]), nil
}

func (s *linuxEngineStore) recoverLinks(_ activeConfiguration, encoded encodedPolicySet) (_ map[uint64]io.Closer, _ map[uint64]*durableLinkPair, resultErr error) {
	active := make(map[uint64]bool)
	for _, subject := range encoded.Subjects {
		active[subject.Key.CgroupID] = true
	}
	links := make(map[uint64]io.Closer)
	candidates := make(map[uint64]*durableLinkPair)
	defer func() {
		if resultErr != nil {
			for _, handle := range links {
				_ = handle.Close()
			}
			for _, handle := range candidates {
				_ = handle.Close()
			}
		}
	}()
	for id, owner := range s.owners {
		live, err := s.ownerLive(owner)
		if err != nil {
			return nil, nil, err
		}
		pair := &durableLinkPair{store: s, cgroupID: id}
		if active[id] {
			links[id] = pair
		} else {
			candidates[id] = pair
		}
		for direction := range pair.links {
			path, err := trustedPinAt(s.pinDirectory, subjectPinName(id, direction))
			if errors.Is(err, unix.ENOENT) && (!active[id] || !live) {
				continue
			}
			if err != nil {
				return nil, nil, fmt.Errorf("recover cgroup %d direction %d: %w", id, direction, err)
			}
			handle, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				return nil, nil, err
			}
			pair.links[direction] = handle
			info, err := handle.Info()
			if err != nil {
				return nil, nil, err
			}
			cgroup := info.Cgroup()
			attach := ebpf.AttachCGroupInetEgress
			if direction == 1 {
				attach = ebpf.AttachCGroupInetIngress
			}
			if cgroup == nil || (cgroup.CgroupId != id && (live || cgroup.CgroupId != 0)) || uint32(cgroup.AttachType) != uint32(attach) || s.programs[info.Program] == nil {
				return nil, nil, errors.New("foreign cgroup link target, attachment type, or program")
			}
			var record durableProgram
			key := uint32(info.Program)
			if err := s.maps[programRegistryName].Lookup(&key, &record); err != nil {
				return nil, nil, err
			}
			if record.Attach != uint32(attach) || strings.TrimRight(string(record.Name[:]), "\x00") != [2]string{"ztap_egress", "ztap_ingress"}[direction] {
				return nil, nil, errors.New("link references wrong directional program")
			}
			if live && active[id] {
				storageKey := cgroupStorageKey{CgroupID: id, AttachType: uint32(attach)}
				var stored uint64
				if err := s.maps["attached_cgroup"].Lookup(&storageKey, &stored); err != nil || stored != id {
					return nil, nil, errors.New("attached cgroup identity storage is inconsistent")
				}
			}
		}
	}
	for id := range active {
		if links[id] == nil {
			return nil, nil, fmt.Errorf("committed subject %d has no ownership metadata", id)
		}
	}
	for _, key := range encoded.Classified {
		if _, exists := s.owners[key.CgroupID]; !exists {
			return nil, nil, errors.New("committed classification has no durable owner")
		}
	}
	return links, candidates, nil
}

func (s *linuxEngineStore) updateRecoveredLinks(active map[uint64]io.Closer, candidates map[uint64]*durableLinkPair) error {
	pairs := make([]*durableLinkPair, 0, len(active)+len(candidates))
	for _, handle := range active {
		pairs = append(pairs, handle.(*durableLinkPair))
	}
	for _, pair := range candidates {
		pairs = append(pairs, pair)
	}
	for _, pair := range pairs {
		live, err := s.ownerLive(s.owners[pair.cgroupID])
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		for direction, handle := range pair.links {
			if handle == nil {
				continue
			}
			name := "ztap_egress"
			if direction == 1 {
				name = "ztap_ingress"
			}
			if err := handle.Update(s.collection.Programs[name]); err != nil {
				return fmt.Errorf("update pinned link in place: %w", err)
			}
			s.ObserveCheckpoint(name + "-updated")
		}
	}
	return nil
}

func (p *durableLinkPair) Close() error {
	var errs []error
	for direction, handle := range p.links {
		if handle != nil {
			if err := handle.Close(); err != nil {
				errs = append(errs, err)
			} else {
				p.links[direction] = nil
			}
		}
	}
	return errors.Join(errs...)
}

func (p *durableLinkPair) Remove() error {
	// Re-read the authoritative commit, so cleanup cannot detach a newly
	// committed pair even if an in-memory transaction record is stale.
	zero := uint32(0)
	var active bpfActiveConfig
	if err := p.store.activeConfigMap.Lookup(&zero, &active); err != nil {
		return err
	}
	key := subjectStateKey{CgroupID: p.cgroupID, Slot: active.ActiveSlot}
	var subject subjectStateValue
	err := p.store.maps["subject_state"].Lookup(&key, &subject)
	if err == nil {
		return errors.New("refuse removal of a committed subject attachment")
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	for direction := range p.links {
		name := subjectPinName(p.cgroupID, direction)
		if err := removeOwnedEnginePinAt(int(p.store.pinDirectory.Fd()), name); err != nil {
			return err
		}
		if p.links[direction] != nil {
			if err := p.links[direction].Close(); err != nil {
				return err
			}
			p.links[direction] = nil
		}
		p.store.ObserveCheckpoint("obsolete-" + []string{"egress", "ingress"}[direction] + "-removed")
	}
	if err := p.Close(); err != nil {
		return err
	}
	var classified uint8
	if err := p.store.maps["workload_class"].Lookup(&key, &classified); err == nil {
		return nil // Link removal must retain ownership of an active unisolated workload.
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if err := p.store.maps[ownerMapName].Delete(&p.cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	delete(p.store.owners, p.cgroupID)
	return nil
}

func (l *linuxSubjectLinker) Attach(ctx context.Context, id uint64) (io.Closer, error) {
	if ctx == nil {
		return nil, errors.New("attach cgroup context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := l.resolvePath(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := l.store.rememberOwner(ctx, id, path); err != nil {
		return nil, err
	}
	pair := &durableLinkPair{store: l.store, cgroupID: id}
	cgroup, _, err := openValidatedCgroup(l.cgroupRoot, path, id)
	if err != nil {
		return pair, err
	}
	defer func() { _ = cgroup.Close() }()
	for direction := range pair.links {
		if err := ctx.Err(); err != nil {
			return pair, err
		}
		attach, program := ebpf.AttachCGroupInetEgress, l.egress
		if direction == 1 {
			attach, program = ebpf.AttachCGroupInetIngress, l.ingress
		}
		if err := rejectIncompatibleCgroupProgram(cgroup, attach, program); err != nil {
			return pair, err
		}
		handle, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroup.Fd()), Program: program, Attach: attach})
		if err != nil {
			return pair, fmt.Errorf("restart-safe enforcement requires pinnable cgroup bpf_link support: %w", err)
		}
		pair.links[direction] = handle
		pin, err := enginePinPathAt(l.store.pinDirectory, subjectPinName(id, direction))
		if err != nil {
			return pair, err
		}
		if err := handle.Pin(pin); err != nil {
			return pair, err
		}
		name := "egress-link-pinned"
		if direction == 1 {
			name = "ingress-link-pinned"
		}
		l.store.ObserveCheckpoint(name)
		// Probe reopening and atomic replacement instead of assuming support
		// based on a kernel version. The pinned attachment stays in place.
		probe, err := link.LoadPinnedLink(pin, nil)
		if err != nil {
			return pair, fmt.Errorf("reopen pinned cgroup link: %w", err)
		}
		updateErr := probe.Update(program)
		closeErr := probe.Close()
		if err := errors.Join(updateErr, closeErr); err != nil {
			return pair, fmt.Errorf("probe pinned cgroup program replacement: %w", err)
		}
		key := cgroupStorageKey{CgroupID: id, AttachType: uint32(attach)}
		if err := l.cgroupStorage.Put(&key, &id); err != nil {
			return pair, err
		}
		if err := rejectIncompatibleCgroupProgram(cgroup, attach, program); err != nil {
			return pair, err
		}
	}
	return pair, ctx.Err()
}

func (s *linuxEngineStore) ObserveCheckpoint(name string) {
	if s.checkpoint != nil {
		s.checkpoint(name)
	}
}
