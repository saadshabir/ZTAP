//go:build linux

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const guardOwnerMapName = "guard_owners"

type durableGuardOwner struct {
	CgroupID uint64
	Device   uint64
	Complete uint32
	_        uint32
	Path     [512]byte
}

type bpfGuardConfig struct {
	HostNetnsCookie uint64
	BootstrapCgroup uint64
}

type bootstrapPeerKey struct {
	Address   [4]byte
	Port      uint16
	Direction uint8
	_         uint8
}

var guardProgramNames = [3]string{"ztap_guard_egress", "ztap_guard_ingress", "ztap_socket_namespace"}
var guardAttachTypes = [3]ebpf.AttachType{ebpf.AttachCGroupInetEgress, ebpf.AttachCGroupInetIngress, ebpf.AttachCGroupInetSockCreate}

func guardPinName(id uint64, direction int) string {
	return "guard_" + strconv.FormatUint(id, 10) + "_" + [3]string{"egress", "ingress", "socket"}[direction]
}

func clearClassifiedMap(m *ebpf.Map, slot uint32) error {
	var keys []subjectStateKey
	var key subjectStateKey
	var value uint8
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return deleteMapKeys(m, "workload_class", keys)
}

func (s *linuxEngineStore) recoverGuardLinks(spec *ebpf.CollectionSpec) error {
	var id uint64
	var owner durableGuardOwner
	iter := s.maps[guardOwnerMapName].Iterate()
	for iter.Next(&id, &owner) {
		path := strings.TrimRight(string(owner.Path[:]), "\x00")
		if id == 0 || id != owner.CgroupID || owner.Complete > 1 || filepath.Clean(path) != path || filepath.IsAbs(path) || path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsRune(path, 0) {
			return errors.New("invalid parent guard ownership")
		}
		if path == "" {
			return errors.New("empty parent guard path")
		}
		file, _, err := openValidatedCgroup(s.cgroupRoot, filepath.Join(s.cgroupRoot, path), id)
		if err != nil {
			return fmt.Errorf("parent guard identity changed: %w", err)
		}
		var st unix.Stat_t
		err = unix.Fstat(int(file.Fd()), &st)
		_ = file.Close()
		if err != nil || uint64(st.Dev) != owner.Device {
			return errors.New("parent guard filesystem changed")
		}
		s.guardOwners[id] = owner
		for direction, attach := range guardAttachTypes {
			path, err := trustedPinAt(s.pinDirectory, guardPinName(id, direction))
			if errors.Is(err, unix.ENOENT) && owner.Complete == 0 {
				continue
			}
			if err != nil {
				return fmt.Errorf("recover parent guard: %w", err)
			}
			handle, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				return err
			}
			handles := s.guardLinks[id]
			handles[direction] = handle
			s.guardLinks[id] = handles
			info, err := handle.Info()
			if err != nil {
				return err
			}
			cg := info.Cgroup()
			var record durableProgram
			key := uint32(info.Program)
			if err := s.maps[programRegistryName].Lookup(&key, &record); err != nil {
				return err
			}
			if cg == nil || cg.CgroupId != id || uint32(cg.AttachType) != uint32(attach) || s.programs[info.Program] == nil || record.Attach != uint32(attach) || strings.TrimRight(string(record.Name[:]), "\x00") != guardProgramNames[direction] {
				return errors.New("foreign parent guard link or program")
			}
			if err := verifyProgramMaps(s.programs[info.Program], spec.Programs[guardProgramNames[direction]], s.maps); err != nil {
				return err
			}
		}
	}
	return iter.Err()
}

func (s *linuxEngineStore) installGuard(ctx context.Context, options *WorkloadGuardOptions) error {
	if options == nil {
		if len(s.guardOwners) != 0 {
			return errors.New("existing workload guard requires verified node bootstrap configuration")
		}
		return nil
	}
	if err := s.pruneDeadHostOwners(); err != nil {
		return err
	}
	if len(options.Parents) == 0 || len(options.Parents) > 2 || options.HostNetnsCookie == 0 || len(options.APIPeers) == 0 || len(options.APIPeers) > 32 {
		return errors.New("incomplete node guard bootstrap configuration")
	}
	if err := s.validateBootstrapOwner(options.BootstrapIdentity); err != nil {
		return err
	}
	zero := uint32(0)
	var previous bpfGuardConfig
	if err := s.maps["guard_config"].Lookup(&zero, &previous); err != nil {
		return err
	}
	if previous.HostNetnsCookie != 0 && previous.HostNetnsCookie != options.HostNetnsCookie {
		return errors.New("node network namespace changed within this boot")
	}
	// Narrow peers are established before granting the new exact cgroup ID.
	var keys []bootstrapPeerKey
	var key bootstrapPeerKey
	var present uint8
	iter := s.maps["bootstrap_peers"].Iterate()
	for iter.Next(&key, &present) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if err := deleteMapKeys(s.maps["bootstrap_peers"], "bootstrap_peers", keys); err != nil {
		return err
	}
	present = 1
	for _, peer := range options.APIPeers {
		if !peer.Addr().Is4() || peer.Port() == 0 {
			return errors.New("bootstrap API endpoint must be IPv4 TCP with an explicit port")
		}
		for direction := uint8(0); direction < 2; direction++ {
			key := bootstrapPeerKey{Address: peer.Addr().As4(), Port: peer.Port(), Direction: direction}
			if err := s.maps["bootstrap_peers"].Put(&key, &present); err != nil {
				return err
			}
		}
	}
	for _, owner := range options.HostNetwork {
		if err := s.validateBootstrapOwner(owner); err != nil {
			// A confirmed dead identity is never transferred to a replacement.
			live, liveErr := s.ownerLive(owner)
			if liveErr != nil || live {
				return err
			}
			continue
		}
		value, err := ownerToDisk(owner)
		if err != nil {
			return err
		}
		if err := s.maps["host_owners"].Put(&owner.CgroupID, &value); err != nil {
			return err
		}
	}
	config := bpfGuardConfig{HostNetnsCookie: options.HostNetnsCookie, BootstrapCgroup: options.BootstrapIdentity.CgroupID}
	if err := s.maps["guard_config"].Put(&zero, &config); err != nil {
		return err
	}
	seen := make(map[uint64]bool)
	for _, relative := range options.Parents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || strings.HasPrefix(relative, "..") {
			return errors.New("invalid Kubernetes parent guard path")
		}
		path := filepath.Join(s.cgroupRoot, relative)
		id, err := cgroupInodeID(path)
		if err != nil {
			return err
		}
		file, _, err := openValidatedCgroup(s.cgroupRoot, path, id)
		if err != nil {
			return err
		}
		err = s.installParentGuard(file, id, relative)
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
		seen[id] = true
	}
	for id := range s.guardOwners {
		if !seen[id] {
			return errors.New("committed Kubernetes guard parent missing from bootstrap configuration")
		}
	}
	return nil
}

// Validate the legacy socket exceptions before updating any recovered links.
// Only the authenticated bootstrap can introduce live host-network owners.
func (s *linuxEngineStore) validateHostOwners() error {
	var id uint64
	var value durableOwner
	iter := s.maps["host_owners"].Iterate()
	for iter.Next(&id, &value) {
		owner, err := ownerFromDisk(value)
		if err != nil || id != owner.CgroupID || owner.PodUID == "" || len(owner.ContainerID) != 64 {
			return errors.New("invalid persisted host-network identity")
		}
		if _, err := s.ownerLive(owner); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (s *linuxEngineStore) pruneDeadHostOwners() error {
	var stale []uint64
	var id uint64
	var value durableOwner
	iter := s.maps["host_owners"].Iterate()
	for iter.Next(&id, &value) {
		owner, err := ownerFromDisk(value)
		if err != nil {
			return err
		}
		live, err := s.ownerLive(owner)
		if err != nil {
			return err
		}
		if !live {
			stale = append(stale, id)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return deleteMapKeys(s.maps["host_owners"], "host_owners", stale)
}

func (s *linuxEngineStore) validateBootstrapOwner(owner WorkloadIdentity) error {
	if owner.PodUID == "" || len(owner.ContainerID) != 64 {
		return errors.New("incomplete bootstrap workload identity")
	}
	if _, err := ownerToDisk(owner); err != nil {
		return err
	}
	live, err := s.ownerLive(owner)
	if err != nil {
		return err
	}
	if !live {
		return errors.New("bootstrap cgroup is no longer live")
	}
	return nil
}

func (s *linuxEngineStore) installParentGuard(file *os.File, id uint64, relative string) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return err
	}
	owner, exists := s.guardOwners[id]
	if !exists {
		owner = durableGuardOwner{CgroupID: id, Device: uint64(st.Dev)}
		if len(relative) >= len(owner.Path) {
			return errors.New("parent guard path too long")
		}
		copy(owner.Path[:], relative)
		if err := s.maps[guardOwnerMapName].Put(&id, &owner); err != nil {
			return err
		}
		s.guardOwners[id] = owner
	}
	// Install socket capture first, before either directional guard can block.
	for _, direction := range []int{2, 0, 1} {
		program := s.collection.Programs[guardProgramNames[direction]]
		handles := s.guardLinks[id]
		if handles[direction] != nil {
			if err := handles[direction].Update(program); err != nil {
				return fmt.Errorf("update pinned parent guard: %w", err)
			}
		} else {
			if err := rejectIncompatibleCgroupProgram(file, guardAttachTypes[direction], program); err != nil {
				return err
			}
			handle, err := link.AttachRawLink(link.RawLinkOptions{Target: int(file.Fd()), Program: program, Attach: guardAttachTypes[direction]})
			if err != nil {
				return fmt.Errorf("parent guard requires pinnable BPF links: %w", err)
			}
			handles[direction] = handle
			s.guardLinks[id] = handles
			path, err := enginePinPathAt(s.pinDirectory, guardPinName(id, direction))
			if err != nil {
				return err
			}
			if err := handle.Pin(path); err != nil {
				return err
			}
			probe, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				return err
			}
			err = probe.Update(program)
			closeErr := probe.Close()
			if err := errors.Join(err, closeErr); err != nil {
				return err
			}
		}
		s.ObserveCheckpoint(guardProgramNames[direction] + "-updated")
	}
	owner.Complete = 1
	if err := s.maps[guardOwnerMapName].Put(&id, &owner); err != nil {
		return err
	}
	s.guardOwners[id] = owner
	return nil
}

func (s *linuxEngineStore) validateGuardCandidate(set encodedPolicySet) error {
	if len(s.guardOwners) == 0 {
		return nil
	}
	classified := make(map[uint64]bool, len(set.Classified))
	for _, key := range set.Classified {
		classified[key.CgroupID] = true
	}
	for _, subject := range set.Subjects {
		if !classified[subject.Key.CgroupID] {
			return errors.New("guarded policy subject lacks explicit classification")
		}
	}
	return nil
}

func (s *linuxEngineStore) pruneUnreferencedOwners() error {
	zero := uint32(0)
	var active bpfActiveConfig
	if err := s.activeConfigMap.Lookup(&zero, &active); err != nil {
		return err
	}
	for id := range s.owners {
		key := subjectStateKey{CgroupID: id, Slot: active.ActiveSlot}
		var present uint8
		if err := s.maps["workload_class"].Lookup(&key, &present); err == nil {
			continue
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		var subject subjectStateValue
		if err := s.maps["subject_state"].Lookup(&key, &subject); err == nil {
			continue
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		pinned := false
		for direction := range 2 {
			_, err := trustedPinAt(s.pinDirectory, subjectPinName(id, direction))
			if err == nil {
				pinned = true
			} else if !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		if pinned {
			continue
		}
		if err := s.maps[ownerMapName].Delete(&id); err != nil {
			return err
		}
		delete(s.owners, id)
	}
	return nil
}
