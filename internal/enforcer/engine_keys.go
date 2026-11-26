package enforcer

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"sort"

	"github.com/saadshabir/ZTAP/internal/policy"
)

// enginePolicyRulesMapFlags is BPF_F_NO_PREALLOC. Keep the ABI flag in the
// common engine definitions so cross-platform layout tests can assert it even
// when the Linux loader is not part of the build.
const enginePolicyRulesMapFlags uint32 = 1

const (
	rulePortWildcardShift = 24
	ruleDirectionShift    = 30
)

type policyRuleKey struct {
	PrefixLength uint32
	Meta         uint32
	CgroupID     uint64
	Peer         [4]byte
	_            [4]byte
}

func (key policyRuleKey) portWildcardBits() uint8 {
	return uint8((key.Meta >> rulePortWildcardShift) & 0xf)
}

func (key policyRuleKey) directionIndex() uint32 {
	return (key.Meta >> ruleDirectionShift) & 1
}

type subjectStateKey struct {
	CgroupID uint64
	Slot     uint32
	_        uint32
}

type subjectStateValue struct {
	Isolated    uint8
	Quarantined uint8
	// Egress, then ingress. Bit n enables lookup of blocks of 1 << (n+1) ports.
	PortRangeMasks [2]uint16
	_              [2]byte
}

type nodeBypassKey struct {
	Slot    uint32
	Address [4]byte
}

type selfBypassKey struct {
	CgroupID uint64
	Slot     uint32
	Address  [4]byte
}

type bpfActiveConfig struct {
	ActiveSlot  uint32
	_           uint32
	PolicyEpoch uint64
}

type cgroupStorageKey struct {
	CgroupID   uint64
	AttachType uint32
	_          uint32
}

type bpfConnectionKey struct {
	PolicyEpoch     uint64
	CgroupID        uint64
	Source          uint32
	Destination     uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
	Direction       uint8
	_               [2]byte
}

type bpfConnectionValue struct {
	ExpiresAtNS      uint64
	TCPFinDirections uint64
}

type bpfEpochDecisionKey struct {
	PolicyEpoch uint64
	Direction   uint8
	Action      uint8
	Reason      uint8
	_           [5]byte
}

type bpfEpochEventDropKey struct {
	PolicyEpoch uint64
	Reason      uint32
	_           uint32
}

type bpfEventLimiterValue struct {
	WindowStartNS uint64
	Emitted       uint32
	_             uint32
}

type encodedPolicySet struct {
	Subjects   []encodedSubjectState
	Nodes      []nodeBypassKey
	Self       []selfBypassKey
	Rules      []policyRuleKey
	Classified []subjectStateKey
}

type encodedSubjectState struct {
	Key   subjectStateKey
	Value subjectStateValue
}

func encodePolicySet(slot uint32, set policy.PolicySet) (encodedPolicySet, error) {
	if slot > 1 {
		return encodedPolicySet{}, fmt.Errorf("policy slot %d is outside 0..1", slot)
	}
	if err := policy.ValidatePolicySet(set); err != nil {
		return encodedPolicySet{}, fmt.Errorf("validate policy set: %w", err)
	}

	encoded := encodedPolicySet{
		Subjects: make([]encodedSubjectState, 0, len(set.Subjects)),
		Nodes:    make([]nodeBypassKey, 0, len(set.NodeIPs)),
		Self:     make([]selfBypassKey, 0),
		Rules:    make([]policyRuleKey, 0, len(set.Rules)),
	}
	seenNodes := make(map[nodeBypassKey]struct{}, len(set.NodeIPs))
	seenSelf := make(map[selfBypassKey]struct{})
	seenRules := make(map[policyRuleKey]struct{}, len(set.Rules))
	portRangeMasks := make(map[uint64][2]uint16)

	for _, rule := range set.Rules {
		key, err := encodePolicyRuleKey(slot, rule)
		if err != nil {
			return encodedPolicySet{}, err
		}
		seenRules[key] = struct{}{}
		if wildcardBits := key.portWildcardBits(); wildcardBits != 0 {
			masks := portRangeMasks[key.CgroupID]
			masks[key.directionIndex()] |= 1 << (wildcardBits - 1)
			portRangeMasks[key.CgroupID] = masks
		}
	}
	for key := range seenRules {
		encoded.Rules = append(encoded.Rules, key)
	}

	for _, subject := range set.Subjects {
		encoded.Subjects = append(encoded.Subjects, encodedSubjectState{
			Key: subjectStateKey{CgroupID: subject.CgroupID, Slot: slot},
			Value: subjectStateValue{
				Isolated:       uint8(subject.Isolated),
				Quarantined:    uint8(subject.Quarantined),
				PortRangeMasks: portRangeMasks[subject.CgroupID],
			},
		})
		for _, address := range subject.PodIPs {
			key := selfBypassKey{CgroupID: subject.CgroupID, Slot: slot}
			key.Address = address.As4()
			seenSelf[key] = struct{}{}
		}
	}
	for _, id := range set.ClassifiedCgroups {
		encoded.Classified = append(encoded.Classified, subjectStateKey{CgroupID: id, Slot: slot})
	}
	sort.Slice(encoded.Classified, func(i, j int) bool { return encoded.Classified[i].CgroupID < encoded.Classified[j].CgroupID })
	for address := range seenSelf {
		encoded.Self = append(encoded.Self, address)
	}
	for _, address := range set.NodeIPs {
		key := nodeBypassKey{Slot: slot, Address: address.As4()}
		seenNodes[key] = struct{}{}
	}
	for key := range seenNodes {
		encoded.Nodes = append(encoded.Nodes, key)
	}
	sort.Slice(encoded.Subjects, func(i, j int) bool {
		return encoded.Subjects[i].Key.CgroupID < encoded.Subjects[j].Key.CgroupID
	})
	sort.Slice(encoded.Nodes, func(i, j int) bool {
		if encoded.Nodes[i].Slot != encoded.Nodes[j].Slot {
			return encoded.Nodes[i].Slot < encoded.Nodes[j].Slot
		}
		return compareIPv4(encoded.Nodes[i].Address, encoded.Nodes[j].Address) < 0
	})
	sort.Slice(encoded.Self, func(i, j int) bool {
		if encoded.Self[i].CgroupID != encoded.Self[j].CgroupID {
			return encoded.Self[i].CgroupID < encoded.Self[j].CgroupID
		}
		return compareIPv4(encoded.Self[i].Address, encoded.Self[j].Address) < 0
	})
	sort.Slice(encoded.Rules, func(i, j int) bool {
		left, right := encoded.Rules[i], encoded.Rules[j]
		if left.Meta != right.Meta {
			return left.Meta < right.Meta
		}
		if left.CgroupID != right.CgroupID {
			return left.CgroupID < right.CgroupID
		}
		if left.PrefixLength != right.PrefixLength {
			return left.PrefixLength < right.PrefixLength
		}
		return compareIPv4(left.Peer, right.Peer) < 0
	})
	return encoded, nil
}

func encodePolicyRuleKey(slot uint32, rule policy.Rule) (policyRuleKey, error) {
	if slot > 1 {
		return policyRuleKey{}, fmt.Errorf("policy slot %d is outside 0..1", slot)
	}
	if !rule.Peer.IsValid() || !rule.Peer.Addr().Is4() {
		return policyRuleKey{}, errorsInvalidPeer(rule.Peer)
	}
	var direction uint32
	switch rule.Direction {
	case policy.DirectionEgress:
		direction = 0
	case policy.DirectionIngress:
		direction = 1
	default:
		return policyRuleKey{}, fmt.Errorf("invalid policy direction %#x", rule.Direction)
	}
	if rule.Protocol != policy.ProtocolTCP && rule.Protocol != policy.ProtocolUDP {
		return policyRuleKey{}, fmt.Errorf("unsupported policy protocol %d", rule.Protocol)
	}
	if rule.Port == 0 {
		return policyRuleKey{}, errors.New("policy port must be non-zero")
	}
	if int(rule.PortWildcardBits) > bits.TrailingZeros16(rule.Port) {
		return policyRuleKey{}, errors.New("policy port block must be aligned at port")
	}

	masked := rule.Peer.Masked()
	address := masked.Addr().As4()
	meta := (slot << 31) | (direction << ruleDirectionShift) | (uint32(rule.PortWildcardBits) << rulePortWildcardShift) |
		(uint32(rule.Protocol) << 16) | uint32(rule.Port)
	return policyRuleKey{
		PrefixLength: uint32(96 + masked.Bits()), // #nosec G115 -- an IPv4 prefix produces a value in the fixed 96..128 range.
		Meta:         meta,
		CgroupID:     rule.CgroupID,
		Peer:         address,
	}, nil
}

func errorsInvalidPeer(prefix netip.Prefix) error {
	return fmt.Errorf("policy peer %q must be an IPv4 prefix", prefix)
}

func compareIPv4(left, right [4]byte) int {
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}
