//go:build linux

package enforcer

import (
	"net"
	"os"
	"strings"

	"ztap/internal/logging"
	"ztap/internal/policy"

	"github.com/cilium/ebpf"
)

var activeIptablesEnforcer *IptablesEnforcer

func ebpfPolicyMapLPMModes(bpfObjectPath string) (v4 bool, v6 bool) {
	objectOverride := strings.TrimSpace(bpfObjectPath)
	if objectOverride == "" {
		objectOverride = strings.TrimSpace(os.Getenv("ZTAP_BPF_OBJECT"))
	}

	var (
		spec *ebpf.CollectionSpec
		err  error
	)
	if objectOverride != "" {
		spec, err = ebpf.LoadCollectionSpec(objectOverride)
	} else {
		spec, err = loadBpf()
	}
	if err != nil {
		return false, false
	}
	if ms, ok := spec.Maps["policy_map"]; ok && ms != nil && ms.Type == ebpf.LPMTrie {
		v4 = true
	}
	if ms, ok := spec.Maps["policy_map_v6"]; ok && ms != nil && ms.Type == ebpf.LPMTrie {
		v6 = true
	}
	return v4, v6
}

func policiesSupportedByEBPF(policies []policy.NetworkPolicy, bpfObjectPath string) bool {
	v4LPM, v6LPM := ebpfPolicyMapLPMModes(bpfObjectPath)

	// Until the embedded (or overridden) eBPF program supports CIDR LPM,
	// restrict to host CIDRs only.
	for _, p := range policies {
		for _, egress := range p.Spec.Egress {
			for _, port := range egress.Ports {
				if port.PortName != "" || port.EndPort != nil {
					return false
				}
			}
			cidr := egress.To.IPBlock.CIDR
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return false
			}
			ones, bits := ipnet.Mask.Size()
			switch bits {
			case 32:
				if !v4LPM && ones != 32 {
					return false
				}
			case 128:
				if !v6LPM && ones != 128 {
					return false
				}
			default:
				return false
			}
		}
		for _, ingress := range p.Spec.Ingress {
			for _, port := range ingress.Ports {
				if port.PortName != "" || port.EndPort != nil {
					return false
				}
			}
			cidr := ingress.From.IPBlock.CIDR
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return false
			}
			ones, bits := ipnet.Mask.Size()
			switch bits {
			case 32:
				if !v4LPM && ones != 32 {
					return false
				}
			case 128:
				if !v6LPM && ones != 128 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

// EnforceWithEBPFIfAvailable is retained as a migration symbol for older
// integrations. Linux policy ownership now belongs to the node-local native
// agent and this global/fallback entry point must never mutate kernel state.
func EnforceWithEBPFIfAvailable(_ EnforcementOptions) error {
	return ErrLegacyLinuxEnforcementRetired
}

// EnforceWithEBPFIfAvailableScoped is retained as a migration symbol for
// callers that used the old tenant-aware API. Linux policy ownership now
// belongs to the node-local native agent.
func EnforceWithEBPFIfAvailableScoped(_ ScopedEnforcementOptions) error {
	return ErrLegacyLinuxEnforcementRetired
}

// StopLinuxEnforcement stops whichever linux enforcer is currently active.
func StopLinuxEnforcement() error {
	if activeIptablesEnforcer != nil {
		err := activeIptablesEnforcer.Cleanup()
		activeIptablesEnforcer = nil
		return err
	}
	return StopEBPFEnforcement()
}

// CanUseEBPF returns true if the current environment supports eBPF enforcement.
func CanUseEBPF() bool {
	if os.Getenv("ZTAP_FORCE_IPTABLES") == "1" {
		logging.Warn("ZTAP_FORCE_IPTABLES is set, forcing iptables fallback", nil)
		return false
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return false
	}

	return true
}
