//go:build !linux

package enforcer

// DefaultAgentStatusPinPath is the expected bpffs pin path for the agent
// status map. Non-Linux builds expose the constant for shared CLI code.
const DefaultAgentStatusPinPath = "/sys/fs/bpf/ztap/agent_status"

// IsEBPFEnforcementActive reports whether eBPF enforcement is active in this process.
func IsEBPFEnforcementActive() bool {
	return false
}
