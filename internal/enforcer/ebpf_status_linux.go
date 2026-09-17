//go:build linux

package enforcer

// DefaultAgentStatusPinPath is the stable agent-status map pin created by the
// instance-owned Linux engine.
const DefaultAgentStatusPinPath = "/sys/fs/bpf/ztap/agent_status"

// IsEBPFEnforcementActive reports whether eBPF enforcement is active in this process.
func IsEBPFEnforcementActive() bool {
	activeEBPFMu.Lock()
	defer activeEBPFMu.Unlock()
	return activeEBPFEnforcer != nil
}
