package cli

import "net"

// NativeAgentOptions describes the node-local resources owned by the
// Kubernetes agent, including its unauthenticated health and metrics listener.
type NativeAgentOptions struct {
	NodeName   string
	Kubeconfig string
	CgroupRoot string
	BPFFSRoot  string
	RunDir     string
	Listen     string
	DryRun     bool

	// StatusListener is used by the Linux integration harness to transfer an
	// already-bound listener into the agent without reopening its address.
	StatusListener net.Listener
}
