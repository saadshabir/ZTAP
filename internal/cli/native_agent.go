package cli

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
}
