package cli

import (
	"strings"
	"testing"
)

func TestAgentRequiresNodeName(t *testing.T) {
	command := newAgentCmd()
	command.SetArgs(nil)
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--node-name is required") {
		t.Fatalf("agent without node name error = %v, want required node-name error", err)
	}
}

func TestAgentRegistersNativeFlags(t *testing.T) {
	command := newAgentCmd()
	for _, name := range []string{"node-name", "kubeconfig", "cgroup-root", "bpffs-root", "run-dir", "listen", "dry-run"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("agent is missing --%s", name)
		}
	}
	if command.Flags().Lookup("cgroup") != nil {
		t.Fatal("retired --cgroup alias remains exposed")
	}
}

func TestAgentRejectsInvalidRootLogLevelBeforeKubeconfig(t *testing.T) {
	root := NewRootCmd("test")
	root.SetArgs([]string{"agent", "--node-name", "node-a", "--log-level", "invalid", "--kubeconfig", "/nonexistent/kubeconfig"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("agent root logging error = %v, want invalid log level", err)
	}
}
