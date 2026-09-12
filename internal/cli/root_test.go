package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"ztap/internal/config"
)

// expectedTree mirrors the command surface captured as the Phase C baseline
// (see docs/modernization-plan.md, pre-flight 0.2). Any change to command
// names, nesting, or flags here is a user-visible CLI change.
func TestNewRootCmdCommandTree(t *testing.T) {
	root := NewRootCmd("test-version")

	if root.Use != "ztap" {
		t.Errorf("root Use = %q, want %q", root.Use, "ztap")
	}
	if root.Version != "" { // Version is set via the version subcommand, not cobra's field
		t.Errorf("unexpected root.Version = %q", root.Version)
	}

	wantPersistent := []string{"log-level", "log-format", "log-file"}
	for _, f := range wantPersistent {
		if root.PersistentFlags().Lookup(f) == nil {
			t.Errorf("missing persistent flag --%s", f)
		}
	}

	// Top-level commands and their direct children.
	want := map[string][]string{
		"validate":   nil,
		"agent":      nil,
		"alert":      {"test"},
		"api":        {"serve"},
		"audit":      {"view", "verify", "keygen", "stats"},
		"aws":        {"sg-sync", "inventory"},
		"azure":      {"nsg-sync"},
		"cluster":    {"status", "join", "leave", "list", "config", "test-etcd"},
		"compliance": {"export", "report"},
		"discovery":  {"register", "deregister", "resolve", "list"},
		"enforce":    nil,
		"flows":      nil,
		"gcp":        {"firewall-sync"},
		"grpc":       {"serve"},
		"logs":       nil,
		"metrics":    nil,
		"policy":     {"sync", "list", "watch", "show", "history", "rollback", "validate"},
		"status":     nil,
		"user":       {"create", "list", "change-password", "disable", "enable", "login", "logout"},
		"version":    nil,
	}

	got := map[string][]string{}
	for _, c := range root.Commands() {
		got[c.Name()] = nil
	}
	for name, children := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("missing top-level command %q", name)
			continue
		}
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Errorf("root.Find(%q): %v", name, err)
			continue
		}
		var have []string
		for _, cc := range cmd.Commands() {
			have = append(have, cc.Name())
		}
		for _, child := range children {
			if !slicesContains(have, child) {
				t.Errorf("command %q missing subcommand %q (have %v)", name, child, have)
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("root has %d commands, want %d", len(got), len(want))
	}
}

func TestNewRootCmdSetsVersion(t *testing.T) {
	root := NewRootCmd("9.9.9-test")
	root.SetArgs([]string{"version"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root.Execute()
	_ = w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	out, _ := io.ReadAll(r)
	_ = r.Close()
	if !strings.Contains(string(out), "ztap 9.9.9-test") {
		t.Errorf("version output = %q, want it to contain %q", out, "ztap 9.9.9-test")
	}
}

func TestClusterBackendUsesCentralConfig(t *testing.T) {
	initClusterBackend()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Cluster: config.Cluster{
			Backend:     "memory",
			NodeID:      "configured-node",
			NodeAddress: "127.0.0.1:9191",
			Election: config.ClusterElection{
				HeartbeatInterval: config.Duration(10 * time.Millisecond),
			},
		},
	}
	if err := startClusterBackendWithConfig(ctx, cfg, "127.0.0.1:9090"); err != nil {
		t.Fatalf("startClusterBackendWithConfig returned error: %v", err)
	}
	defer stopClusterBackend()

	node := clusterElection.GetNode("configured-node")
	if node == nil {
		t.Fatal("configured node was not registered")
	}
	if node.Address != "127.0.0.1:9191" {
		t.Fatalf("node address = %q, want configured address", node.Address)
	}
}

func TestClusterBackendLifecycle(t *testing.T) {
	initClusterBackend()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startClusterBackend(ctx); err != nil {
		t.Fatalf("startClusterBackend returned error: %v", err)
	}
	defer stopClusterBackend()

	if clusterElection == nil || !clusterElection.IsLeader() {
		t.Fatal("cluster backend did not elect the local node")
	}
}

func TestNewRootCmdPersistentPreRunLogging(t *testing.T) {
	// The PersistentPreRunE must be wired on the root command so logging
	// flags apply to every subcommand (baseline behavior preserved).
	root := NewRootCmd("test")
	if root.PersistentPreRunE == nil {
		t.Fatal("root command has no PersistentPreRunE")
	}
	// Setting a log format flag must not error during pre-run for --help-less
	// invocations; exercise the flag definitions.
	for _, f := range []string{"log-level", "log-format", "log-file"} {
		if root.PersistentFlags().Lookup(f) == nil {
			t.Errorf("persistent flag --%s not registered", f)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
