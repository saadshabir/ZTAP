package cli

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRequiresNodeName(t *testing.T) {
	command := newAgentCmd(&App{})
	command.SetArgs(nil)
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--node-name is required") {
		t.Fatalf("agent without node name error = %v, want required node-name error", err)
	}
}

func TestAgentRegistersNativeFlags(t *testing.T) {
	command := newAgentCmd(&App{})
	for _, name := range []string{"node-name", "kubeconfig", "cgroup-root", "cgroup", "bpffs-root", "run-dir", "listen", "dry-run"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("agent is missing --%s", name)
		}
	}
}

func TestConfigureNativeAgentLoggingDefaultsToJSONStderr(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	logger, err := configureNativeAgentLogging(newAgentCmd(&App{}))
	if err != nil {
		t.Fatalf("configure default agent logging: %v", err)
	}
	if logger.Output() != os.Stderr {
		t.Fatalf("default agent log output = %v, want stderr", logger.Output())
	}
	var output strings.Builder
	logger.SetOutput(&output)
	slog.Info("native agent test message")
	if got := output.String(); !strings.Contains(got, `"level":"info"`) || !strings.Contains(got, `"message":"native agent test message"`) {
		t.Fatalf("default agent log output = %q, want JSON info message", got)
	}
}

func TestConfigureNativeAgentLoggingHonorsFlags(t *testing.T) {
	previous := slog.Default()
	command := newAgentCmd(&App{})
	command.Flags().String("log-level", "", "")
	command.Flags().String("log-format", "", "")
	command.Flags().String("log-file", "", "")
	logPath := filepath.Join(t.TempDir(), "agent.log")
	for name, value := range map[string]string{
		"log-level":  "warn",
		"log-format": "text",
		"log-file":   logPath,
	} {
		if err := command.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	logger, err := configureNativeAgentLogging(command)
	if err != nil {
		t.Fatalf("configure flagged agent logging: %v", err)
	}
	file, ok := logger.Output().(*os.File)
	if !ok {
		t.Fatalf("flagged agent log output = %T, want file", logger.Output())
	}
	t.Cleanup(func() {
		slog.SetDefault(previous)
		_ = file.Close()
	})
	slog.Info("filtered agent message")
	slog.Warn("retained agent message")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read agent log file: %v", err)
	}
	if got := string(data); strings.Contains(got, "filtered agent message") || !strings.Contains(got, "[WARN] retained agent message") {
		t.Fatalf("flagged agent log output = %q, want only text warning", got)
	}
}

func TestAgentRejectsInvalidRootLogLevelBeforeKubeconfig(t *testing.T) {
	root := NewRootCmd("test")
	root.SetArgs([]string{"agent", "--node-name", "node-a", "--log-level", "invalid", "--kubeconfig", "/nonexistent/kubeconfig"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("agent root logging error = %v, want invalid log level", err)
	}
}
