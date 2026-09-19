package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRootCmdCommandSurface(t *testing.T) {
	root := NewRootCmd("test-version")
	want := []string{"agent", "flows", "validate", "version"}
	var visible []string
	for _, command := range root.Commands() {
		if !command.Hidden {
			visible = append(visible, command.Name())
		}
	}
	if strings.Join(visible, ",") != strings.Join(want, ",") {
		t.Fatalf("visible root commands = %v, want %v", visible, want)
	}
	for _, name := range want {
		if _, _, err := root.Find([]string{name}); err != nil {
			t.Errorf("missing command %q: %v", name, err)
		}
	}
	for _, name := range []string{"log-level", "log-format"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing persistent flag --%s", name)
		}
	}
	if root.PersistentFlags().Lookup("log-file") != nil {
		t.Fatal("retired --log-file flag remains exposed")
	}
	command, _, err := root.Find([]string{"help"})
	if err != nil {
		t.Errorf("missing help command: %v", err)
	} else if command.Name() != "help" {
		t.Errorf("help command name = %q, want help", command.Name())
	} else if !command.Hidden {
		t.Error("help command is visible in the primary command list")
	}
}

func TestRootSupportCommandsRemainCallable(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "help", args: []string{"help", "agent"}, want: "Run ZTAP node agent"},
		{name: "completion", args: []string{"completion", "bash"}, want: "bash completion V2 for ztap"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := NewRootCmd("test-version")
			output := &bytes.Buffer{}
			root.SetOut(output)
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(test.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("%s failed: %v", test.name, err)
			}
			if !strings.Contains(output.String(), test.want) {
				t.Fatalf("%s output missing %q", test.name, test.want)
			}
			command, _, err := root.Find(test.args[:1])
			if err != nil || !command.Hidden {
				t.Fatalf("%s support command is unavailable or visible: %v", test.name, err)
			}
		})
	}
}

func TestRootHelpListsOnlyPrimaryCommands(t *testing.T) {
	root := NewRootCmd("test-version")
	output := &bytes.Buffer{}
	root.SetOut(output)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("root help failed: %v", err)
	}
	parts := strings.SplitN(output.String(), "Available Commands:\n", 2)
	if len(parts) != 2 {
		t.Fatalf("root help has no available commands section: %q", output.String())
	}
	commands := strings.SplitN(parts[1], "\n\n", 2)[0]
	for _, line := range []string{"  agent ", "  flows ", "  validate ", "  version "} {
		if !strings.Contains(commands, line) {
			t.Errorf("root help missing %q", line)
		}
	}
	for _, line := range []string{"  help ", "  completion ", "  __help "} {
		if strings.Contains(commands, line) {
			t.Errorf("root help exposes support command %q", line)
		}
	}
}

func TestVersionCommandUsesStableRecord(t *testing.T) {
	SetBuildInfo("9.9.9-test", "abc123", "2026-09-18T00:00:00Z")
	t.Cleanup(func() { SetBuildInfo("dev", "unknown", "unknown") })
	root := NewRootCmd("9.9.9-test")
	output := &bytes.Buffer{}
	root.SetOut(output)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	line := strings.TrimSpace(output.String())
	for _, field := range []string{"version=9.9.9-test", "commit=abc123", "build_date=2026-09-18T00:00:00Z", "go=", "os=", "arch="} {
		if !strings.Contains(line, field) {
			t.Errorf("version output = %q, missing %q", line, field)
		}
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("version output has more than one record: %q", line)
	}
}

func TestConfigureLoggingRejectsInvalidOptions(t *testing.T) {
	root := NewRootCmd("test")
	root.SetArgs([]string{"version", "--log-level", "invalid"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("configureLogging error = %v, want invalid log level", err)
	}
}
