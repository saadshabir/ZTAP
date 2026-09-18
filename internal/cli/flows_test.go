package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFlowsCommandUsesLiveOnlySurface(t *testing.T) {
	command := newFlowsCmd()
	for _, name := range []string{"action", "protocol", "direction", "run-dir", "output"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("missing flows flag --%s", name)
		}
	}
	for _, removed := range []string{"follow", "limit"} {
		if command.Flags().Lookup(removed) != nil {
			t.Errorf("legacy flows flag --%s is still exposed", removed)
		}
	}
	if command.RunE == nil {
		t.Fatal("flows command must return streaming errors through RunE")
	}
}

func TestRunFlowsRejectsUnsupportedFiltersBeforeOpeningReader(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "action", args: []string{"--action", "dropped"}, want: "invalid --action"},
		{name: "protocol", args: []string{"--protocol", "ICMP"}, want: "invalid --protocol"},
		{name: "direction", args: []string{"--direction", "sideways"}, want: "invalid --direction"},
		{name: "output", args: []string{"--output", "yaml"}, want: "invalid --output"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := newFlowsCmd()
			command.SetArgs(test.args)
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("flows error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFlowsCommandRejectsRemovedFlags(t *testing.T) {
	command := newFlowsCmd()
	command.SetArgs([]string{"--follow"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("removed --follow error = %v, want unknown flag", err)
	}
}

func TestFlowsCommandRejectsUnsupportedPlatformBeforeCreatingLock(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux supports live flow streaming")
	}
	runDir := filepath.Join(t.TempDir(), "flows")
	command := newFlowsCmd()
	command.SetArgs([]string{"--run-dir", runDir})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatalf("flows error = %v, want unsupported-platform error", err)
	}
	if _, statErr := os.Stat(runDir); !os.IsNotExist(statErr) {
		t.Fatalf("unsupported flows command created run directory or stat failed: %v", statErr)
	}
}
