package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestValidateCommandAcceptsNativePolicyWithoutConfig(t *testing.T) {
	root := NewRootCmd("test")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web
spec:
  podSelector: {}
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 443
`))
	root.SetArgs([]string{"validate", "-f", "-"})

	if err := root.Execute(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if output := root.OutOrStdout().(*bytes.Buffer).String(); !strings.Contains(output, "valid: 1 NetworkPolicy object(s)") || !strings.Contains(output, "default/web") {
		t.Fatalf("output = %q, want validation summary and policy name", output)
	}
}

func TestValidateCommandExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		data string
		want int
	}{
		{
			name: "invalid policy",
			args: []string{"validate", "-f", "-"},
			data: `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: old
spec:
  podSelector: {}
`,
			want: 1,
		},
		{
			name: "missing file",
			args: []string{"validate", "-f", filepath.Join(t.TempDir(), "missing.yaml")},
			want: 2,
		},
		{
			name: "missing file flag",
			args: []string{"validate"},
			want: 2,
		},
		{
			name: "unknown flag",
			args: []string{"validate", "--unknown"},
			want: 2,
		},
		{
			name: "unexpected argument",
			args: []string{"validate", "policy.yaml"},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCmd("test")
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetIn(strings.NewReader(tt.data))
			root.SetArgs(tt.args)
			err := root.Execute()
			if err == nil {
				t.Fatal("expected command error")
			}
			if got := ExitCode(err); got != tt.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", err, got, tt.want)
			}
		})
	}
}

func TestValidateCommandReturnsOutputErrors(t *testing.T) {
	root := NewRootCmd("test")
	root.SetOut(failingWriter{})
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: output-error
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress: []
`))
	root.SetArgs([]string{"validate", "-f", "-"})

	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "write validation result") {
		t.Fatalf("error = %v, want output write error", err)
	}
}

func TestCommandSkipsConfigOnlyForTopLevelCommands(t *testing.T) {
	root := NewRootCmd("test")
	topLevelValidate, _, err := root.Find([]string{"validate"})
	if err != nil {
		t.Fatalf("find top-level validate: %v", err)
	}
	legacyValidate, _, err := root.Find([]string{"policy", "validate"})
	if err != nil {
		t.Fatalf("find legacy policy validate: %v", err)
	}
	if !commandSkipsConfig(topLevelValidate) {
		t.Fatal("top-level validate should skip legacy config")
	}
	if commandSkipsConfig(legacyValidate) {
		t.Fatal("nested policy validate must retain legacy config setup")
	}
}

func TestValidateCommandReadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: from-file
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress: []
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	root := NewRootCmd("test")
	output := &bytes.Buffer{}
	root.SetOut(output)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"validate", "--file", path})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if !strings.Contains(output.String(), "default/from-file") {
		t.Fatalf("output = %q, want file policy name", output.String())
	}
}
