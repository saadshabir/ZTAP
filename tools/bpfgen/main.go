// Command bpfgen generates the eBPF Go bindings for internal/enforcer without
// committing binary artifacts: it runs bpf2go to compile the retained BPF
// programs and then inlines the resulting object bytes into generated Go
// sources, so the repository contains no *.o files (see Scorecard
// Binary-Artifacts).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	targets = "bpfel,bpfeb"
)

type programSource struct {
	stem   string
	source string
}

var programSources = []programSource{{stem: "engine", source: "../../bpf/engine.c"}}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bpfgen:", err)
		os.Exit(1)
	}
}

func run() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	pkgDir := filepath.Join(repoRoot, "internal", "enforcer")

	for _, source := range programSources {
		args := []string{
			"run", "github.com/cilium/ebpf/cmd/bpf2go",
			"-no-strip",
			"-target", targets,
			source.stem, source.source,
			"--", "-I../../bpf",
		}
		// The command and all arguments are generated from the checked-in source
		// list above; no user-controlled input reaches this generator.
		cmd := exec.Command("go", args...) // #nosec G204 -- arguments are fixed generator inputs
		cmd.Dir = pkgDir
		cmd.Env = append(hostEnv(), "GOPACKAGE=enforcer")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("bpf2go %s: %w", source.stem, err)
		}

		for _, variant := range []string{"bpfel", "bpfeb"} {
			objectFile := filepath.Join(pkgDir, source.stem+"_"+variant+".o")
			goFile := filepath.Join(pkgDir, source.stem+"_"+variant+".go")
			bytesVar := "_" + capitalize(source.stem) + "Bytes"
			if err := inlineObject(goFile, objectFile, bytesVar); err != nil {
				return err
			}
			if err := os.Remove(objectFile); err != nil {
				return fmt.Errorf("remove %s: %w", objectFile, err)
			}
		}
	}
	return nil
}

// inlineObject replaces the go:embed directive in the bpf2go-generated file
// with an inline byte literal so no binary artifact is committed.
func inlineObject(goFile, objectFile, bytesVar string) error {
	data, err := os.ReadFile(objectFile) // #nosec G304 -- objectFile is constructed from the checked-in source name and generator output directory.
	if err != nil {
		return fmt.Errorf("read %s: %w", objectFile, err)
	}
	content, err := os.ReadFile(goFile) // #nosec G304 -- goFile is constructed from the checked-in source name and generator output directory.
	if err != nil {
		return fmt.Errorf("read %s: %w", goFile, err)
	}

	embedName := filepath.Base(objectFile)
	old := fmt.Sprintf("// Do not access this directly.\n//\n//go:embed %s\nvar %s []byte\n", embedName, bytesVar)
	if !strings.Contains(string(content), old) {
		return fmt.Errorf("unexpected generated layout in %s (embed block not found)", goFile)
	}

	const bytesPerLine = 16

	var b strings.Builder
	b.WriteString("// Do not access this directly.\n")
	b.WriteString("//\n")
	fmt.Fprintf(&b, "// %s holds the eBPF object inlined by tools/bpfgen so the\n", bytesVar)
	b.WriteString("// repository contains no binary artifacts; regenerate with\n")
	b.WriteString("// `go generate ./internal/enforcer/...`.\n")
	fmt.Fprintf(&b, "var %s = []byte(\n", bytesVar)
	line := ""
	chunk := 0
	for i := 0; i < len(data); i++ {
		line += fmt.Sprintf("\\x%02x", data[i])
		if (i+1)%bytesPerLine == 0 {
			b.WriteString(indentFor(chunk) + "\"" + line + "\" +\n")
			line = ""
			chunk++
		}
	}
	if line != "" {
		b.WriteString(indentFor(chunk) + "\"" + line + "\" +\n")
	}
	b.WriteString("\t\t\"\",\n)\n")

	out := strings.Replace(string(content), old, b.String(), 1)
	// Generated bindings are source files and must remain readable by the
	// repository tooling; never recreate them with owner-only permissions.
	return os.WriteFile(goFile, []byte(out), 0o644) // #nosec G306 -- generated source is intentionally repository-readable
}

func capitalize(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

// indentFor returns the gofmt-compatible indentation for a string-literal
// chunk: the first line is indented one tab, continuation lines two tabs.
func indentFor(chunk int) string {
	if chunk == 0 {
		return "\t"
	}
	return "\t\t"
}

// hostEnv returns the current environment with GOOS/GOARCH/CGO_ENABLED
// stripped so the spawned bpf2go always builds natively (go generate may be
// invoked with GOOS=linux from another development host).
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if key == "GOOS" || key == "GOARCH" || key == "CGO_ENABLED" {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", cwd)
		}
		dir = parent
	}
}
