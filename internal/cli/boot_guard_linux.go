//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/saadshabir/ZTAP/internal/enforcer"
)

func verifyBootGuardKubelet(ctx context.Context, unit string) error {
	const systemd = "org.freedesktop.systemd1"
	var objects []string
	if err := readSystemdBusJSON(ctx, &objects, "call", systemd, "/org/freedesktop/systemd1", systemd+".Manager", "LoadUnit", "s", unit); err != nil {
		return fmt.Errorf("load kubelet unit %q: %w", unit, err)
	}
	if len(objects) != 1 || objects[0] == "" {
		return fmt.Errorf("systemd did not return an object path for kubelet unit %q", unit)
	}
	var commands [][]json.RawMessage
	if err := readSystemdBusJSON(ctx, &commands, "get-property", systemd, objects[0], systemd+".Service", "ExecStart"); err != nil {
		return fmt.Errorf("read %s ExecStart: %w", unit, err)
	}
	if err := validateBootGuardKubeletExecStart(commands); err != nil {
		return fmt.Errorf("%s ExecStart: %w", unit, err)
	}
	return nil
}

func readSystemdBusJSON(ctx context.Context, dst any, args ...string) error {
	commandArgs := append([]string{"--system", "--json=short", "--timeout=5s", "--"}, args...)
	output, err := exec.CommandContext(ctx, "busctl", commandArgs...).Output() // #nosec G204 -- argv passed directly to systemd's D-Bus client.
	if err != nil {
		return err
	}
	reply := struct {
		Data any `json:"data"`
	}{Data: dst}
	return json.Unmarshal(output, &reply)
}

func validateBootGuardKubeletExecStart(commands [][]json.RawMessage) error {
	// ExecStart contains a tuple per command. The first two fields are the
	// executable path and the argument vector before environment expansion.
	if len(commands) != 1 || len(commands[0]) < 2 {
		return errors.New("require exactly one direct kubelet command")
	}
	var path string
	var args []string
	if err := json.Unmarshal(commands[0][0], &path); err != nil {
		return err
	}
	if err := json.Unmarshal(commands[0][1], &args); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != "kubelet" || len(args) == 0 || args[0] != path {
		return errors.New("require a direct kubelet executable with an absolute path")
	}
	// Kubelet reapplies command-line flags after loading config and drop-ins.
	// Literal trailing flags also take precedence over systemd's expanded args.
	layoutFlags := []string{"--cgroup-driver=systemd", "--cgroups-per-qos=true"}
	if len(args) < 4 || slices.Contains(args, "--") || !slices.Equal(args[len(args)-3:len(args)-1], layoutFlags) {
		return errors.New("append literal --cgroup-driver=systemd --cgroups-per-qos=true --cgroup-root=/ (or --cgroup-root=/kubelet) after all other arguments")
	}
	switch args[len(args)-1] {
	case "--cgroup-root=/", "--cgroup-root=/kubelet":
		return nil
	default:
		return errors.New("the final kubelet argument must be --cgroup-root=/ or --cgroup-root=/kubelet")
	}
}

func installNodeBootGuard(ctx context.Context, cgroupRoot, bpffsRoot, runDir string) (resultErr error) {
	unlock, err := acquireNativeAgentLock(runDir)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	parents, err := kubernetesCgroupParents(cgroupRoot)
	if err != nil {
		return err
	}
	if len(parents) != len(kubernetesParentPaths) {
		return errors.New("boot guard requires both supported Kubernetes systemd slices")
	}
	cookie, err := socketNetnsCookie()
	if err != nil {
		return fmt.Errorf("read host network namespace cookie: %w", err)
	}
	if err := enforcer.InstallBootGuard(ctx, cgroupRoot, bpffsRoot, parents, cookie); err != nil {
		return err
	}
	slog.Info("installed persistent Kubernetes boot guard", "parents", parents)
	return nil
}
