package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type environmentContext struct {
	Mode            string
	RunID           string
	MigrationRunID  string
	Commit          string
	Ref             string
	WorkflowRunID   string
	WorkflowEvent   string
	WorkflowPath    string
	MigrationBranch string
	Arch            string
}

type cpuMaxObservation struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Value  string `json:"value,omitempty"`
	Error  string `json:"error,omitempty"`
}

type cgroup2Mount struct {
	Root      string
	MountPath string
}

func recordEnvironmentCommand(args []string) error {
	flags := flag.NewFlagSet("record-environment", flag.ContinueOnError)
	output := flags.String("output", "", "output environment evidence file")
	mode := flags.String("mode", "", "workflow mode: preflight or release")
	runID := flags.String("phase5-run-id", "", "Phase 5 evidence run ID")
	migrationRunID := flags.String("migration-ci-run-id", "", "trusted Migration CI run ID")
	commit := flags.String("commit", "", "source commit SHA")
	ref := flags.String("ref", "", "full workflow ref")
	workflowRunID := flags.String("workflow-run-id", "", "current workflow run ID")
	workflowEvent := flags.String("workflow-event", "", "current workflow event")
	workflowPath := flags.String("workflow-path", "", "current workflow path")
	migrationBranch := flags.String("migration-ci-branch", "", "trusted Migration CI branch")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("record-environment does not accept positional arguments")
	}
	if *output == "" {
		return errors.New("--output is required")
	}
	context := environmentContext{
		Mode: *mode, RunID: *runID, MigrationRunID: *migrationRunID, Commit: *commit, Ref: *ref,
		WorkflowRunID: *workflowRunID, WorkflowEvent: *workflowEvent, WorkflowPath: *workflowPath,
		MigrationBranch: *migrationBranch,
	}
	values, captureErrors := captureEnvironment(context)
	encodedErrors, err := json.Marshal(captureErrors)
	if err != nil {
		return fmt.Errorf("encode capture errors: %w", err)
	}
	values["capture_errors_json"] = string(encodedErrors)
	if err := writeEnvironmentFile(*output, values); err != nil {
		return fmt.Errorf("write environment evidence: %w", err)
	}
	if err := verifyEnvironmentFileForContext(*output, context); err != nil {
		return fmt.Errorf("recorded environment in %s, but it does not satisfy the reference profile: %w", *output, err)
	}
	return nil
}

func captureEnvironment(context environmentContext) (map[string]string, []string) {
	values := map[string]string{
		"environment_schema":     "2",
		"environment_mode":       context.Mode,
		"timestamp_utc":          time.Now().UTC().Format(time.RFC3339Nano),
		"phase5_run_id":          context.RunID,
		"migration_ci_run_id":    context.MigrationRunID,
		"commit":                 context.Commit,
		"ref":                    context.Ref,
		"workflow_run_id":        context.WorkflowRunID,
		"workflow_event":         context.WorkflowEvent,
		"workflow_path":          context.WorkflowPath,
		"migration_ci_workflow":  ".github/workflows/migration-ci.yml",
		"migration_ci_event":     "push",
		"migration_ci_branch":    context.MigrationBranch,
		"reference_cpu_set":      "unavailable",
		"reference_gomaxprocs":   strconv.Itoa(runtimeGOMAXPROCS()),
		"cpu_max_status":         "unavailable",
		"cpu_max_path":           "unavailable",
		"cpu_max":                "unavailable",
		"cpu_max_hierarchy_json": "[]",
	}
	var captureErrors []string

	commands := []struct {
		key  string
		args []string
	}{
		{key: "go_version", args: []string{"go", "version"}},
		{key: "goos", args: []string{"go", "env", "GOOS"}},
		{key: "goarch", args: []string{"go", "env", "GOARCH"}},
		{key: "nproc", args: []string{"nproc"}},
		{key: "getconf_clk_tck", args: []string{"getconf", "CLK_TCK"}},
		{key: "uname", args: []string{"uname", "-a"}},
		{key: "cgroup2", args: []string{"stat", "-fc", "%T", "/sys/fs/cgroup"}},
		{key: "bpffs", args: []string{"stat", "-fc", "%T", "/sys/fs/bpf"}},
	}
	for _, command := range commands {
		value, err := environmentCommand(command.args[0], command.args[1:]...)
		if err != nil {
			values[command.key] = "unavailable"
			captureErrors = append(captureErrors, fmt.Sprintf("%s: %v", strings.Join(command.args, " "), err))
		} else {
			values[command.key] = value
		}
	}
	values["allowed_cpu_list"] = readAllowedCPUList(&captureErrors)
	values["reference_nproc"] = "unavailable"
	if value, err := environmentCommand("taskset", "--cpu-list", "0,1", "nproc"); err != nil {
		captureErrors = append(captureErrors, fmt.Sprintf("taskset --cpu-list 0,1 nproc: %v", err))
	} else {
		values["reference_nproc"] = value
		values["reference_cpu_set"] = "0,1"
	}

	mount, membershipPath, processCgroup, err := discoverCgroup2()
	if err != nil {
		captureErrors = append(captureErrors, "discover cgroup v2 provenance: "+err.Error())
		values["cgroup_mount_root"] = "unavailable"
		values["cgroup_mount_point"] = "unavailable"
		values["cgroup_membership_path"] = "unavailable"
		values["cgroup_process_path"] = "unavailable"
	} else {
		values["cgroup_mount_root"] = mount.Root
		values["cgroup_mount_point"] = mount.MountPath
		values["cgroup_membership_path"] = membershipPath
		values["cgroup_process_path"] = processCgroup
		observations, walkErr := observeCPUQuotaHierarchy(mount.MountPath, processCgroup)
		if walkErr != nil {
			captureErrors = append(captureErrors, "read cgroup CPU quota hierarchy: "+walkErr.Error())
		}
		encoded, encodeErr := json.Marshal(observations)
		if encodeErr != nil {
			captureErrors = append(captureErrors, "encode cgroup CPU quota hierarchy: "+encodeErr.Error())
		} else {
			values["cpu_max_hierarchy_json"] = string(encoded)
		}
		if selected, ok := limitingCPUQuota(observations); ok {
			values["cpu_max_status"] = "recorded"
			values["cpu_max_path"] = path.Join(selected.Path, "cpu.max")
			values["cpu_max"] = selected.Value
		}
	}
	return values, captureErrors
}

func runtimeGOMAXPROCS() int {
	return runtime.GOMAXPROCS(0)
}

func environmentCommand(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	value := strings.Join(strings.Fields(string(output)), " ")
	if err != nil {
		return value, fmt.Errorf("%w: %s", err, value)
	}
	return value, nil
}

func readAllowedCPUList(captureErrors *[]string) string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		*captureErrors = append(*captureErrors, "read /proc/self/status: "+err.Error())
		return "unavailable"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Cpus_allowed_list:"))
		}
	}
	*captureErrors = append(*captureErrors, "/proc/self/status has no Cpus_allowed_list field")
	return "unavailable"
}

func discoverCgroup2() (cgroup2Mount, string, string, error) {
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return cgroup2Mount{}, "", "", fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	mount, err := findCgroup2Mount(mountInfo)
	if err != nil {
		return cgroup2Mount{}, "", "", err
	}
	cgroupFile, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return cgroup2Mount{}, "", "", fmt.Errorf("read /proc/self/cgroup: %w", err)
	}
	membershipPath, err := unifiedCgroupPath(cgroupFile)
	if err != nil {
		return cgroup2Mount{}, "", "", err
	}
	filesystemPath, err := mapCgroupPathToMount(membershipPath, mount.Root, mount.MountPath)
	if err != nil {
		return cgroup2Mount{}, "", "", err
	}
	return mount, membershipPath, filesystemPath, nil
}

func findCgroup2Mount(mountInfo []byte) (cgroup2Mount, error) {
	var selected cgroup2Mount
	for _, line := range strings.Split(string(mountInfo), "\n") {
		before, after, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		preFields := strings.Fields(before)
		postFields := strings.Fields(after)
		if len(preFields) < 5 || len(postFields) == 0 || postFields[0] != "cgroup2" {
			continue
		}
		candidate := cgroup2Mount{Root: unescapeMountInfo(preFields[3]), MountPath: unescapeMountInfo(preFields[4])}
		if candidate.MountPath == "/sys/fs/cgroup" {
			return candidate, nil
		}
		if len(candidate.MountPath) > len(selected.MountPath) {
			selected = candidate
		}
	}
	if selected.MountPath == "" {
		return cgroup2Mount{}, errors.New("no cgroup2 mount is present in /proc/self/mountinfo")
	}
	return cgroup2Mount{}, fmt.Errorf("cgroup2 mount point is %q, expected /sys/fs/cgroup", selected.MountPath)
}

func unescapeMountInfo(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}

func unifiedCgroupPath(cgroupFile []byte) (string, error) {
	for _, line := range strings.Split(string(cgroupFile), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 && fields[0] == "0" && fields[1] == "" {
			if !strings.HasPrefix(fields[2], "/") || path.Clean(fields[2]) != fields[2] {
				return "", fmt.Errorf("unified cgroup path %q is not a clean absolute path", fields[2])
			}
			return fields[2], nil
		}
	}
	return "", errors.New("/proc/self/cgroup has no unified 0:: membership")
}

func mapCgroupPathToMount(cgroupPath, mountRoot, mountPoint string) (string, error) {
	if !path.IsAbs(cgroupPath) || path.Clean(cgroupPath) != cgroupPath || !path.IsAbs(mountRoot) || path.Clean(mountRoot) != mountRoot || !path.IsAbs(mountPoint) || path.Clean(mountPoint) != mountPoint {
		return "", errors.New("cgroup membership and mount paths must be clean absolute paths")
	}
	relative := cgroupPath
	if mountRoot != "/" {
		switch {
		case cgroupPath == mountRoot:
			relative = "/"
		case strings.HasPrefix(cgroupPath, mountRoot+"/"):
			relative = strings.TrimPrefix(cgroupPath, mountRoot)
		default:
			// A cgroup namespace can present membership paths relative to the
			// namespace root while mountinfo reports the host-side mount root.
			relative = cgroupPath
		}
	}
	mapped := path.Clean(path.Join(mountPoint, strings.TrimPrefix(relative, "/")))
	if !pathWithin(mountPoint, mapped) {
		return "", fmt.Errorf("cgroup membership %q escapes mount point %q", cgroupPath, mountPoint)
	}
	return mapped, nil
}

func observeCPUQuotaHierarchy(mountPoint, processPath string) ([]cpuMaxObservation, error) {
	mountPoint = path.Clean(mountPoint)
	processPath = path.Clean(processPath)
	if !path.IsAbs(mountPoint) || !path.IsAbs(processPath) || !pathWithin(mountPoint, processPath) {
		return nil, errors.New("process cgroup path is outside its cgroup2 mount point")
	}
	for _, directory := range []string{mountPoint, processPath} {
		info, err := os.Stat(directory)
		if err != nil {
			return nil, fmt.Errorf("stat cgroup directory %q: %w", directory, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("cgroup path %q is not a directory", directory)
		}
	}
	observations := make([]cpuMaxObservation, 0, 8)
	current := processPath
	for depth := 0; depth < 256; depth++ {
		observation := cpuMaxObservation{Path: current, Status: "missing"}
		contents, err := os.ReadFile(path.Join(current, "cpu.max"))
		switch {
		case err == nil:
			observation.Status = "recorded"
			observation.Value = strings.TrimSpace(string(contents))
		case errors.Is(err, os.ErrNotExist):
			// Missing at this level means no quota file is exposed for this group.
		case err != nil:
			observation.Status = "unreadable"
			observation.Error = err.Error()
		}
		observations = append(observations, observation)
		if current == mountPoint {
			return observations, nil
		}
		parent := path.Dir(current)
		if parent == current || !pathWithin(mountPoint, parent) {
			return observations, fmt.Errorf("cgroup hierarchy from %q did not reach mount point %q", processPath, mountPoint)
		}
		current = parent
	}
	return observations, errors.New("cgroup CPU quota hierarchy exceeds 256 levels")
}

func limitingCPUQuota(observations []cpuMaxObservation) (cpuMaxObservation, bool) {
	var selected cpuMaxObservation
	selectedFinite := false
	for _, observation := range observations {
		if observation.Status != "recorded" || validateCPUQuota(observation.Value) != nil {
			continue
		}
		fields := strings.Fields(observation.Value)
		if fields[0] == "max" {
			if selected.Path == "" {
				selected = observation
			}
			continue
		}
		if !selectedFinite || compareCPUQuota(fields, strings.Fields(selected.Value)) < 0 {
			selected = observation
			selectedFinite = true
		}
	}
	return selected, selected.Path != ""
}

func compareCPUQuota(left, right []string) int {
	leftQuota, _ := new(big.Int).SetString(left[0], 10)
	leftPeriod, _ := new(big.Int).SetString(left[1], 10)
	rightQuota, _ := new(big.Int).SetString(right[0], 10)
	rightPeriod, _ := new(big.Int).SetString(right[1], 10)
	leftScaled := new(big.Int).Mul(leftQuota, rightPeriod)
	rightScaled := new(big.Int).Mul(rightQuota, leftPeriod)
	return leftScaled.Cmp(rightScaled)
}

func pathWithin(root, candidate string) bool {
	root = path.Clean(root)
	candidate = path.Clean(candidate)
	return candidate == root || strings.HasPrefix(candidate, strings.TrimSuffix(root, "/")+"/")
}

func verifyCPUQuotaProvenance(values map[string]string) error {
	if values["cpu_max_status"] != "recorded" {
		return fmt.Errorf("cpu_max_status is %q; no readable cpu.max provenance was recorded", values["cpu_max_status"])
	}
	mountPoint := values["cgroup_mount_point"]
	mountRoot := values["cgroup_mount_root"]
	processPath := values["cgroup_process_path"]
	if mountPoint != "/sys/fs/cgroup" || !path.IsAbs(mountRoot) || path.Clean(mountRoot) != mountRoot || mountRoot != "/" {
		return fmt.Errorf("cgroup2 mount provenance is incomplete: root=%q mount_point=%q", mountRoot, mountPoint)
	}
	if !path.IsAbs(processPath) || path.Clean(processPath) != processPath {
		return fmt.Errorf("cgroup_process_path %q is not a clean absolute path", processPath)
	}
	expectedStart, err := mapCgroupPathToMount(values["cgroup_membership_path"], mountRoot, mountPoint)
	if err != nil {
		return err
	}
	if expectedStart != processPath {
		return fmt.Errorf("cgroup_process_path %q does not match mapped membership path %q", processPath, expectedStart)
	}
	var observations []cpuMaxObservation
	if err := json.Unmarshal([]byte(values["cpu_max_hierarchy_json"]), &observations); err != nil {
		return fmt.Errorf("cpu_max_hierarchy_json is invalid: %w", err)
	}
	if len(observations) == 0 || observations[0].Path != expectedStart || observations[len(observations)-1].Path != mountPoint {
		return errors.New("cpu.max observations do not cover the process cgroup through the cgroup mount root")
	}
	for i, observation := range observations {
		if !pathWithin(mountPoint, observation.Path) || path.Clean(observation.Path) != observation.Path {
			return fmt.Errorf("cpu.max observation path %q escapes or is not normalized under %q", observation.Path, mountPoint)
		}
		if i > 0 && path.Dir(observations[i-1].Path) != observation.Path {
			return errors.New("cpu.max observations are not in process-to-mount-root order")
		}
		switch observation.Status {
		case "missing":
			if observation.Value != "" || observation.Error != "" {
				return fmt.Errorf("missing cpu.max observation at %q contains a value or error", observation.Path)
			}
		case "recorded":
			if err := validateCPUQuota(observation.Value); err != nil {
				return fmt.Errorf("cpu.max at %q: %w", observation.Path, err)
			}
		case "unreadable":
			return fmt.Errorf("cpu.max at %q could not be read: %s", observation.Path, observation.Error)
		default:
			return fmt.Errorf("cpu.max at %q has unknown observation status %q", observation.Path, observation.Status)
		}
	}
	selected, ok := limitingCPUQuota(observations)
	if !ok {
		return errors.New("no cpu.max value is visible from the process cgroup through the mount root")
	}
	selectedFile := path.Join(selected.Path, "cpu.max")
	if values["cpu_max_path"] != selectedFile || values["cpu_max"] != selected.Value {
		return fmt.Errorf("selected cpu.max provenance %q=%q does not match the most restrictive observed value %q=%q", values["cpu_max_path"], values["cpu_max"], selectedFile, selected.Value)
	}
	fields := strings.Fields(selected.Value)
	if fields[0] != "max" {
		quota, _ := new(big.Int).SetString(fields[0], 10)
		period, _ := new(big.Int).SetString(fields[1], 10)
		if quota.Cmp(new(big.Int).Mul(big.NewInt(2), period)) < 0 {
			return fmt.Errorf("effective cpu.max quota %q at %q is below the two-CPU reference profile", selected.Value, selected.Path)
		}
	}
	return nil
}

func writeEnvironmentFile(filename string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if strings.ContainsAny(values[key], "\r\n") {
			_ = file.Close()
			return fmt.Errorf("environment value %q contains a line break", key)
		}
		if _, err := fmt.Fprintf(file, "%s=%s\n", key, values[key]); err != nil {
			_ = file.Close()
			return err
		}
	}
	return file.Close()
}
