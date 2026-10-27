package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func readEnvironmentValues(path string) (values map[string]string, err error) {
	file, err := openRegularFile(path, "environment evidence")
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxEnvironmentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEnvironmentBytes {
		return nil, fmt.Errorf("%s exceeds the 1 MiB environment evidence limit", path)
	}

	values = make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("line %d is not a key=value record", lineNumber)
		}
		if _, known := phase5EnvironmentKeys[key]; !known {
			return nil, fmt.Errorf("line %d has unknown key %q", lineNumber, key)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("line %d repeats key %q", lineNumber, key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

func verifyEnvironmentFileForContext(path string, expected environmentContext) error {
	values, err := readEnvironmentValues(path)
	if err != nil {
		return err
	}
	required := []string{
		"environment_schema",
		"environment_mode",
		"timestamp_utc",
		"phase5_run_id",
		"migration_ci_run_id",
		"commit",
		"ref",
		"workflow_run_id",
		"workflow_event",
		"workflow_path",
		"migration_ci_workflow",
		"migration_ci_event",
		"migration_ci_branch",
		"go_version",
		"goos",
		"goarch",
		"nproc",
		"allowed_cpu_list",
		"reference_cpu_set",
		"reference_nproc",
		"reference_gomaxprocs",
		"cgroup2",
		"bpffs",
		"getconf_clk_tck",
		"uname",
		"cpu_max",
		"cpu_max_status",
		"cpu_max_path",
		"cpu_max_hierarchy_json",
		"cgroup_mount_root",
		"cgroup_mount_point",
		"cgroup_membership_path",
		"cgroup_process_path",
		"capture_errors_json",
	}
	for _, key := range required {
		if strings.TrimSpace(values[key]) == "" {
			return fmt.Errorf("missing %q", key)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, values["timestamp_utc"]); err != nil {
		return fmt.Errorf("timestamp_utc %q is not RFC3339: %v", values["timestamp_utc"], err)
	}
	if values["environment_schema"] != "2" {
		return fmt.Errorf("environment_schema %q is unsupported", values["environment_schema"])
	}
	if values["environment_mode"] != "preflight" {
		return fmt.Errorf("environment_mode %q is unsupported", values["environment_mode"])
	}
	if expected.RunID != "" && values["phase5_run_id"] != expected.RunID {
		return fmt.Errorf("phase5_run_id %q does not match expected %q", values["phase5_run_id"], expected.RunID)
	}
	if expected.MigrationRunID != "" && values["migration_ci_run_id"] != expected.MigrationRunID {
		return fmt.Errorf("migration_ci_run_id %q does not match expected %q", values["migration_ci_run_id"], expected.MigrationRunID)
	}
	migrationRunID, err := strconv.ParseUint(values["migration_ci_run_id"], 10, 64)
	if err != nil || migrationRunID == 0 {
		return fmt.Errorf("migration_ci_run_id %q is not a positive integer", values["migration_ci_run_id"])
	}
	if expected.Commit != "" && values["commit"] != expected.Commit {
		return fmt.Errorf("commit %q does not match expected %q", values["commit"], expected.Commit)
	}
	if !validCommit(values["commit"]) {
		return fmt.Errorf("commit %q is not a full hexadecimal commit ID", values["commit"])
	}
	if expected.Ref != "" && values["ref"] != expected.Ref {
		return fmt.Errorf("ref %q does not match expected %q", values["ref"], expected.Ref)
	}
	workflowRunID, err := strconv.ParseUint(values["workflow_run_id"], 10, 64)
	if err != nil || workflowRunID == 0 {
		return fmt.Errorf("workflow_run_id %q is not a positive integer", values["workflow_run_id"])
	}
	if expected.WorkflowRunID != "" && values["workflow_run_id"] != expected.WorkflowRunID {
		return fmt.Errorf("workflow_run_id %q does not match expected %q", values["workflow_run_id"], expected.WorkflowRunID)
	}
	if expected.WorkflowEvent != "" && values["workflow_event"] != expected.WorkflowEvent {
		return fmt.Errorf("workflow_event %q does not match expected %q", values["workflow_event"], expected.WorkflowEvent)
	}
	if expected.WorkflowPath != "" && values["workflow_path"] != expected.WorkflowPath {
		return fmt.Errorf("workflow_path %q does not match expected %q", values["workflow_path"], expected.WorkflowPath)
	}
	if expected.MigrationBranch != "" && values["migration_ci_branch"] != expected.MigrationBranch {
		return fmt.Errorf("migration_ci_branch %q does not match expected %q", values["migration_ci_branch"], expected.MigrationBranch)
	}
	if expected.Arch != "" && values["goarch"] != expected.Arch {
		return fmt.Errorf("goarch %q does not match expected %q", values["goarch"], expected.Arch)
	}
	if values["migration_ci_workflow"] != ".github/workflows/migration-ci.yml" || values["migration_ci_event"] != "push" {
		return errors.New("trusted Migration CI provenance is not a workflow push")
	}
	if values["workflow_path"] != ".github/workflows/migration-ci.yml" || values["workflow_event"] != "workflow_dispatch" {
		return errors.New("measurement provenance is not a Migration CI workflow dispatch")
	}
	if !validWorkflowRef(values["ref"], values["migration_ci_branch"]) {
		return fmt.Errorf("ref %q and migration_ci_branch %q are inconsistent", values["ref"], values["migration_ci_branch"])
	}
	var captureErrors []string
	if err := json.Unmarshal([]byte(values["capture_errors_json"]), &captureErrors); err != nil {
		return fmt.Errorf("capture_errors_json is invalid JSON: %w", err)
	}
	if len(captureErrors) != 0 {
		return fmt.Errorf("environment capture reported errors: %s", strings.Join(captureErrors, "; "))
	}
	if values["goos"] != "linux" || values["goarch"] != "amd64" || values["reference_cpu_set"] != "0,1" || values["reference_nproc"] != "2" || values["reference_gomaxprocs"] != "2" || values["cgroup2"] != "cgroup2fs" || values["bpffs"] != "bpf_fs" {
		return errors.New("environment is not the documented Linux two-CPU reference profile")
	}
	if _, err := recordedGoVersion(values["go_version"], values["goarch"]); err != nil {
		return err
	}
	if !strings.HasPrefix(values["uname"], "Linux ") {
		return fmt.Errorf("uname %q does not report a Linux host", values["uname"])
	}
	if err := verifyCPUQuotaProvenance(values); err != nil {
		return err
	}
	clockTicks, err := strconv.ParseInt(values["getconf_clk_tck"], 10, 64)
	if err != nil || clockTicks <= 0 {
		return fmt.Errorf("getconf_clk_tck %q is not a positive integer", values["getconf_clk_tck"])
	}
	nproc, err := strconv.ParseInt(values["nproc"], 10, 64)
	if err != nil || nproc <= 0 {
		return fmt.Errorf("nproc %q is not a positive integer", values["nproc"])
	}
	referenceNproc, err := strconv.ParseInt(values["reference_nproc"], 10, 64)
	if err != nil || referenceNproc <= 0 {
		return fmt.Errorf("reference_nproc %q is not a positive integer", values["reference_nproc"])
	}
	if nproc < referenceNproc {
		return fmt.Errorf("nproc %d is smaller than the reference CPU count %d", nproc, referenceNproc)
	}
	return nil
}

func validWorkflowRef(ref, migrationBranch string) bool {
	return migrationBranch != "" && strings.HasPrefix(ref, "refs/heads/") && strings.TrimPrefix(ref, "refs/heads/") == migrationBranch
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func recordedGoVersion(value, expectedArch string) (string, error) {
	fields := strings.Fields(value)
	version := ""
	if len(fields) == 4 {
		version = fields[2]
	}
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || !validGoVersionToken(version) || fields[3] != "linux/"+expectedArch {
		return "", fmt.Errorf("go_version %q does not report the recorded Linux/%s target", value, expectedArch)
	}
	return version, nil
}

func validGoVersionToken(version string) bool {
	if !strings.HasPrefix(version, "go") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(version, "go"), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func verifyEnvironmentMatchesEvidence(environmentPath, directory string) error {
	values, err := readEnvironmentValues(environmentPath)
	if err != nil {
		return err
	}
	goVersion, err := recordedGoVersion(values["go_version"], values["goarch"])
	if err != nil {
		return err
	}
	var reference referenceEvidence
	if err := readEvidence(filepath.Join(directory, "phase5-performance.json"), &reference); err != nil {
		return err
	}
	if reference.RunID != values["phase5_run_id"] {
		return fmt.Errorf("phase5-performance.json run ID %q does not match environment phase5_run_id %q", reference.RunID, values["phase5_run_id"])
	}
	if reference.GoVersion != goVersion || reference.GOOS != values["goos"] || reference.GOARCH != values["goarch"] {
		return fmt.Errorf("phase5-performance.json producer metadata does not match environment: Go=%q/%q GOOS=%q/%q GOARCH=%q/%q", reference.GoVersion, goVersion, reference.GOOS, values["goos"], reference.GOARCH, values["goarch"])
	}
	referenceNproc, err := strconv.Atoi(values["reference_nproc"])
	if err != nil || referenceNproc <= 0 {
		return fmt.Errorf("reference_nproc %q is not a positive integer", values["reference_nproc"])
	}
	if reference.CPUs != referenceNproc {
		return fmt.Errorf("phase5-performance.json CPU profile %d does not match reference_nproc=%d", reference.CPUs, referenceNproc)
	}
	clockTicks, err := strconv.ParseInt(values["getconf_clk_tck"], 10, 64)
	if err != nil || clockTicks <= 0 {
		return fmt.Errorf("getconf_clk_tck %q is not a positive integer", values["getconf_clk_tck"])
	}
	var resource resourceEvidence
	if err := readEvidence(filepath.Join(directory, "phase5-agent-resource.json"), &resource); err != nil {
		return err
	}
	if resource.ClockTicks != clockTicks {
		return fmt.Errorf("phase5-agent-resource.json clock ticks %d do not match getconf_clk_tck=%d", resource.ClockTicks, clockTicks)
	}
	return nil
}

func validateCPUQuota(value string) error {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return fmt.Errorf("cpu_max %q is not a two-field cgroup CPU quota", value)
	}
	if fields[0] != "max" {
		quota, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || quota == 0 {
			return fmt.Errorf("cpu_max %q has an invalid quota", value)
		}
	}
	period, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return fmt.Errorf("cpu_max %q has an invalid period", value)
	}
	return nil
}
