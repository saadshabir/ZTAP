package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func hostedKeyValues(path string) (map[string][]string, error) {
	text, err := readHostedEvidence(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("%s has malformed hosted key/value line %q", path, line)
		}
		values[key] = append(values[key], value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return values, nil
}

func validateHostedKeySet(values map[string][]string, path string, allowed map[string]struct{}) error {
	for key, entries := range values {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s contains unexpected hosted evidence key %q", path, key)
		}
		if _, repeated := hostedRepeatedEvidenceKeys[key]; !repeated && len(entries) != 1 {
			return fmt.Errorf("%s contains duplicate hosted evidence key %q", path, key)
		}
	}
	return nil
}

func requireHostedValue(values map[string][]string, path, key, expected string) error {
	entries := values[key]
	if len(entries) == 1 && entries[0] == expected {
		return nil
	}
	return fmt.Errorf("%s must contain exactly one %s=%s entry", path, key, expected)
}

func hostedSingleValue(values map[string][]string, path, key string) (string, error) {
	entries := values[key]
	if len(entries) != 1 || strings.TrimSpace(entries[0]) == "" {
		return "", fmt.Errorf("%s must contain exactly one non-empty %s value", path, key)
	}
	return entries[0], nil
}

func parseHostedFloat(values map[string][]string, path, key string) (float64, error) {
	value, err := hostedSingleValue(values, path, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 {
		return 0, fmt.Errorf("%s has invalid %s=%q", path, key, value)
	}
	return parsed, nil
}

func parseHostedUint(values map[string][]string, path, key string) (uint64, error) {
	value, err := hostedSingleValue(values, path, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s has invalid %s=%q", path, key, value)
	}
	return parsed, nil
}

func validateHostedResourceEvidence(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	samples, err := parseHostedResourceSamples(path, text)
	if err != nil {
		return err
	}
	values, err := hostedKeyValues(path)
	if err != nil {
		return err
	}
	if err := validateHostedKeySet(values, path, hostedResourceEvidenceKeys); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "scope", "real capability-only DaemonSet in kind with 250 Pods, 25 policies, and 2500 rules"); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "reference_fixture_status", "active_waiting_for_quiet_interval"); err != nil {
		return err
	}
	for _, key := range []string{"agent_pod", "container_id", "cgroup_path"} {
		if _, err := hostedSingleValue(values, path, key); err != nil {
			return err
		}
	}
	if err := requireHostedValue(values, path, "agent_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	agentPod, err := hostedSingleValue(values, path, "agent_pod")
	if err != nil {
		return err
	}
	if !validHostedAgentPodName(agentPod) {
		return fmt.Errorf("%s records agent_pod=%q outside the shipped ztap-agent DaemonSet", path, agentPod)
	}
	containerID, err := hostedSingleValue(values, path, "container_id")
	if err != nil {
		return err
	}
	if !validHostedContainerID(containerID) {
		return fmt.Errorf("%s records a non-64-hex container_id=%q", path, containerID)
	}
	cgroupPath, err := hostedSingleValue(values, path, "cgroup_path")
	if err != nil {
		return err
	}
	if !validHostedContainerCgroupPath(cgroupPath, containerID) {
		return fmt.Errorf("%s records cgroup_path=%q that is not a canonical /sys/fs/cgroup path for container_id=%q", path, cgroupPath, containerID)
	}
	for key, expected := range map[string]string{
		"observed_fixture_pods":             "250",
		"observed_fixture_policies":         "25",
		"reference_cpu_max":                 "200000 100000",
		"reference_fixture_agent_enforcing": "1",
		"reference_fixture_compiled_rules":  "2500",
		"reference_total_compiled_rules":    "2501",
		"reference_total_enforced_cgroups":  "251",
		"retained_smoke_client_cgroups":     "1",
		"retained_smoke_client_rules":       "1",
		"memory_metric":                     "memory.current (conservative cgroup memory upper bound; includes non-RSS charges)",
		"samples":                           "3",
		"quiet_settle_seconds":              "10",
		"sample_interval_seconds":           "5",
		"memory_peak_sample_interval_ms":    "100",
		"cpu_budget_cores":                  "0.10",
		"memory_current_budget_mib":         "200",
		"budget_result":                     "passed",
	} {
		if err := requireHostedValue(values, path, key, expected); err != nil {
			return err
		}
	}
	activePolicyEpoch, err := parseHostedUint(values, path, "reference_fixture_active_policy_epoch")
	if err != nil {
		return err
	}
	if activePolicyEpoch < 1 {
		return fmt.Errorf("%s reports active policy epoch %d, want at least 1", path, activePolicyEpoch)
	}
	enforced, err := parseHostedUint(values, path, "reference_fixture_enforced_cgroups")
	if err != nil {
		return err
	}
	if enforced != referenceSubjects {
		return fmt.Errorf("%s reports %d enforced cgroups, want exactly %d", path, enforced, referenceSubjects)
	}
	totalEnforced, err := parseHostedUint(values, path, "reference_total_enforced_cgroups")
	if err != nil {
		return err
	}
	retainedCgroups, err := parseHostedUint(values, path, "retained_smoke_client_cgroups")
	if err != nil {
		return err
	}
	if totalEnforced != enforced+retainedCgroups {
		return fmt.Errorf("%s reports %d total enforced cgroups, want fixture count %d plus %d retained smoke cgroups", path, totalEnforced, enforced, retainedCgroups)
	}
	compiledRules, err := parseHostedUint(values, path, "reference_fixture_compiled_rules")
	if err != nil {
		return err
	}
	totalRules, err := parseHostedUint(values, path, "reference_total_compiled_rules")
	if err != nil {
		return err
	}
	retainedRules, err := parseHostedUint(values, path, "retained_smoke_client_rules")
	if err != nil {
		return err
	}
	if totalRules != compiledRules+retainedRules {
		return fmt.Errorf("%s reports %d total compiled rules, want fixture count %d plus %d retained smoke rules", path, totalRules, compiledRules, retainedRules)
	}
	maxCPU, err := parseHostedFloat(values, path, "max_cpu_cores")
	if err != nil {
		return err
	}
	maxSampleCPU := 0.0
	maxSampleMemory := 0.0
	for _, sample := range samples {
		if sample.ElapsedNanoseconds < uint64(5*time.Second) {
			return fmt.Errorf("%s resource sample elapsed interval %dns is shorter than the documented five seconds", path, sample.ElapsedNanoseconds)
		}
		if sample.CPUCores > maxSampleCPU {
			maxSampleCPU = sample.CPUCores
		}
		if sample.MemoryCurrentMiB > maxSampleMemory {
			maxSampleMemory = sample.MemoryCurrentMiB
		}
	}
	if !nearlyEqual(maxCPU, maxSampleCPU) {
		return fmt.Errorf("%s reports max_cpu_cores=%.6f, want sample maximum %.6f", path, maxCPU, maxSampleCPU)
	}
	if maxCPU > cpuBudgetCores {
		return fmt.Errorf("%s reports %.6f CPU cores, over %.2f budget", path, maxCPU, cpuBudgetCores)
	}
	maxMemory, err := parseHostedFloat(values, path, "max_memory_current_mib")
	if err != nil {
		return err
	}
	if !nearlyEqual(maxMemory, maxSampleMemory) {
		return fmt.Errorf("%s reports max_memory_current_mib=%.6f, want sample maximum %.6f", path, maxMemory, maxSampleMemory)
	}
	if maxMemory > rssBudgetMiB {
		return fmt.Errorf("%s reports %.3f MiB, over %d MiB budget", path, maxMemory, rssBudgetMiB)
	}
	return nil
}

func validateHostedResourceSamples(path, text string) error {
	_, err := parseHostedResourceSamples(path, text)
	return err
}

type hostedResourceSample struct {
	StartCPUUsec       uint64
	EndCPUUsec         uint64
	StartMemoryBytes   uint64
	EndMemoryBytes     uint64
	PeakMemoryBytes    uint64
	CPUCores           float64
	MemoryCurrentMiB   float64
	ElapsedNanoseconds uint64
}

func parseHostedResourceSamples(path, text string) ([]hostedResourceSample, error) {
	nextSample := 1
	samples := make([]hostedResourceSample, 0, repeatedSamples)
	var previousEndCPUUsec uint64
	havePreviousEndCPU := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if !strings.HasPrefix(line, "sample=") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 9 {
			return nil, fmt.Errorf("%s has malformed resource sample line %q", path, line)
		}
		values := make(map[string]string, len(fields))
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if !ok || key == "" || value == "" {
				return nil, fmt.Errorf("%s has malformed resource sample field %q", path, field)
			}
			if _, exists := values[key]; exists {
				return nil, fmt.Errorf("%s repeats resource sample field %q", path, key)
			}
			values[key] = value
		}
		for _, key := range []string{"sample", "start_cpu_usec", "end_cpu_usec", "start_memory_current_bytes", "end_memory_current_bytes", "peak_memory_current_bytes", "cpu_cores", "memory_current_mib", "elapsed_ns"} {
			if _, ok := values[key]; !ok {
				return nil, fmt.Errorf("%s resource sample is missing %s", path, key)
			}
		}
		if len(values) != 9 {
			return nil, fmt.Errorf("%s has an invalid resource sample field set", path)
		}
		sample, err := strconv.Atoi(values["sample"])
		if err != nil || sample != nextSample {
			return nil, fmt.Errorf("%s resource sample index = %q, want %d", path, values["sample"], nextSample)
		}
		parsedSample := hostedResourceSample{}
		for _, field := range []struct {
			key   string
			value *uint64
		}{
			{key: "start_cpu_usec", value: &parsedSample.StartCPUUsec},
			{key: "end_cpu_usec", value: &parsedSample.EndCPUUsec},
			{key: "start_memory_current_bytes", value: &parsedSample.StartMemoryBytes},
			{key: "end_memory_current_bytes", value: &parsedSample.EndMemoryBytes},
			{key: "peak_memory_current_bytes", value: &parsedSample.PeakMemoryBytes},
		} {
			parsed, parseErr := strconv.ParseUint(values[field.key], 10, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("%s resource sample has invalid %s=%q", path, field.key, values[field.key])
			}
			*field.value = parsed
		}
		if parsedSample.EndCPUUsec < parsedSample.StartCPUUsec {
			return nil, fmt.Errorf("%s resource sample CPU counter decreased from %d to %d", path, parsedSample.StartCPUUsec, parsedSample.EndCPUUsec)
		}
		if havePreviousEndCPU && parsedSample.StartCPUUsec < previousEndCPUUsec {
			return nil, fmt.Errorf("%s resource sample CPU counter reset between samples from %d to %d", path, previousEndCPUUsec, parsedSample.StartCPUUsec)
		}
		if parsedSample.PeakMemoryBytes < parsedSample.StartMemoryBytes || parsedSample.PeakMemoryBytes < parsedSample.EndMemoryBytes {
			return nil, fmt.Errorf("%s resource sample peak memory %d is below start/end readings %d/%d", path, parsedSample.PeakMemoryBytes, parsedSample.StartMemoryBytes, parsedSample.EndMemoryBytes)
		}
		elapsed, err := strconv.ParseUint(values["elapsed_ns"], 10, 64)
		if err != nil || elapsed == 0 {
			return nil, fmt.Errorf("%s resource sample has invalid elapsed_ns=%q", path, values["elapsed_ns"])
		}
		reportedCPU, err := strconv.ParseFloat(values["cpu_cores"], 64)
		if err != nil || math.IsNaN(reportedCPU) || math.IsInf(reportedCPU, 0) || reportedCPU < 0 {
			return nil, fmt.Errorf("%s resource sample has invalid cpu_cores=%q", path, values["cpu_cores"])
		}
		computedCPU := float64(parsedSample.EndCPUUsec-parsedSample.StartCPUUsec) * 1000 / float64(elapsed)
		if !nearlyEqualMeasurement(reportedCPU, computedCPU) {
			return nil, fmt.Errorf("%s resource sample cpu_cores=%.9f does not match raw counters %.9f", path, reportedCPU, computedCPU)
		}
		reportedMemory, err := strconv.ParseFloat(values["memory_current_mib"], 64)
		if err != nil || math.IsNaN(reportedMemory) || math.IsInf(reportedMemory, 0) || reportedMemory < 0 {
			return nil, fmt.Errorf("%s resource sample has invalid memory_current_mib=%q", path, values["memory_current_mib"])
		}
		computedMemory := float64(parsedSample.PeakMemoryBytes) / (1024 * 1024)
		if !nearlyEqualMeasurement(reportedMemory, computedMemory) {
			return nil, fmt.Errorf("%s resource sample memory_current_mib=%.9f does not match raw counters %.9f", path, reportedMemory, computedMemory)
		}
		parsedSample.CPUCores = reportedCPU
		parsedSample.MemoryCurrentMiB = reportedMemory
		parsedSample.ElapsedNanoseconds = elapsed
		samples = append(samples, parsedSample)
		previousEndCPUUsec = parsedSample.EndCPUUsec
		havePreviousEndCPU = true
		nextSample++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if len(samples) != repeatedSamples {
		return nil, fmt.Errorf("%s contains %d measured resource samples, want %d", path, len(samples), repeatedSamples)
	}
	return samples, nil
}

func validHostedHex(value string) bool {
	if value == "" {
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

func validHostedContainerID(value string) bool {
	return len(value) == 64 && validHostedHex(value)
}

func validHostedCgroupPath(value string) bool {
	return strings.HasPrefix(value, "/sys/fs/cgroup/") && filepath.Clean(value) == value
}

func validHostedContainerCgroupPath(value, containerID string) bool {
	if !validHostedCgroupPath(value) || !validHostedContainerID(containerID) ||
		filepath.Base(value) != "cri-containerd-"+strings.ToLower(containerID)+".scope" {
		return false
	}
	return strings.HasPrefix(value, "/sys/fs/cgroup/kubepods.slice/") ||
		strings.HasPrefix(value, "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/")
}

func validHostedAgentPodName(value string) bool {
	if !strings.HasPrefix(value, "ztap-agent-") || len(value) > 253 {
		return false
	}
	suffix := strings.TrimPrefix(value, "ztap-agent-")
	if suffix == "" || suffix[0] == '-' || suffix[len(suffix)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func hostedTimestampResolutionNS(value string) uint64 {
	parts := strings.SplitN(value, "T", 2)
	if len(parts) != 2 || len(parts[1]) <= 8 || parts[1][8] != '.' {
		return uint64(time.Second)
	}
	fraction := parts[1][9:]
	if zoneStart := strings.IndexAny(fraction, "Z+-"); zoneStart >= 0 {
		fraction = fraction[:zoneStart]
	}
	if len(fraction) == 0 || len(fraction) > 9 {
		return 0
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' {
			return 0
		}
	}
	resolution := uint64(1)
	for index := len(fraction); index < 9; index++ {
		resolution *= 10
	}
	return resolution
}

func validateHostedRollingEvidence(path string) error {
	values, err := hostedKeyValues(path)
	if err != nil {
		return err
	}
	if versions, ok := values["schema_version"]; ok {
		if len(versions) != 1 || versions[0] != "2" {
			return errors.New("unsupported hosted continuity evidence version")
		}
		return validateHostedContinuityRolling(values, path)
	}

	if err := validateHostedKeySet(values, path, hostedRollingEvidenceKeys); err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "baseline_selected_smoke_client", "blocked"); err != nil {
		return err
	}
	smokeClientNode, err := hostedSingleValue(values, path, "smoke_client_node")
	if err != nil {
		return err
	}
	oldPod, err := hostedSingleValue(values, path, "old_pod")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "old_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	if !validHostedAgentPodName(oldPod) {
		return fmt.Errorf("%s records old_pod=%q outside the shipped ztap-agent DaemonSet", path, oldPod)
	}
	oldUID, err := hostedSingleValue(values, path, "old_uid")
	if err != nil {
		return err
	}
	oldNode, err := hostedSingleValue(values, path, "old_node")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "old_ready", "true"); err != nil {
		return err
	}
	replacementPod, err := hostedSingleValue(values, path, "replacement_pod")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "replacement_namespace", hostedAgentNamespace); err != nil {
		return err
	}
	if !validHostedAgentPodName(replacementPod) {
		return fmt.Errorf("%s records replacement_pod=%q outside the shipped ztap-agent DaemonSet", path, replacementPod)
	}
	replacementUID, err := hostedSingleValue(values, path, "replacement_uid")
	if err != nil {
		return err
	}
	replacementNode, err := hostedSingleValue(values, path, "replacement_node")
	if err != nil {
		return err
	}
	if err := requireHostedValue(values, path, "replacement_ready", "true"); err != nil {
		return err
	}
	replacementCreatedAt, err := hostedSingleValue(values, path, "replacement_created_at")
	if err != nil {
		return err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, replacementCreatedAt)
	if err != nil || createdAt.UnixNano() <= 0 {
		return fmt.Errorf("%s records invalid replacement_created_at=%q", path, replacementCreatedAt)
	}
	replacementObserved, err := parseHostedUint(values, path, "replacement_observed_ns")
	if err != nil {
		return err
	}
	if replacementObserved == 0 {
		return fmt.Errorf("%s records a zero replacement observation timestamp", path)
	}
	if oldPod == replacementPod {
		return fmt.Errorf("%s reports the same old and replacement pod %q", path, oldPod)
	}
	if oldUID == replacementUID {
		return fmt.Errorf("%s reports the same old and replacement pod UID %q", path, oldUID)
	}
	if oldNode != replacementNode {
		return fmt.Errorf("%s reports replacement node %q, want the old pod node %q", path, replacementNode, oldNode)
	}
	if oldNode != smokeClientNode {
		return fmt.Errorf("%s reports old pod node %q, want smoke-client node %q", path, oldNode, smokeClientNode)
	}
	rolloutStarted, err := parseHostedUint(values, path, "rollout_started_ns")
	if err != nil {
		return err
	}
	if rolloutStarted == 0 {
		return fmt.Errorf("%s records a zero rollout start timestamp", path)
	}
	start, err := parseHostedUint(values, path, "fail_open_start_ns")
	if err != nil {
		return err
	}
	if start == 0 {
		return fmt.Errorf("%s records a zero fail-open start timestamp", path)
	}
	end, err := parseHostedUint(values, path, "fail_open_end_ns")
	if err != nil {
		return err
	}
	if end == 0 {
		return fmt.Errorf("%s records a zero fail-open end timestamp", path)
	}
	if end <= start {
		return fmt.Errorf("%s records a non-positive fail-open interval", path)
	}
	if rolloutStarted > start {
		return fmt.Errorf("%s records fail-open start before rollout start", path)
	}
	createdAtNS := uint64(createdAt.UnixNano())
	if replacementObserved < createdAtNS {
		return fmt.Errorf("%s records replacement observation at %d before its creation at %d", path, replacementObserved, createdAtNS)
	}
	creationResolution := hostedTimestampResolutionNS(replacementCreatedAt)
	if creationResolution == 0 || createdAtNS > ^uint64(0)-creationResolution ||
		createdAtNS > end || createdAtNS+creationResolution <= rolloutStarted {
		return fmt.Errorf("%s records replacement creation at %d with %d-ns precision outside rollout-to-fail-open interval [%d,%d]", path, createdAtNS, creationResolution, rolloutStarted, end)
	}
	if replacementObserved < rolloutStarted || replacementObserved > end {
		return fmt.Errorf("%s records replacement observation at %d outside rollout-to-fail-open interval [%d,%d]", path, replacementObserved, rolloutStarted, end)
	}
	interval, err := parseHostedUint(values, path, "fail_open_interval_ms")
	if err != nil {
		return err
	}
	expected := (end - start) / 1_000_000
	if expected == 0 {
		return fmt.Errorf("%s records a fail-open interval shorter than one millisecond", path)
	}
	if interval != expected {
		return fmt.Errorf("%s records fail_open_interval_ms=%d, want %d from nanosecond timestamps", path, interval, expected)
	}
	return nil
}
