package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func verifyHostedEvidence(ebpfDirectory, capabilityDirectory string) error {
	ebpfTests, err := findHostedEvidenceFile(ebpfDirectory, "ebpf-engine-tests.txt")
	if err != nil {
		return err
	}
	capabilitySmoke, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-smoke.txt")
	if err != nil {
		return err
	}
	capabilityFixture, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-reference-fixture.txt")
	if err != nil {
		return err
	}
	fixture, err := findHostedEvidenceFile(capabilityDirectory, "phase5-reference-fixture.yaml")
	if err != nil {
		return err
	}
	resource, err := findHostedEvidenceFile(capabilityDirectory, "capability-agent-resource.txt")
	if err != nil {
		return err
	}
	rolling, err := findHostedEvidenceFile(capabilityDirectory, "rolling-fail-open-evidence.txt")
	if err != nil {
		return err
	}

	if err := requireHostedExactLine(ebpfTests, "ebpf_engine_runtime_gate=passed"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "capability-only DaemonSet attached and enforced the smoke policy"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "kindnet_networkpolicy_controller=disabled"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "status_endpoints=passed"); err != nil {
		return err
	}
	if err := requireHostedPositiveUintLine(capabilitySmoke, "packet_decisions_blocked_default_deny"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilitySmoke, "flow_streaming=passed"); err != nil {
		return err
	}
	if err := validateHostedFlowEvidence(capabilitySmoke); err != nil {
		return err
	}
	if err := validateHostedClusterIPEvidence(capabilitySmoke); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "fixture_shape=pods=250 policies=25 pods_per_policy=10 peers_per_policy=10 compiled_rules=2500"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "fixture_live_shape=verified"); err != nil {
		return err
	}
	if err := requireHostedExactLine(capabilityFixture, "offline_fixture_shape=pods=250 policies=25 compiled_rules=2500"); err != nil {
		return err
	}
	if err := validateHostedFixture(fixture); err != nil {
		return err
	}
	if err := validateHostedResourceEvidence(resource); err != nil {
		return err
	}
	if err := validateHostedRollingEvidence(rolling); err != nil {
		return err
	}
	return nil
}

type hostedFlowRecord struct {
	Timestamp     string `json:"timestamp"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
	CgroupID      uint64 `json:"cgroup_id"`
	Direction     string `json:"direction"`
	Protocol      string `json:"protocol"`
	SourceIP      string `json:"src_ip"`
	SourcePort    uint16 `json:"src_port"`
	DestIP        string `json:"dst_ip"`
	DestPort      uint16 `json:"dst_port"`
	Action        string `json:"action"`
	Reason        string `json:"reason"`
	SchemaVersion uint8  `json:"schema_version"`
}

func validateHostedFlowEvidence(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	expected := make(map[string]string, 3)
	blockedDefaultDenyEgress := make([]hostedFlowRecord, 0, 1)
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if strings.HasPrefix(line, "flow_expected_") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || value == "" {
				return fmt.Errorf("%s line %d has malformed flow expectation %q", path, lineNumber, line)
			}
			switch key {
			case "flow_expected_src_ip", "flow_expected_dst_ip", "flow_expected_dst_port":
			default:
				return fmt.Errorf("%s line %d has unknown flow expectation %q", path, lineNumber, key)
			}
			if _, exists := expected[key]; exists {
				return fmt.Errorf("%s line %d repeats flow expectation %q", path, lineNumber, key)
			}
			expected[key] = value
			continue
		}
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var record hostedFlowRecord
		if err := decodeHostedFlowRecord(line, &record); err != nil {
			return fmt.Errorf("%s line %d is not a valid flow JSON record: %w", path, lineNumber, err)
		}
		if record.Action == "blocked" && record.Direction == "egress" && record.Reason == "default_deny" {
			blockedDefaultDenyEgress = append(blockedDefaultDenyEgress, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	for _, key := range []string{"flow_expected_src_ip", "flow_expected_dst_ip", "flow_expected_dst_port"} {
		if expected[key] == "" {
			return fmt.Errorf("%s is missing %s", path, key)
		}
	}
	sourceIP := net.ParseIP(expected["flow_expected_src_ip"])
	if sourceIP == nil || sourceIP.To4() == nil {
		return fmt.Errorf("%s has invalid flow_expected_src_ip=%q", path, expected["flow_expected_src_ip"])
	}
	destIP := net.ParseIP(expected["flow_expected_dst_ip"])
	if destIP == nil || destIP.To4() == nil {
		return fmt.Errorf("%s has invalid flow_expected_dst_ip=%q", path, expected["flow_expected_dst_ip"])
	}
	destPort, err := strconv.ParseUint(expected["flow_expected_dst_port"], 10, 16)
	if err != nil || destPort != 8080 {
		return fmt.Errorf("%s has invalid flow_expected_dst_port=%q", path, expected["flow_expected_dst_port"])
	}
	for _, record := range blockedDefaultDenyEgress {
		if record.Protocol == "TCP" && record.SourceIP == sourceIP.String() &&
			record.SourcePort != 0 && record.DestIP == destIP.String() &&
			uint64(record.DestPort) == destPort {
			return nil
		}
	}
	return fmt.Errorf("%s is missing a blocked default-deny TCP egress flow for %s -> %s:%d", path, sourceIP, destIP, destPort)
}

func validateHostedClusterIPEvidence(path string) error {
	for _, marker := range []string{
		"selector_peer_direct_podip=allowed",
		"selector_peer_service_clusterip=blocked",
		"explicit_clusterip_ipblock_service=allowed",
		"explicit_clusterip_ipblock_podip=blocked",
	} {
		if err := requireHostedExactLine(path, marker); err != nil {
			return err
		}
	}
	serviceIPText, err := hostedSingleLineValue(path, "service_cluster_ip")
	if err != nil {
		return err
	}
	serviceIP := net.ParseIP(serviceIPText)
	if serviceIP == nil || serviceIP.To4() == nil || serviceIP.String() != serviceIPText {
		return fmt.Errorf("%s has invalid service_cluster_ip=%q", path, serviceIPText)
	}
	backendIPText, err := hostedSingleLineValue(path, "service_backend_pod_ip")
	if err != nil {
		return err
	}
	backendIP := net.ParseIP(backendIPText)
	if backendIP == nil || backendIP.To4() == nil || backendIP.String() != backendIPText {
		return fmt.Errorf("%s has invalid service_backend_pod_ip=%q", path, backendIPText)
	}
	if serviceIP.Equal(backendIP) {
		return fmt.Errorf("%s records the Service ClusterIP and backend PodIP as the same address", path)
	}
	cidr, err := hostedSingleLineValue(path, "explicit_clusterip_ipblock_cidr")
	if err != nil {
		return err
	}
	if cidr != serviceIPText+"/32" {
		return fmt.Errorf("%s has explicit_clusterip_ipblock_cidr=%q, want %s/32", path, cidr, serviceIPText)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%s has invalid explicit_clusterip_ipblock_cidr=%q", path, cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 32 || !network.IP.Equal(serviceIP) {
		return fmt.Errorf("%s has explicit_clusterip_ipblock_cidr=%q, want the exact IPv4 Service address", path, cidr)
	}
	flowDestinationIP, err := hostedSingleLineValue(path, "flow_expected_dst_ip")
	if err != nil {
		return err
	}
	if flowDestinationIP != backendIPText {
		return fmt.Errorf("%s flow destination %q does not match Service backend PodIP %q", path, flowDestinationIP, backendIPText)
	}
	selectorEpochText, err := hostedSingleLineValue(path, "selector_peer_policy_epoch")
	if err != nil {
		return err
	}
	selectorEpoch, err := strconv.ParseUint(selectorEpochText, 10, 64)
	if err != nil || selectorEpoch == 0 {
		return fmt.Errorf("%s has invalid selector_peer_policy_epoch=%q", path, selectorEpochText)
	}
	explicitEpochText, err := hostedSingleLineValue(path, "explicit_clusterip_policy_epoch")
	if err != nil {
		return err
	}
	explicitEpoch, err := strconv.ParseUint(explicitEpochText, 10, 64)
	if err != nil || explicitEpoch <= selectorEpoch {
		return fmt.Errorf("%s explicit ClusterIP policy epoch %q must exceed selector policy epoch %d", path, explicitEpochText, selectorEpoch)
	}
	return nil
}

func decodeHostedFlowRecord(line string, output *hostedFlowRecord) error {
	if err := validateStrictJSONKeys([]byte(line)); err != nil {
		return err
	}
	if err := validateRequiredJSONFields([]byte(line), output); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return err
	}
	for _, field := range []string{
		"timestamp", "policy_epoch", "cgroup_id", "direction", "protocol", "src_ip",
		"src_port", "dst_ip", "dst_port", "action", "reason", "schema_version",
	} {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing field %q", field)
		}
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	if output.Timestamp == "" {
		return errors.New("timestamp is empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, output.Timestamp); err != nil {
		return fmt.Errorf("timestamp %q is not RFC3339: %w", output.Timestamp, err)
	}
	if output.PolicyEpoch == 0 {
		return errors.New("policy_epoch is zero")
	}
	if output.CgroupID == 0 {
		return errors.New("cgroup_id is zero")
	}
	if output.Direction != "egress" && output.Direction != "ingress" {
		return fmt.Errorf("direction %q is unsupported", output.Direction)
	}
	if output.Action != "blocked" && output.Action != "allowed" {
		return fmt.Errorf("action %q is unsupported", output.Action)
	}
	if output.Protocol != "TCP" && output.Protocol != "UDP" && output.Protocol != "ICMP" {
		return fmt.Errorf("protocol %q is unsupported", output.Protocol)
	}
	if net.ParseIP(output.SourceIP) == nil || net.ParseIP(output.DestIP) == nil {
		return fmt.Errorf("flow addresses %q -> %q are invalid", output.SourceIP, output.DestIP)
	}
	if output.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d is unsupported", output.SchemaVersion)
	}
	if strings.TrimSpace(output.Reason) == "" {
		return errors.New("reason is empty")
	}
	return nil
}

func findHostedEvidenceFile(root, name string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("hosted evidence directory for %s is empty", name)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("open hosted evidence directory %q: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("hosted evidence path %q is a symlink", root)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("hosted evidence path %q is not a directory", root)
	}
	var matches []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("hosted evidence contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("hosted evidence entry %q is not a regular file", path)
		}
		if strings.EqualFold(entry.Name(), name) && entry.Name() != name {
			return fmt.Errorf("hosted evidence file %q has a case-variant duplicate name %q", name, path)
		}
		if entry.Name() == name {
			matches = append(matches, path)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("walk hosted evidence directory %q: %w", root, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("hosted evidence file %q is missing from %s", name, root)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("hosted evidence file %q occurs %d times in %s", name, len(matches), root)
	}
	return matches[0], nil
}

func readHostedEvidence(path string) (content string, err error) {
	const maxHostedEvidenceBytes = 4 << 20
	file, err := openRegularFile(path, "hosted evidence")
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, maxHostedEvidenceBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxHostedEvidenceBytes {
		return "", fmt.Errorf("%s exceeds the 4 MiB hosted evidence limit", path)
	}
	return string(data), nil
}

func requireHostedExactLine(path, expected string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	expectedKey, _, keyedMarker := strings.Cut(expected, "=")
	found := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if keyedMarker && strings.HasPrefix(line, expectedKey+"=") && line != expected {
			return fmt.Errorf("%s contains conflicting evidence line %q for %q", path, line, expectedKey)
		}
		if line == expected {
			if found {
				return fmt.Errorf("%s contains duplicate exact evidence line %q", path, expected)
			}
			found = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if found {
		return nil
	}
	return fmt.Errorf("%s is missing exact evidence line %q", path, expected)
}

func requireHostedPositiveUintLine(path, key string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	count := 0
	var value string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		recordedKey, recordedValue, ok := strings.Cut(line, "=")
		if !ok || recordedKey != key {
			continue
		}
		count++
		value = recordedValue
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if count != 1 {
		return fmt.Errorf("%s must contain exactly one %s= entry", path, key)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return fmt.Errorf("%s must contain a positive unsigned %s value", path, key)
	}
	return nil
}

func hostedSingleLineValue(path, key string) (string, error) {
	text, err := readHostedEvidence(path)
	if err != nil {
		return "", err
	}
	count := 0
	var value string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		recordedKey, recordedValue, ok := strings.Cut(line, "=")
		if !ok || recordedKey != key {
			continue
		}
		count++
		value = strings.TrimSpace(recordedValue)
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", path, err)
	}
	if count != 1 || value == "" {
		return "", fmt.Errorf("%s must contain exactly one non-empty %s value", path, key)
	}
	return value, nil
}
