package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

func validateHostedFixture(path string) error {
	text, err := readHostedEvidence(path)
	if err != nil {
		return err
	}
	if !strings.Contains(text, "namespace: ztap-performance") {
		return fmt.Errorf("%s is missing the ztap-performance namespace", path)
	}
	if countHostedExactLine(text, "apiVersion: v1") != referenceSubjects+1 {
		return fmt.Errorf("%s contains an unexpected core API object count", path)
	}
	if countHostedExactLine(text, "apiVersion: networking.k8s.io/v1") != referencePolicies {
		return fmt.Errorf("%s contains an unexpected NetworkPolicy API object count", path)
	}
	if countHostedExactLine(text, "namespace: ztap-performance") != referenceSubjects+referencePolicies {
		return fmt.Errorf("%s does not place every workload and policy in ztap-performance", path)
	}
	podCount := countHostedExactLine(text, "kind: Pod")
	if podCount != referenceSubjects {
		return fmt.Errorf("%s contains %d Pod objects, want %d", path, podCount, referenceSubjects)
	}
	policyCount := countHostedExactLine(text, "kind: NetworkPolicy")
	if policyCount != referencePolicies {
		return fmt.Errorf("%s contains %d NetworkPolicy objects, want %d", path, policyCount, referencePolicies)
	}
	if err := validateHostedObjectNames(path, text, "reference-pod-", referenceSubjects, 3); err != nil {
		return err
	}
	if err := validateHostedObjectNames(path, text, "reference-policy-", referencePolicies, 2); err != nil {
		return err
	}
	if countHostedObjectBucketMarkers(text) != referenceSubjects+referencePolicies {
		return fmt.Errorf("%s is missing the documented subject buckets", path)
	}
	if err := validateHostedFixtureDocuments(path, text); err != nil {
		return err
	}
	peerCount := countHostedContainingLine(text, "cidr: 198.18.")
	if peerCount != referenceRules/referenceSubjects*referencePolicies {
		return fmt.Errorf("%s contains an unexpected reference peer count", path)
	}
	return nil
}

func validateHostedObjectNames(path, text, prefix string, expectedCount, width int) error {
	seen := make(map[int]struct{}, expectedCount)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		namePrefix := "name: " + prefix
		if !strings.HasPrefix(line, namePrefix) {
			continue
		}
		suffix := strings.TrimPrefix(line, namePrefix)
		if len(suffix) != width {
			return fmt.Errorf("%s contains malformed %s object name %q", path, prefix, line)
		}
		index, err := strconv.Atoi(suffix)
		if err != nil || index < 0 || index >= expectedCount {
			return fmt.Errorf("%s contains out-of-range %s object name %q", path, prefix, line)
		}
		if _, duplicate := seen[index]; duplicate {
			return fmt.Errorf("%s repeats %s object name %q", path, prefix, line)
		}
		seen[index] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	if len(seen) != expectedCount {
		return fmt.Errorf("%s contains %d %s object names, want %d", path, len(seen), prefix, expectedCount)
	}
	return nil
}

func countHostedExactLine(text, expected string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		if strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r")) == expected {
			count++
		}
	}
	return count
}

func countHostedContainingLine(text, fragment string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), fragment) {
			count++
		}
	}
	return count
}

func countHostedObjectBucketMarkers(text string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.HasPrefix(line, "    phase5-bucket:") {
			count++
		}
	}
	return count
}

func validateHostedFixtureDocuments(path, text string) error {
	documents, err := hostedFixtureDocuments(path, text)
	if err != nil {
		return err
	}
	if len(documents) != referenceSubjects+referencePolicies+1 {
		return fmt.Errorf("%s contains %d YAML documents, want %d", path, len(documents), referenceSubjects+referencePolicies+1)
	}
	namespaceCount := 0
	for _, document := range documents {
		object, err := decodeHostedYAMLDocument(path, document)
		if err != nil {
			return err
		}
		apiVersion, apiVersionOK := hostedYAMLStringField(object, "apiVersion")
		kind, kindOK := hostedYAMLStringField(object, "kind")
		metadata, metadataOK := hostedYAMLMappingField(object, "metadata")
		name, nameOK := hostedYAMLStringField(metadata, "name")
		if !apiVersionOK || !kindOK || !metadataOK || !nameOK {
			return fmt.Errorf("%s contains a fixture document with invalid top-level metadata", path)
		}
		switch kind {
		case "Namespace":
			if err := requireHostedYAMLFieldSet(path, object, "Namespace document", "apiVersion", "kind", "metadata"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, "Namespace metadata", "name"); err != nil {
				return err
			}
			namespaceCount++
			if apiVersion != "v1" || name != "ztap-performance" {
				return fmt.Errorf("%s contains an invalid ztap-performance Namespace document", path)
			}
			continue
		case "Pod":
			if err := requireHostedYAMLFieldSet(path, object, fmt.Sprintf("Pod %q", name), "apiVersion", "kind", "metadata", "spec"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, fmt.Sprintf("Pod %q metadata", name), "name", "namespace", "labels"); err != nil {
				return err
			}
			namespace, namespaceOK := hostedYAMLStringField(metadata, "namespace")
			if apiVersion != "v1" || !namespaceOK || namespace != "ztap-performance" {
				return fmt.Errorf("%s Pod %q has an invalid API version or namespace", path, name)
			}
			index, err := parseHostedFixtureIndex(path, name, "reference-pod-", 3, referenceSubjects)
			if err != nil {
				return err
			}
			labels, labelsOK := hostedYAMLMappingField(metadata, "labels")
			if !labelsOK {
				return fmt.Errorf("%s Pod %q is missing metadata labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, labels, index/(referenceSubjects/referencePolicies)); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, labels, fmt.Sprintf("Pod %q labels", name), "phase5-bucket"); err != nil {
				return err
			}
			if err := validateHostedFixturePodSpec(path, object, name); err != nil {
				return err
			}
		case "NetworkPolicy":
			if err := requireHostedYAMLFieldSet(path, object, fmt.Sprintf("NetworkPolicy %q", name), "apiVersion", "kind", "metadata", "spec"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, metadata, fmt.Sprintf("NetworkPolicy %q metadata", name), "name", "namespace", "labels"); err != nil {
				return err
			}
			namespace, namespaceOK := hostedYAMLStringField(metadata, "namespace")
			if apiVersion != "networking.k8s.io/v1" || !namespaceOK || namespace != "ztap-performance" {
				return fmt.Errorf("%s NetworkPolicy %q has an invalid API version or namespace", path, name)
			}
			index, err := parseHostedFixtureIndex(path, name, "reference-policy-", 2, referencePolicies)
			if err != nil {
				return err
			}
			labels, labelsOK := hostedYAMLMappingField(metadata, "labels")
			if !labelsOK {
				return fmt.Errorf("%s NetworkPolicy %q is missing metadata labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, labels, index); err != nil {
				return err
			}
			spec, specOK := hostedYAMLMappingField(object, "spec")
			selector, selectorOK := hostedYAMLMappingField(spec, "podSelector")
			selectorLabels, selectorLabelsOK := hostedYAMLMappingField(selector, "matchLabels")
			if !specOK || !selectorOK || !selectorLabelsOK {
				return fmt.Errorf("%s NetworkPolicy %q is missing its pod selector labels", path, name)
			}
			if err := requireHostedYAMLBucket(path, selectorLabels, index); err != nil {
				return err
			}
			if err := validateHostedFixturePeers(path, object, index); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s contains unexpected fixture kind %q", path, kind)
		}
	}
	if namespaceCount != 1 {
		return fmt.Errorf("%s contains %d Namespace documents, want 1", path, namespaceCount)
	}
	return nil
}

func validateHostedFixturePodSpec(path string, object *yaml.Node, name string) error {
	spec, specOK := hostedYAMLMappingField(object, "spec")
	if !specOK {
		return fmt.Errorf("%s Pod %q is missing its spec mapping", path, name)
	}
	if err := requireHostedYAMLFieldSet(path, spec, fmt.Sprintf("Pod %q spec", name), "containers"); err != nil {
		return err
	}
	containers, containersOK := hostedYAMLSequenceField(spec, "containers")
	if !containersOK || len(containers.Content) != 1 {
		count := 0
		if containersOK {
			count = len(containers.Content)
		}
		return fmt.Errorf("%s Pod %q contains %d containers, want 1", path, name, count)
	}
	container := containers.Content[0]
	if err := requireHostedYAMLFieldSet(path, container, fmt.Sprintf("Pod %q workload container", name), "name", "image", "imagePullPolicy", "command", "securityContext"); err != nil {
		return err
	}
	containerName, containerNameOK := hostedYAMLStringField(container, "name")
	image, imageOK := hostedYAMLStringField(container, "image")
	imagePullPolicy, imagePullPolicyOK := hostedYAMLStringField(container, "imagePullPolicy")
	if !containerNameOK || containerName != "workload" || !imageOK || image != "busybox:1.36.1" || !imagePullPolicyOK || imagePullPolicy != "IfNotPresent" {
		return fmt.Errorf("%s Pod %q workload container has unexpected image metadata", path, name)
	}
	command, commandOK := hostedYAMLSequenceField(container, "command")
	wantCommand := []string{"sh", "-c", "sleep 3600"}
	if !commandOK || len(command.Content) != len(wantCommand) {
		return fmt.Errorf("%s Pod %q workload command has an unexpected shape", path, name)
	}
	for index, want := range wantCommand {
		item := command.Content[index]
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || item.Value != want {
			return fmt.Errorf("%s Pod %q workload command item %d is %q, want %q", path, name, index, item.Value, want)
		}
	}
	security, ok := hostedYAMLMappingField(container, "securityContext")
	if !ok {
		return fmt.Errorf("%s Pod %q workload security context is missing", path, name)
	}
	if err := requireHostedYAMLFieldSet(path, security, fmt.Sprintf("Pod %q security context", name), "allowPrivilegeEscalation", "capabilities"); err != nil {
		return err
	}
	escalation, ok := hostedYAMLField(security, "allowPrivilegeEscalation")
	if !ok || escalation.Kind != yaml.ScalarNode || escalation.Tag != "!!bool" || escalation.Value != "false" {
		return fmt.Errorf("%s Pod %q must explicitly disable privilege escalation", path, name)
	}
	capabilities, ok := hostedYAMLMappingField(security, "capabilities")
	if !ok {
		return fmt.Errorf("%s Pod %q capabilities are missing", path, name)
	}
	if err := requireHostedYAMLFieldSet(path, capabilities, fmt.Sprintf("Pod %q capabilities", name), "drop"); err != nil {
		return err
	}
	drop, ok := hostedYAMLSequenceField(capabilities, "drop")
	if !ok || len(drop.Content) != 1 || drop.Content[0].Tag != "!!str" || drop.Content[0].Value != "NET_RAW" {
		return fmt.Errorf("%s Pod %q must drop NET_RAW", path, name)
	}
	return nil
}

func decodeHostedYAMLDocument(path string, document []string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(strings.Join(document, "\n") + "\n"))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("%s contains invalid YAML: %w", path, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s contains a fixture document that is not a YAML mapping", path)
	}
	if err := validateStrictYAMLMapping(root.Content[0], 0); err != nil {
		return nil, fmt.Errorf("%s contains invalid or duplicate YAML mapping keys: %w", path, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s contains multiple YAML documents in one fixture document", path)
		}
		return nil, fmt.Errorf("%s contains trailing invalid YAML: %w", path, err)
	}
	return root.Content[0], nil
}

func validateStrictYAMLMapping(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if depth > maxHostedYAMLDepth {
		return fmt.Errorf("YAML nesting exceeds depth %d", maxHostedYAMLDepth)
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return errors.New("YAML anchors and aliases are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return errors.New("mapping has an incomplete key/value pair")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind == yaml.ScalarNode && key.Value == "<<" {
				return errors.New("YAML merge keys are not allowed")
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("mapping key %q is not a string", key.Value)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateStrictYAMLMapping(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateHostedFixturePeers(path string, object *yaml.Node, policyIndex int) error {
	wantPeers := referenceRules / referenceSubjects
	spec, specOK := hostedYAMLMappingField(object, "spec")
	if !specOK {
		return fmt.Errorf("%s policy %q is missing its spec mapping", path, fmt.Sprintf("reference-policy-%02d", policyIndex))
	}
	policyName := fmt.Sprintf("reference-policy-%02d", policyIndex)
	if err := requireHostedYAMLFieldSet(path, spec, fmt.Sprintf("NetworkPolicy %q spec", policyName), "podSelector", "policyTypes", "egress"); err != nil {
		return err
	}
	selector, selectorOK := hostedYAMLMappingField(spec, "podSelector")
	if !selectorOK {
		return fmt.Errorf("%s policy %q is missing its pod selector mapping", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, selector, fmt.Sprintf("NetworkPolicy %q podSelector", policyName), "matchLabels"); err != nil {
		return err
	}
	selectorLabels, selectorLabelsOK := hostedYAMLMappingField(selector, "matchLabels")
	if !selectorLabelsOK {
		return fmt.Errorf("%s policy %q is missing its matchLabels mapping", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, selectorLabels, fmt.Sprintf("NetworkPolicy %q matchLabels", policyName), "phase5-bucket"); err != nil {
		return err
	}
	policyTypes, policyTypesOK := hostedYAMLSequenceField(spec, "policyTypes")
	if !policyTypesOK || len(policyTypes.Content) != 1 || policyTypes.Content[0].Kind != yaml.ScalarNode || policyTypes.Content[0].Tag != "!!str" || policyTypes.Content[0].Value != "Egress" {
		return fmt.Errorf("%s policy %q must contain exactly one Egress policy type", path, policyName)
	}
	egress, egressOK := hostedYAMLSequenceField(spec, "egress")
	if !egressOK || len(egress.Content) != 1 {
		return fmt.Errorf("%s policy %q must contain exactly one egress rule", path, policyName)
	}
	rule := egress.Content[0]
	if err := requireHostedYAMLFieldSet(path, rule, fmt.Sprintf("NetworkPolicy %q egress rule", policyName), "to", "ports"); err != nil {
		return err
	}
	to, toOK := hostedYAMLSequenceField(rule, "to")
	if !toOK || len(to.Content) != wantPeers {
		count := 0
		if toOK {
			count = len(to.Content)
		}
		return fmt.Errorf("%s policy %q contains %d structured peers, want %d", path, policyName, count, wantPeers)
	}
	ports, portsOK := hostedYAMLSequenceField(rule, "ports")
	if !portsOK || len(ports.Content) != 1 {
		return fmt.Errorf("%s policy %q must contain exactly one port rule", path, policyName)
	}
	if err := requireHostedYAMLFieldSet(path, ports.Content[0], fmt.Sprintf("NetworkPolicy %q port rule", policyName), "protocol", "port"); err != nil {
		return err
	}
	protocol, protocolOK := hostedYAMLStringField(ports.Content[0], "protocol")
	port, portOK := hostedYAMLIntegerField(ports.Content[0], "port")
	if !protocolOK || protocol != "TCP" || !portOK || port != 10000 {
		return fmt.Errorf("%s policy %q must allow only TCP port 10000", path, policyName)
	}
	for peerIndex, peer := range to.Content {
		ipBlock, ok := hostedYAMLMappingField(peer, "ipBlock")
		if ok {
			if err := requireHostedYAMLFieldSet(path, peer, fmt.Sprintf("NetworkPolicy %q peer %d", policyName, peerIndex), "ipBlock"); err != nil {
				return err
			}
			if err := requireHostedYAMLFieldSet(path, ipBlock, fmt.Sprintf("NetworkPolicy %q peer %d ipBlock", policyName, peerIndex), "cidr"); err != nil {
				return err
			}
		}
		cidr, cidrOK := hostedYAMLStringField(ipBlock, "cidr")
		want := fmt.Sprintf("198.18.%d.%d/32", policyIndex, peerIndex)
		if !ok || !cidrOK || cidr != want {
			return fmt.Errorf("%s policy %q peer %d has CIDR %q, want %q", path, policyName, peerIndex, cidr, want)
		}
	}
	return nil
}

func hostedFixtureDocuments(path, text string) ([][]string, error) {
	documents := make([][]string, 0, referenceSubjects+referencePolicies+1)
	current := make([]string, 0, 32)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "---" {
			if len(current) > 0 {
				documents = append(documents, current)
				current = make([]string, 0, 32)
			}
			continue
		}
		if strings.TrimSpace(line) != "" {
			current = append(current, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if len(current) > 0 {
		documents = append(documents, current)
	}
	return documents, nil
}

func parseHostedFixtureIndex(path, name, prefix string, width, count int) (int, error) {
	if !strings.HasPrefix(name, prefix) {
		return 0, fmt.Errorf("%s contains malformed fixture object name %q", path, name)
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != width {
		return 0, fmt.Errorf("%s contains malformed fixture object name %q", path, name)
	}
	index, err := strconv.Atoi(suffix)
	if err != nil || index < 0 || index >= count {
		return 0, fmt.Errorf("%s contains out-of-range fixture object name %q", path, name)
	}
	return index, nil
}

func hostedYAMLField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		keyNode := mapping.Content[index]
		if keyNode.Kind == yaml.ScalarNode && keyNode.Value == key {
			return mapping.Content[index+1], true
		}
	}
	return nil, false
}

func requireHostedYAMLFieldSet(path string, mapping *yaml.Node, context string, expectedFields ...string) error {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("%s has no mapping for %s", path, context)
	}
	expected := make(map[string]struct{}, len(expectedFields))
	for _, field := range expectedFields {
		expected[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(mapping.Content)/2)
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key := mapping.Content[index].Value
		if _, ok := expected[key]; !ok {
			return fmt.Errorf("%s has unexpected YAML field %q in %s", path, key, context)
		}
		seen[key] = struct{}{}
	}
	for _, field := range expectedFields {
		if _, ok := seen[field]; !ok {
			return fmt.Errorf("%s is missing YAML field %q in %s", path, field, context)
		}
	}
	return nil
}

func hostedYAMLStringField(mapping *yaml.Node, key string) (string, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.ScalarNode || field.Tag != "!!str" {
		return "", false
	}
	return field.Value, true
}

func hostedYAMLMappingField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.MappingNode {
		return nil, false
	}
	return field, true
}

func hostedYAMLSequenceField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.SequenceNode {
		return nil, false
	}
	return field, true
}

func hostedYAMLIntegerField(mapping *yaml.Node, key string) (int64, bool) {
	field, ok := hostedYAMLField(mapping, key)
	if !ok || field.Kind != yaml.ScalarNode || field.Tag != "!!int" {
		return 0, false
	}
	value, err := strconv.ParseInt(field.Value, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func requireHostedYAMLBucket(path string, labels *yaml.Node, expected int) error {
	want := fmt.Sprintf("%02d", expected)
	value, ok := hostedYAMLStringField(labels, "phase5-bucket")
	if !ok {
		return fmt.Errorf("%s is missing a string phase5-bucket marker", path)
	}
	if value != want {
		return fmt.Errorf("%s has bucket %q, want %q", path, value, want)
	}
	return nil
}
