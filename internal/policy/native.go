package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	yaml "gopkg.in/yaml.v3"
)

const (
	// NativeNetworkPolicyAPIVersion is the only API version accepted by the
	// streamlined product contract.
	NativeNetworkPolicyAPIVersion = "networking.k8s.io/v1"

	// NativeNetworkPolicyKind and NativeNetworkPolicyListKind are the only
	// resource kinds accepted by the offline validator.
	NativeNetworkPolicyKind     = "NetworkPolicy"
	NativeNetworkPolicyListKind = "NetworkPolicyList"

	// MaxIPBlockExpansion bounds the number of normalized IPv4 prefixes
	// generated from one ipBlock after applying its except entries.
	MaxIPBlockExpansion = 1024

	maxNativeAnnotationsSize = 256 * 1024
)

// NativeObjectMeta is the metadata subset needed by the streamlined policy
// contract. Namespace defaults to "default" for offline documents.
type NativeObjectMeta struct {
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// NativeLabelSelector is the Kubernetes label-selector subset accepted by
// the streamlined compiler.
type NativeLabelSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []NativeLabelSelectorRequirement
}

// NativeLabelSelectorRequirement is one Kubernetes selector expression.
type NativeLabelSelectorRequirement struct {
	Key      string
	Operator string
	Values   []string
}

// NativeIPBlock is an IPv4 CIDR peer with optional exclusions.
type NativeIPBlock struct {
	CIDR   string
	Except []string
}

// NativePeer describes one ingress source or egress destination. A peer may
// contain podSelector, namespaceSelector, or ipBlock. The two selectors may
// be combined; ipBlock may not be combined with either selector.
type NativePeer struct {
	PodSelector       *NativeLabelSelector
	NamespaceSelector *NativeLabelSelector
	IPBlock           *NativeIPBlock
}

// NativePort is the normalized numeric TCP/UDP port accepted by v0.1.0.
type NativePort struct {
	Protocol   string
	Port       int
	PortName   string
	HasEndPort bool
}

// NativeIngressRule is an ingress rule after strict decoding. Every rule
// must have at least one peer and one numeric port.
type NativeIngressRule struct {
	From  []NativePeer
	Ports []NativePort
}

// NativeEgressRule is an egress rule after strict decoding. Every rule must
// have at least one peer and one numeric port.
type NativeEgressRule struct {
	To    []NativePeer
	Ports []NativePort
}

// NativeNetworkPolicySpec is the supported NetworkPolicy spec subset.
type NativeNetworkPolicySpec struct {
	PodSelector *NativeLabelSelector
	PolicyTypes *[]string
	Ingress     []NativeIngressRule
	Egress      []NativeEgressRule
}

// NativeNetworkPolicy is a strictly decoded native Kubernetes NetworkPolicy.
// SourceDocument and FieldPrefix are populated by the file decoder to make
// diagnostics stable for multi-document files and NetworkPolicyList items.
type NativeNetworkPolicy struct {
	APIVersion     string
	Kind           string
	Metadata       *NativeObjectMeta
	Spec           *NativeNetworkPolicySpec
	SourceDocument int
	FieldPrefix    string
}

// EffectivePolicyTypes applies the Kubernetes NetworkPolicy defaulting rules
// used by the streamlined compiler. Ingress is selected when policyTypes is
// omitted; Egress is additionally selected when egress rules are present.
func (p NativeNetworkPolicy) EffectivePolicyTypes() []string {
	if p.Spec == nil || p.Spec.PolicyTypes == nil {
		if p.Spec != nil && len(p.Spec.Egress) > 0 {
			return []string{"Ingress", "Egress"}
		}
		return []string{"Ingress"}
	}
	result := append([]string(nil), (*p.Spec.PolicyTypes)...)
	return result
}

// NativeValidationError describes invalid or unsupported policy content. It
// intentionally carries a stable field path and source location so the CLI
// can report actionable errors without printing the source document.
type NativeValidationError struct {
	Document  int
	Namespace string
	Name      string
	Field     string
	Message   string
}

func (e NativeValidationError) Error() string {
	document := e.Document
	if document <= 0 {
		document = 1
	}

	location := fmt.Sprintf("document %d", document)
	namespace := strings.TrimSpace(e.Namespace)
	name := strings.TrimSpace(e.Name)
	if namespace != "" || name != "" {
		if namespace == "" {
			namespace = "default"
		}
		if name == "" {
			location += fmt.Sprintf(" (%s)", namespace)
		} else {
			location += fmt.Sprintf(" (%s/%s)", namespace, name)
		}
	}
	if e.Field != "" {
		return fmt.Sprintf("%s: %s: %s", location, e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s", location, e.Message)
}

// ExitCode lets the CLI distinguish invalid policy content from file or YAML
// decoding failures.
func (NativeValidationError) ExitCode() int { return 1 }

// NativeDecodeError represents an input read/decode failure rather than a
// policy that decoded successfully but is outside the supported subset.
type NativeDecodeError struct {
	Document int
	Err      error
}

func (e NativeDecodeError) Error() string {
	if e.Document > 0 {
		return fmt.Sprintf("document %d: %v", e.Document, e.Err)
	}
	return e.Err.Error()
}

func (e NativeDecodeError) Unwrap() error { return e.Err }

// ExitCode lets the CLI map input syntax/read failures to status 2.
func (NativeDecodeError) ExitCode() int { return 2 }

type nativeMetaWire struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type nativeSelectorRequirementWire struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

type nativeSelectorWire struct {
	MatchLabels      map[string]string               `yaml:"matchLabels"`
	MatchExpressions []nativeSelectorRequirementWire `yaml:"matchExpressions"`
}

type nativeIPBlockWire struct {
	CIDR   string   `yaml:"cidr"`
	Except []string `yaml:"except"`
}

type nativePeerWire struct {
	PodSelector       *nativeSelectorWire `yaml:"podSelector"`
	NamespaceSelector *nativeSelectorWire `yaml:"namespaceSelector"`
	IPBlock           *nativeIPBlockWire  `yaml:"ipBlock"`
}

type nativePortWire struct {
	Protocol string    `yaml:"protocol"`
	Port     yaml.Node `yaml:"port"`
	EndPort  yaml.Node `yaml:"endPort"`
}

type nativeIngressRuleWire struct {
	From  []nativePeerWire `yaml:"from"`
	Ports []nativePortWire `yaml:"ports"`
}

type nativeEgressRuleWire struct {
	To    []nativePeerWire `yaml:"to"`
	Ports []nativePortWire `yaml:"ports"`
}

type nativeSpecWire struct {
	PodSelector *nativeSelectorWire     `yaml:"podSelector"`
	PolicyTypes *[]string               `yaml:"policyTypes"`
	Ingress     []nativeIngressRuleWire `yaml:"ingress"`
	Egress      []nativeEgressRuleWire  `yaml:"egress"`
}

type nativePolicyWire struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   *nativeMetaWire `yaml:"metadata"`
	Spec       *nativeSpecWire `yaml:"spec"`
}

type nativeListWire struct {
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   *nativeMetaWire     `yaml:"metadata"`
	Items      *[]nativePolicyWire `yaml:"items"`
}

type nativeHeader struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

// DecodeNativePolicies decodes multi-document YAML and expands
// NetworkPolicyList items. It performs strict structural decoding but leaves
// semantic subset validation to ValidateNativePolicies.
func DecodeNativePolicies(data []byte) ([]NativeNetworkPolicy, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var policies []NativeNetworkPolicy
	document := 0

	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, NativeDecodeError{Document: document + 1, Err: err}
		}

		document++
		if nativeEmptyDocument(&node) {
			continue
		}
		root := node.Content[0]
		if root.Kind != yaml.MappingNode {
			return nil, NativeValidationError{
				Document: document,
				Field:    "document",
				Message:  "must be a Kubernetes object",
			}
		}

		var header nativeHeader
		if err := root.Decode(&header); err != nil {
			return nil, NativeValidationError{
				Document: document,
				Field:    "document",
				Message:  fmt.Sprintf("must be a Kubernetes object: %v", err),
			}
		}

		switch header.Kind {
		case NativeNetworkPolicyKind:
			if err := validateNativeFieldNames(root, "", document, false); err != nil {
				return nil, withNativeNodeContext(err, root, document)
			}
			var wire nativePolicyWire
			if err := decodeNativeNodeStrict(root, &wire); err != nil {
				return nil, classifyNativeDecodeError(document, err)
			}
			policies = append(policies, nativePolicyFromWire(wire, document, ""))
		case NativeNetworkPolicyListKind:
			if err := validateNativeFieldNames(root, "", document, true); err != nil {
				return nil, withNativeNodeContext(err, root, document)
			}
			var wire nativeListWire
			if err := decodeNativeNodeStrict(root, &wire); err != nil {
				return nil, classifyNativeDecodeError(document, err)
			}
			if wire.APIVersion != NativeNetworkPolicyAPIVersion {
				return nil, NativeValidationError{
					Document: document,
					Field:    "apiVersion",
					Message:  "must be networking.k8s.io/v1",
				}
			}
			if wire.Items == nil {
				return nil, NativeValidationError{
					Document: document,
					Field:    "items",
					Message:  "must be provided for NetworkPolicyList",
				}
			}
			for i, item := range *wire.Items {
				if item.APIVersion == "" {
					item.APIVersion = wire.APIVersion
				}
				if item.Kind == "" {
					item.Kind = NativeNetworkPolicyKind
				}
				policies = append(policies, nativePolicyFromWire(item, document, fmt.Sprintf("items[%d].", i)))
			}
		default:
			return nil, NativeValidationError{
				Document: document,
				Field:    "kind",
				Message:  "must be NetworkPolicy or NetworkPolicyList",
			}
		}
	}

	return policies, nil
}

func nativeEmptyDocument(node *yaml.Node) bool {
	if node == nil || len(node.Content) == 0 {
		return true
	}
	root := node.Content[0]
	return nativeNullNode(root) && root.Value == ""
}

func decodeNativeNodeStrict(node *yaml.Node, target any) error {
	// validateNativeFieldNames already rejects unknown and duplicate fields with
	// stable paths. Decode without KnownFields so standard Kubernetes metadata
	// fields that are valid but irrelevant to compilation can be ignored here.
	return node.Decode(target)
}

func classifyNativeDecodeError(document int, err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		return NativeValidationError{
			Document: document,
			Field:    "document",
			Message:  fmt.Sprintf("invalid fields: %v", err),
		}
	}
	return NativeDecodeError{Document: document, Err: err}
}

type nativeFieldCheck func(node *yaml.Node, field string, document int) error

func validateNativeFieldNames(node *yaml.Node, field string, document int, list bool) error {
	policyFields := nativePolicyFieldChecks()
	if list {
		return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
			"apiVersion": stringNativeField,
			"kind":       stringNativeField,
			"metadata":   mappingNativeField(nativeListMetadataFieldChecks()),
			"items": sequenceNativeField(func(item *yaml.Node, itemField string, itemDocument int) error {
				return validateNativeMapping(item, itemField, itemDocument, policyFields)
			}),
		})
	}
	return validateNativeMapping(node, field, document, policyFields)
}

func nativePolicyFieldChecks() map[string]nativeFieldCheck {
	return map[string]nativeFieldCheck{
		"apiVersion": stringNativeField,
		"kind":       stringNativeField,
		"metadata":   mappingNativeField(nativeMetadataFieldChecks()),
		"spec": mappingNativeField(map[string]nativeFieldCheck{
			"podSelector": mappingNativeField(nativeSelectorFieldChecks()),
			"policyTypes": sequenceNativeField(stringNativeField),
			"ingress": sequenceNativeField(func(node *yaml.Node, field string, document int) error {
				return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
					"from":  sequenceNativeField(nativePeerFieldCheck),
					"ports": sequenceNativeField(nativePortFieldCheck),
				})
			}),
			"egress": sequenceNativeField(func(node *yaml.Node, field string, document int) error {
				return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
					"to":    sequenceNativeField(nativePeerFieldCheck),
					"ports": sequenceNativeField(nativePortFieldCheck),
				})
			}),
		}),
	}
}

func nativeMetadataFieldChecks() map[string]nativeFieldCheck {
	return map[string]nativeFieldCheck{
		"name":                       optionalStringNativeField,
		"generateName":               optionalStringNativeField,
		"namespace":                  optionalStringNativeField,
		"selfLink":                   optionalStringNativeField,
		"uid":                        optionalStringNativeField,
		"resourceVersion":            optionalStringNativeField,
		"generation":                 optionalIntegerNativeField,
		"creationTimestamp":          timestampNativeField,
		"deletionTimestamp":          timestampNativeField,
		"deletionGracePeriodSeconds": optionalIntegerNativeField,
		"labels":                     stringMapNativeField,
		"annotations":                stringMapNativeField,
		"ownerReferences": sequenceNativeField(func(node *yaml.Node, field string, document int) error {
			return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
				"apiVersion":         stringNativeField,
				"kind":               stringNativeField,
				"name":               stringNativeField,
				"uid":                stringNativeField,
				"controller":         optionalBooleanNativeField,
				"blockOwnerDeletion": optionalBooleanNativeField,
			})
		}),
		"finalizers": sequenceNativeField(stringNativeField),
		"managedFields": sequenceNativeField(func(node *yaml.Node, field string, document int) error {
			return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
				"manager":     optionalStringNativeField,
				"operation":   optionalStringNativeField,
				"apiVersion":  optionalStringNativeField,
				"time":        timestampNativeField,
				"fieldsType":  optionalStringNativeField,
				"fieldsV1":    mapNativeField,
				"subresource": optionalStringNativeField,
			})
		}),
	}
}

func nativeListMetadataFieldChecks() map[string]nativeFieldCheck {
	return map[string]nativeFieldCheck{
		"selfLink":           optionalStringNativeField,
		"resourceVersion":    optionalStringNativeField,
		"continue":           optionalStringNativeField,
		"remainingItemCount": optionalIntegerNativeField,
		"shardInfo": mappingNativeField(map[string]nativeFieldCheck{
			"selector": stringNativeField,
		}),
	}
}

func nativeSelectorFieldChecks() map[string]nativeFieldCheck {
	return map[string]nativeFieldCheck{
		"matchLabels": stringMapNativeField,
		"matchExpressions": sequenceNativeField(func(node *yaml.Node, field string, document int) error {
			return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
				"key":      stringNativeField,
				"operator": stringNativeField,
				"values":   sequenceNativeField(stringNativeField),
			})
		}),
	}
}

func nativePeerFieldCheck(node *yaml.Node, field string, document int) error {
	return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
		"podSelector":       mappingNativeField(nativeSelectorFieldChecks()),
		"namespaceSelector": mappingNativeField(nativeSelectorFieldChecks()),
		"ipBlock": mappingNativeField(map[string]nativeFieldCheck{
			"cidr":   stringNativeField,
			"except": sequenceNativeField(stringNativeField),
		}),
	})
}

func nativePortFieldCheck(node *yaml.Node, field string, document int) error {
	return validateNativeMapping(node, field, document, map[string]nativeFieldCheck{
		"protocol": optionalStringNativeField,
		"port":     portValueNativeField,
		"endPort":  optionalIntegerNativeField,
	})
}

func validateNativeMapping(node *yaml.Node, field string, document int, checks map[string]nativeFieldCheck) error {
	if node.Kind != yaml.MappingNode {
		return nativeShapeError(document, field, "must be an object")
	}
	seen := make(map[string]struct{}, len(checks))
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return nativeShapeError(document, field, "field names must be strings")
		}
		key := keyNode.Value
		childField := key
		if field != "" {
			childField = field + "." + key
		}
		if _, exists := seen[key]; exists {
			return nativeShapeError(document, childField, "duplicate field")
		}
		seen[key] = struct{}{}
		check, ok := checks[key]
		if !ok {
			return nativeShapeError(document, childField, "unknown field")
		}
		if check != nil {
			if err := check(valueNode, childField, document); err != nil {
				return err
			}
		}
	}
	return nil
}

func stringNativeField(node *yaml.Node, field string, document int) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return nativeShapeError(document, field, "must be a string")
	}
	return nil
}

func optionalStringNativeField(node *yaml.Node, field string, document int) error {
	if nativeNullNode(node) {
		return nil
	}
	return stringNativeField(node, field, document)
}

func optionalIntegerNativeField(node *yaml.Node, field string, document int) error {
	if nativeNullNode(node) {
		return nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
		return nativeShapeError(document, field, "must be an integer")
	}
	return nil
}

func optionalBooleanNativeField(node *yaml.Node, field string, document int) error {
	if nativeNullNode(node) {
		return nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return nativeShapeError(document, field, "must be a boolean")
	}
	return nil
}

func timestampNativeField(node *yaml.Node, field string, document int) error {
	if nativeNullNode(node) {
		return nil
	}
	if node.Kind != yaml.ScalarNode || (node.Tag != "!!str" && node.Tag != "!!timestamp") {
		return nativeShapeError(document, field, "must be an RFC 3339 timestamp")
	}
	return nil
}

func portValueNativeField(node *yaml.Node, field string, document int) error {
	if node.Kind != yaml.ScalarNode || (node.Tag != "!!int" && node.Tag != "!!str" && !nativeNullNode(node)) {
		return nativeShapeError(document, field, "must be an integer or string")
	}
	return nil
}

func mapNativeField(node *yaml.Node, field string, document int) error {
	if node.Kind != yaml.MappingNode && !nativeNullNode(node) {
		return nativeShapeError(document, field, "must be an object")
	}
	return nil
}

func stringMapNativeField(node *yaml.Node, field string, document int) error {
	if nativeNullNode(node) {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return nativeShapeError(document, field, "must be an object")
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nativeShapeError(document, field, "keys must be strings")
		}
		childField := field + "." + key.Value
		if _, exists := seen[key.Value]; exists {
			return nativeShapeError(document, childField, "duplicate field")
		}
		seen[key.Value] = struct{}{}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return nativeShapeError(document, childField, "must be a string")
		}
	}
	return nil
}

func mappingNativeField(checks map[string]nativeFieldCheck) nativeFieldCheck {
	return func(node *yaml.Node, field string, document int) error {
		if nativeNullNode(node) {
			return nil
		}
		return validateNativeMapping(node, field, document, checks)
	}
}

func sequenceNativeField(itemCheck nativeFieldCheck) nativeFieldCheck {
	return func(node *yaml.Node, field string, document int) error {
		if nativeNullNode(node) {
			return nil
		}
		if node.Kind != yaml.SequenceNode {
			return nativeShapeError(document, field, "must be a list")
		}
		for i, item := range node.Content {
			if itemCheck != nil {
				if err := itemCheck(item, fmt.Sprintf("%s[%d]", field, i), document); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func nativeNullNode(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

func nativeShapeError(document int, field, message string) NativeValidationError {
	return NativeValidationError{Document: document, Field: field, Message: message}
}

func withNativeNodeContext(err error, root *yaml.Node, document int) error {
	var validationErr NativeValidationError
	if !errors.As(err, &validationErr) {
		return err
	}
	validationErr.Document = document
	contextRoot := nativePolicyContextRoot(root, validationErr.Field)
	var envelope struct {
		Metadata *nativeMetaWire `yaml:"metadata"`
	}
	if contextRoot != nil {
		if decodeErr := contextRoot.Decode(&envelope); decodeErr == nil && envelope.Metadata != nil {
			validationErr.Namespace = envelope.Metadata.Namespace
			validationErr.Name = envelope.Metadata.Name
		}
	}
	return validationErr
}

func nativePolicyContextRoot(root *yaml.Node, field string) *yaml.Node {
	if root == nil || !strings.HasPrefix(field, "items[") {
		return root
	}
	end := strings.IndexByte(field, ']')
	if end < len("items[") {
		return root
	}
	index, err := strconv.Atoi(field[len("items["):end])
	if err != nil || index < 0 || root.Kind != yaml.MappingNode {
		return root
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "items" {
			continue
		}
		items := root.Content[i+1]
		if items.Kind == yaml.SequenceNode && index < len(items.Content) {
			return items.Content[index]
		}
		break
	}
	return root
}

func nativePolicyFromWire(w nativePolicyWire, document int, prefix string) NativeNetworkPolicy {
	policy := NativeNetworkPolicy{
		APIVersion:     w.APIVersion,
		Kind:           w.Kind,
		SourceDocument: document,
		FieldPrefix:    prefix,
	}
	if w.Metadata != nil {
		policy.Metadata = &NativeObjectMeta{
			Name:        w.Metadata.Name,
			Namespace:   w.Metadata.Namespace,
			Labels:      w.Metadata.Labels,
			Annotations: w.Metadata.Annotations,
		}
	}
	if w.Spec != nil {
		policy.Spec = &NativeNetworkPolicySpec{
			PolicyTypes: w.Spec.PolicyTypes,
			Ingress:     make([]NativeIngressRule, 0, len(w.Spec.Ingress)),
			Egress:      make([]NativeEgressRule, 0, len(w.Spec.Egress)),
		}
		if w.Spec.PodSelector != nil {
			policy.Spec.PodSelector = nativeSelectorFromWire(w.Spec.PodSelector)
		}
		for _, rule := range w.Spec.Ingress {
			converted := NativeIngressRule{From: make([]NativePeer, 0, len(rule.From)), Ports: make([]NativePort, 0, len(rule.Ports))}
			for _, peer := range rule.From {
				converted.From = append(converted.From, nativePeerFromWire(peer))
			}
			for _, port := range rule.Ports {
				converted.Ports = append(converted.Ports, nativePortFromWire(port))
			}
			policy.Spec.Ingress = append(policy.Spec.Ingress, converted)
		}
		for _, rule := range w.Spec.Egress {
			converted := NativeEgressRule{To: make([]NativePeer, 0, len(rule.To)), Ports: make([]NativePort, 0, len(rule.Ports))}
			for _, peer := range rule.To {
				converted.To = append(converted.To, nativePeerFromWire(peer))
			}
			for _, port := range rule.Ports {
				converted.Ports = append(converted.Ports, nativePortFromWire(port))
			}
			policy.Spec.Egress = append(policy.Spec.Egress, converted)
		}
	}
	return policy
}

func nativeSelectorFromWire(selector *nativeSelectorWire) *NativeLabelSelector {
	if selector == nil {
		return nil
	}
	result := &NativeLabelSelector{
		MatchLabels:      selector.MatchLabels,
		MatchExpressions: make([]NativeLabelSelectorRequirement, 0, len(selector.MatchExpressions)),
	}
	for _, expr := range selector.MatchExpressions {
		result.MatchExpressions = append(result.MatchExpressions, NativeLabelSelectorRequirement(expr))
	}
	return result
}

func nativePeerFromWire(peer nativePeerWire) NativePeer {
	return NativePeer{
		PodSelector:       nativeSelectorFromWire(peer.PodSelector),
		NamespaceSelector: nativeSelectorFromWire(peer.NamespaceSelector),
		IPBlock: func() *NativeIPBlock {
			if peer.IPBlock == nil {
				return nil
			}
			return &NativeIPBlock{CIDR: peer.IPBlock.CIDR, Except: peer.IPBlock.Except}
		}(),
	}
}

func nativePortFromWire(port nativePortWire) NativePort {
	protocol := port.Protocol
	if protocol == "" {
		protocol = "TCP"
	}
	value, name := nativePortValue(port.Port)
	return NativePort{Protocol: protocol, Port: value, PortName: name, HasEndPort: port.EndPort.Kind != 0 && !nativeNullNode(&port.EndPort)}
}

func nativePortValue(node yaml.Node) (int, string) {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
		if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
			return 0, strings.TrimSpace(node.Value)
		}
		return 0, ""
	}
	var value int64
	err := node.Decode(&value)
	if err != nil || value < 1 || value > 65535 {
		return 0, ""
	}
	return int(value), ""
}

// LoadNativePoliciesFromBytes decodes and validates every native policy in a
// byte slice. It requires at least one NetworkPolicy object.
func LoadNativePoliciesFromBytes(data []byte) ([]NativeNetworkPolicy, error) {
	policies, err := DecodeNativePolicies(data)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, NativeValidationError{Document: 1, Field: "document", Message: "contains no NetworkPolicy objects"}
	}
	if err := ValidateNativePolicies(policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// ValidateNativePolicies validates a decoded set in source order.
func ValidateNativePolicies(policies []NativeNetworkPolicy) error {
	for i := range policies {
		if err := validateNativePolicy(&policies[i]); err != nil {
			return err
		}
	}
	return nil
}

// ValidateNativePolicy validates one native policy constructed in Go. Source
// context is optional; decoded file policies retain their document context.
func ValidateNativePolicy(policy *NativeNetworkPolicy) error {
	return validateNativePolicy(policy)
}

func validateNativePolicy(policy *NativeNetworkPolicy) error {
	if policy == nil {
		return NativeValidationError{Document: 1, Field: "document", Message: "must not be nil"}
	}
	document := policy.SourceDocument
	if document <= 0 {
		document = 1
	}
	meta := policy.Metadata
	namespace := "default"
	name := ""
	if meta != nil {
		name = meta.Name
		if meta.Namespace != "" {
			namespace = meta.Namespace
		}
	}
	field := func(path string) string {
		return policy.FieldPrefix + path
	}
	invalid := func(path, message string) error {
		return NativeValidationError{Document: document, Namespace: namespace, Name: name, Field: field(path), Message: message}
	}

	if policy.APIVersion != NativeNetworkPolicyAPIVersion {
		return invalid("apiVersion", "must be networking.k8s.io/v1")
	}
	if policy.Kind != NativeNetworkPolicyKind {
		return invalid("kind", "must be NetworkPolicy")
	}
	if meta == nil {
		return invalid("metadata", "must be provided")
	}
	if strings.TrimSpace(meta.Name) == "" {
		return invalid("metadata.name", "must be provided")
	}
	if errs := utilvalidation.IsDNS1123Subdomain(meta.Name); len(errs) > 0 {
		return invalid("metadata.name", "must be a valid DNS-1123 subdomain")
	}
	if meta.Namespace != "" {
		if errs := utilvalidation.IsDNS1123Label(meta.Namespace); len(errs) > 0 {
			return invalid("metadata.namespace", "must be a valid DNS-1123 label")
		}
	}
	for _, key := range sortedNativeMapKeys(meta.Labels) {
		path := fmt.Sprintf("metadata.labels[%q]", key)
		if errs := utilvalidation.IsQualifiedName(key); len(errs) > 0 {
			return invalid(path, "key must be a valid Kubernetes qualified name")
		}
		if errs := utilvalidation.IsValidLabelValue(meta.Labels[key]); len(errs) > 0 {
			return invalid(path, "value must be a valid Kubernetes label value")
		}
	}
	annotationSize := 0
	for _, key := range sortedNativeMapKeys(meta.Annotations) {
		path := fmt.Sprintf("metadata.annotations[%q]", key)
		if errs := utilvalidation.IsQualifiedName(strings.ToLower(key)); len(errs) > 0 {
			return invalid(path, "key must be a valid Kubernetes qualified name")
		}
		annotationSize += len(key) + len(meta.Annotations[key])
	}
	if annotationSize > maxNativeAnnotationsSize {
		return invalid("metadata.annotations", fmt.Sprintf("must not exceed %d total bytes", maxNativeAnnotationsSize))
	}
	if policy.Spec == nil {
		return invalid("spec", "must be provided")
	}
	if policy.Spec.PodSelector == nil {
		return invalid("spec.podSelector", "must be provided")
	}
	if err := validateNativeSelector(policy.Spec.PodSelector, field("spec.podSelector")); err != nil {
		return withNativeContext(err, document, namespace, name)
	}

	if policy.Spec.PolicyTypes != nil {
		if len(*policy.Spec.PolicyTypes) == 0 {
			return invalid("spec.policyTypes", "must include Ingress or Egress when provided")
		}
		seen := make(map[string]struct{}, len(*policy.Spec.PolicyTypes))
		for i, policyType := range *policy.Spec.PolicyTypes {
			path := field(fmt.Sprintf("spec.policyTypes[%d]", i))
			if policyType != "Ingress" && policyType != "Egress" {
				return NativeValidationError{Document: document, Namespace: namespace, Name: name, Field: path, Message: "must be Ingress or Egress"}
			}
			if _, ok := seen[policyType]; ok {
				return NativeValidationError{Document: document, Namespace: namespace, Name: name, Field: path, Message: "must not contain duplicates"}
			}
			seen[policyType] = struct{}{}
		}
		if len(policy.Spec.Ingress) > 0 {
			if _, ok := seen["Ingress"]; !ok {
				return invalid("spec.policyTypes", "must include Ingress when ingress rules are present")
			}
		}
		if len(policy.Spec.Egress) > 0 {
			if _, ok := seen["Egress"]; !ok {
				return invalid("spec.policyTypes", "must include Egress when egress rules are present")
			}
		}
	}

	for i, rule := range policy.Spec.Ingress {
		if len(rule.From) == 0 {
			return invalid(fmt.Sprintf("spec.ingress[%d].from", i), "must include at least one explicit peer")
		}
		if len(rule.Ports) == 0 {
			return invalid(fmt.Sprintf("spec.ingress[%d].ports", i), "must include at least one explicit numeric port")
		}
		for j, peer := range rule.From {
			if err := validateNativePeer(peer, field(fmt.Sprintf("spec.ingress[%d].from[%d]", i, j))); err != nil {
				return withNativeContext(err, document, namespace, name)
			}
		}
		for j, port := range rule.Ports {
			if err := validateNativePort(port, field(fmt.Sprintf("spec.ingress[%d].ports[%d]", i, j))); err != nil {
				return withNativeContext(err, document, namespace, name)
			}
		}
	}
	for i, rule := range policy.Spec.Egress {
		if len(rule.To) == 0 {
			return invalid(fmt.Sprintf("spec.egress[%d].to", i), "must include at least one explicit peer")
		}
		if len(rule.Ports) == 0 {
			return invalid(fmt.Sprintf("spec.egress[%d].ports", i), "must include at least one explicit numeric port")
		}
		for j, peer := range rule.To {
			if err := validateNativePeer(peer, field(fmt.Sprintf("spec.egress[%d].to[%d]", i, j))); err != nil {
				return withNativeContext(err, document, namespace, name)
			}
		}
		for j, port := range rule.Ports {
			if err := validateNativePort(port, field(fmt.Sprintf("spec.egress[%d].ports[%d]", i, j))); err != nil {
				return withNativeContext(err, document, namespace, name)
			}
		}
	}

	return nil
}

func sortedNativeMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func withNativeContext(err error, document int, namespace, name string) error {
	var validationErr NativeValidationError
	if errors.As(err, &validationErr) {
		if validationErr.Document <= 0 {
			validationErr.Document = document
		}
		if validationErr.Namespace == "" {
			validationErr.Namespace = namespace
		}
		if validationErr.Name == "" {
			validationErr.Name = name
		}
		return validationErr
	}
	return err
}

func validateNativeSelector(selector *NativeLabelSelector, field string) error {
	if selector == nil {
		return NativeValidationError{Field: field, Message: "must be provided"}
	}
	metav1Selector := &metav1.LabelSelector{
		MatchLabels: selector.MatchLabels,
		MatchExpressions: func() []metav1.LabelSelectorRequirement {
			requirements := make([]metav1.LabelSelectorRequirement, 0, len(selector.MatchExpressions))
			for _, expression := range selector.MatchExpressions {
				requirements = append(requirements, metav1.LabelSelectorRequirement{
					Key: expression.Key, Operator: metav1.LabelSelectorOperator(expression.Operator), Values: expression.Values,
				})
			}
			return requirements
		}(),
	}
	if _, err := metav1.LabelSelectorAsSelector(metav1Selector); err != nil {
		return NativeValidationError{Field: field, Message: fmt.Sprintf("invalid selector: %v", err)}
	}
	return nil
}

func validateNativePeer(peer NativePeer, field string) error {
	hasPod := peer.PodSelector != nil
	hasNamespace := peer.NamespaceSelector != nil
	hasIPBlock := peer.IPBlock != nil
	if !hasPod && !hasNamespace && !hasIPBlock {
		return NativeValidationError{Field: field, Message: "must specify podSelector, namespaceSelector, or ipBlock"}
	}
	if hasIPBlock && (hasPod || hasNamespace) {
		return NativeValidationError{Field: field, Message: "ipBlock cannot be combined with selectors"}
	}
	if hasPod {
		if err := validateNativeSelector(peer.PodSelector, field+".podSelector"); err != nil {
			return err
		}
	}
	if hasNamespace {
		if err := validateNativeSelector(peer.NamespaceSelector, field+".namespaceSelector"); err != nil {
			return err
		}
	}
	if hasIPBlock {
		if _, err := ExpandNativeIPBlock(*peer.IPBlock); err != nil {
			return NativeValidationError{Field: field + ".ipBlock", Message: err.Error()}
		}
	}
	return nil
}

func validateNativePort(port NativePort, field string) error {
	if port.Protocol != "TCP" && port.Protocol != "UDP" {
		return NativeValidationError{Field: field + ".protocol", Message: "must be TCP or UDP"}
	}
	if strings.TrimSpace(port.PortName) != "" {
		return NativeValidationError{Field: field + ".port", Message: "named ports are not supported in v0.1.0"}
	}
	if port.HasEndPort {
		return NativeValidationError{Field: field + ".endPort", Message: "endPort is not supported in v0.1.0"}
	}
	if port.Port < 1 || port.Port > 65535 {
		return NativeValidationError{Field: field + ".port", Message: "must be between 1 and 65535"}
	}
	return nil
}

// ExpandNativeIPBlock normalizes an IPv4 ipBlock and subtracts its except
// prefixes. The returned prefixes are sorted and deduplicated.
func ExpandNativeIPBlock(block NativeIPBlock) ([]netip.Prefix, error) {
	base, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %v", err)
	}
	base = base.Masked()
	if !base.Addr().Is4() {
		return nil, errors.New("only IPv4 CIDRs are supported")
	}

	type addressRange struct {
		start uint64
		end   uint64
	}

	excluded := make([]addressRange, 0, len(block.Except))
	for i, rawExcept := range block.Except {
		except, err := netip.ParsePrefix(rawExcept)
		if err != nil {
			return nil, fmt.Errorf("except[%d] is invalid: %v", i, err)
		}
		except = except.Masked()
		if !except.Addr().Is4() {
			return nil, fmt.Errorf("except[%d] must be IPv4", i)
		}
		if !prefixContainsPrefix(base, except) {
			return nil, fmt.Errorf("except[%d] must be within cidr", i)
		}
		if except.Bits() < base.Bits() {
			return nil, fmt.Errorf("except[%d] must be within cidr", i)
		}
		start, end := nativePrefixRange(except)
		excluded = append(excluded, addressRange{start: start, end: end})
	}

	sort.Slice(excluded, func(i, j int) bool {
		if excluded[i].start != excluded[j].start {
			return excluded[i].start < excluded[j].start
		}
		return excluded[i].end < excluded[j].end
	})
	merged := make([]addressRange, 0, len(excluded))
	for _, current := range excluded {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end+1 {
			merged = append(merged, current)
			continue
		}
		if current.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = current.end
		}
	}

	baseStart, baseEnd := nativePrefixRange(base)
	prefixes := make([]netip.Prefix, 0)
	cursor := baseStart
	for _, current := range merged {
		if cursor < current.start {
			if err := appendNativeRangePrefixes(&prefixes, cursor, current.start-1); err != nil {
				return nil, err
			}
		}
		if current.end == baseEnd {
			cursor = baseEnd + 1
			break
		}
		cursor = current.end + 1
	}
	if cursor <= baseEnd {
		if err := appendNativeRangePrefixes(&prefixes, cursor, baseEnd); err != nil {
			return nil, err
		}
	}

	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	return prefixes, nil
}

func prefixContainsPrefix(container, candidate netip.Prefix) bool {
	return container.Bits() <= candidate.Bits() && container.Contains(candidate.Addr())
}

func nativePrefixRange(prefix netip.Prefix) (uint64, uint64) {
	address := prefix.Masked().Addr().As4()
	start := uint64(uint32(address[0])<<24 | uint32(address[1])<<16 | uint32(address[2])<<8 | uint32(address[3]))
	size := uint64(1) << uint64(32-prefix.Bits())
	return start, start + size - 1
}

func appendNativeRangePrefixes(prefixes *[]netip.Prefix, start, end uint64) error {
	for start <= end {
		alignment := start & -start
		if start == 0 {
			alignment = uint64(1) << 32
		}
		remaining := end - start + 1
		largestRemaining := uint64(1) << uint(bits.Len64(remaining)-1)
		size := alignment
		if largestRemaining < size {
			size = largestRemaining
		}
		prefixBits := 32 - (bits.Len64(size) - 1)
		value := uint32(start)
		address := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
		*prefixes = append(*prefixes, netip.PrefixFrom(address, prefixBits))
		if len(*prefixes) > MaxIPBlockExpansion {
			return fmt.Errorf("except expansion exceeds %d prefixes", MaxIPBlockExpansion)
		}
		start += size
	}
	return nil
}
