package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// MaxPolicySubjects and MaxPolicyRules are the v0.1.0 active-slot limits.
	MaxPolicySubjects = 16_384
	MaxPolicyRules    = 16_384

	// ProtocolTCP and ProtocolUDP are the IP protocol numbers carried by Rule.
	ProtocolTCP uint8 = 6
	ProtocolUDP uint8 = 17
)

// Direction is a bit mask of independently isolated traffic directions.
type Direction uint8

const (
	DirectionEgress Direction = 1 << iota
	DirectionIngress
)

const allDirections = DirectionEgress | DirectionIngress

// Subject is the kernel-neutral state for one selected container cgroup.
type Subject struct {
	CgroupID    uint64
	Isolated    Direction
	Quarantined Direction
	PodIPs      []netip.Addr
}

// Rule is one normalized IPv4 peer, protocol, and destination-port allow.
type Rule struct {
	CgroupID  uint64
	Direction Direction
	Peer      netip.Prefix
	Protocol  uint8
	Port      uint16
}

// PolicySet is the complete candidate passed to the enforcement engine.
// Kubernetes objects intentionally do not cross this boundary.
type PolicySet struct {
	NodeIPs  []netip.Addr
	Subjects []Subject
	Rules    []Rule
}

// ResolvedNamespace is the immutable namespace fact needed for peer matching.
type ResolvedNamespace struct {
	Name   string
	Labels map[string]string
}

// CgroupResolutionFailure is a bounded reason why a running local pod could
// not be mapped to every container cgroup in the caller-owned snapshot. The
// zero value means there was no resolution failure; a pod may still have no
// cgroup IDs while its containers are pending.
type CgroupResolutionFailure uint8

const (
	CgroupResolutionFailureNone CgroupResolutionFailure = iota
	CgroupResolutionFailureNotFound
	CgroupResolutionFailureUnsupportedRuntime
)

// ResolvedPod contains only the pod facts needed by policy compilation. Pods
// from the whole cluster participate in peer resolution; Local identifies pods
// scheduled to this node, whose resolved cgroups can become subjects.
type ResolvedPod struct {
	Namespace               string
	Name                    string
	Labels                  map[string]string
	PodIPs                  []netip.Addr
	CgroupIDs               []uint64
	CgroupResolutionFailure CgroupResolutionFailure
	Local                   bool
	HostNetwork             bool
}

// ResolutionInput is a point-in-time, kernel-neutral snapshot prepared by the
// Kubernetes layer. The compiler reads but never mutates it.
type ResolutionInput struct {
	NodeIPs    []netip.Addr
	Namespaces []ResolvedNamespace
	Pods       []ResolvedPod
}

// RejectedPolicy is a stable diagnostic for a policy excluded from ordinary
// rule compilation. Selected local subjects are quarantined independently.
type RejectedPolicy struct {
	Document   int
	Namespace  string
	Name       string
	Generation int64
	Field      string
	Message    string
}

// CompileResult contains a complete candidate plus bounded policy diagnostics.
type CompileResult struct {
	PolicySet PolicySet
	Rejected  []RejectedPolicy
}

// CapacityError reports a node-local aggregate that cannot fit in one slot.
type CapacityError struct {
	Resource string
	Observed int
	Allowed  int
}

func (e CapacityError) Error() string {
	return fmt.Sprintf("%s capacity exceeded: observed %d, allowed %d", e.Resource, e.Observed, e.Allowed)
}

// ResolutionError reports malformed or ambiguous immutable input.
type ResolutionError struct {
	Field   string
	Message string
}

func (e ResolutionError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type subjectState struct {
	subject Subject
	podKey  string
}

type compileState struct {
	input      ResolutionInput
	namespaces map[string]map[string]string
	subjects   map[uint64]*subjectState
	rules      map[Rule]struct{}
	bypasses   int
	rejected   []RejectedPolicy
}

// CompileNativePolicies validates and compiles native NetworkPolicies. A
// rejected policy quarantines only the local subjects and directions it can
// select; accepted policies continue contributing additive state.
func CompileNativePolicies(policies []NativeNetworkPolicy, input ResolutionInput) (CompileResult, error) {
	normalized, namespaces, err := normalizeResolutionInput(input)
	if err != nil {
		return CompileResult{}, err
	}

	state := compileState{
		input:      normalized,
		namespaces: namespaces,
		subjects:   make(map[uint64]*subjectState),
		rules:      make(map[Rule]struct{}),
		bypasses:   len(normalized.NodeIPs),
	}
	if observed := state.ruleEntryCount(); observed > MaxPolicyRules {
		return CompileResult{}, CapacityError{Resource: "rule", Observed: observed, Allowed: MaxPolicyRules}
	}

	ordered := append([]NativeNetworkPolicy(nil), policies...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return nativePolicySortKey(ordered[i]) < nativePolicySortKey(ordered[j])
	})

	for i := range ordered {
		if err := state.compilePolicy(&ordered[i]); err != nil {
			return CompileResult{}, err
		}
	}

	set := state.policySet()
	if err := ValidatePolicySet(set); err != nil {
		return CompileResult{}, err
	}

	sort.Slice(state.rejected, func(i, j int) bool {
		left, right := state.rejected[i], state.rejected[j]
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Document != right.Document {
			return left.Document < right.Document
		}
		return left.Field < right.Field
	})
	return CompileResult{PolicySet: set, Rejected: state.rejected}, nil
}

func normalizeResolutionInput(input ResolutionInput) (ResolutionInput, map[string]map[string]string, error) {
	normalized := ResolutionInput{
		NodeIPs:    make([]netip.Addr, 0, len(input.NodeIPs)),
		Namespaces: append([]ResolvedNamespace(nil), input.Namespaces...),
		Pods:       append([]ResolvedPod(nil), input.Pods...),
	}
	for i, address := range input.NodeIPs {
		if !address.IsValid() {
			return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("nodeIPs[%d]", i), Message: "must be a valid IP address"}
		}
		address = address.Unmap()
		if address.Is4() {
			normalized.NodeIPs = append(normalized.NodeIPs, address)
		}
	}
	normalized.NodeIPs = uniqueSortedAddrs(normalized.NodeIPs)
	if len(normalized.NodeIPs) == 0 {
		return ResolutionInput{}, nil, ResolutionError{Field: "nodeIPs", Message: "must contain at least one IPv4 Node address"}
	}

	namespaces := make(map[string]map[string]string, len(normalized.Namespaces))
	for i := range normalized.Namespaces {
		namespace := &normalized.Namespaces[i]
		if strings.TrimSpace(namespace.Name) == "" {
			return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("namespaces[%d].name", i), Message: "must not be empty"}
		}
		if previous, exists := namespaces[namespace.Name]; exists && !labels.Equals(labels.Set(previous), labels.Set(namespace.Labels)) {
			return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("namespaces[%q]", namespace.Name), Message: "has conflicting duplicate entries"}
		}
		namespaces[namespace.Name] = cloneLabels(namespace.Labels)
		namespace.Labels = cloneLabels(namespace.Labels)
	}

	podKeys := make(map[string]struct{}, len(normalized.Pods))
	cgroups := make(map[uint64]string)
	for i := range normalized.Pods {
		pod := &normalized.Pods[i]
		if pod.Namespace == "" {
			pod.Namespace = "default"
		}
		if strings.TrimSpace(pod.Name) == "" {
			return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("pods[%d].name", i), Message: "must not be empty"}
		}
		key := pod.Namespace + "/" + pod.Name
		if _, exists := namespaces[pod.Namespace]; !exists {
			return ResolutionInput{}, nil, ResolutionError{
				Field:   fmt.Sprintf("pods[%q].namespace", key),
				Message: "has no matching namespace entry",
			}
		}
		if _, exists := podKeys[key]; exists {
			return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("pods[%q]", key), Message: "has a duplicate entry"}
		}
		podKeys[key] = struct{}{}
		pod.Labels = cloneLabels(pod.Labels)
		pod.PodIPs = append([]netip.Addr(nil), pod.PodIPs...)
		for j, address := range pod.PodIPs {
			if !address.IsValid() {
				return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("pods[%q].podIPs[%d]", key, j), Message: "must be a valid IP address"}
			}
			pod.PodIPs[j] = address.Unmap()
		}
		pod.PodIPs = uniqueSortedAddrs(pod.PodIPs)
		pod.CgroupIDs = uniqueSortedUint64(pod.CgroupIDs)
		if pod.CgroupResolutionFailure > CgroupResolutionFailureUnsupportedRuntime {
			return ResolutionInput{}, nil, ResolutionError{
				Field:   fmt.Sprintf("pods[%q].cgroupResolutionFailure", key),
				Message: "has an unknown value",
			}
		}
		for j, cgroupID := range pod.CgroupIDs {
			if cgroupID == 0 {
				return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("pods[%q].cgroupIDs[%d]", key, j), Message: "must be non-zero"}
			}
			if owner, exists := cgroups[cgroupID]; exists && owner != key {
				return ResolutionInput{}, nil, ResolutionError{Field: fmt.Sprintf("pods[%q].cgroupIDs[%d]", key, j), Message: "is already owned by " + owner}
			}
			cgroups[cgroupID] = key
		}
	}
	sort.Slice(normalized.Pods, func(i, j int) bool {
		return podKey(normalized.Pods[i]) < podKey(normalized.Pods[j])
	})
	return normalized, namespaces, nil
}

func (s *compileState) compilePolicy(policy *NativeNetworkPolicy) error {
	directions := nativePolicyDirections(policy)
	selected, selectorErr := s.selectedLocalPods(policy)
	validationErr := ValidateNativePolicy(policy)
	if validationErr == nil && selectorErr != nil {
		validationErr = selectorErr
	}
	if validationErr != nil {
		if selectorErr != nil {
			selected = s.localPodsInNamespace(nativePolicyNamespace(policy))
		}
		s.addRejected(policy, validationErr)
		return s.addSelectedSubjects(selected, directions, directions)
	}

	for _, pod := range selected {
		quarantined := Direction(0)
		if podHasIPv6(pod) {
			quarantined = directions
		}
		if err := s.addSelectedSubjects([]ResolvedPod{pod}, directions, quarantined); err != nil {
			return err
		}
	}

	if directions&DirectionIngress != 0 {
		for _, rule := range policy.Spec.Ingress {
			if err := s.addRules(policy, selected, DirectionIngress, rule.From, rule.Ports); err != nil {
				return err
			}
		}
	}
	if directions&DirectionEgress != 0 {
		for _, rule := range policy.Spec.Egress {
			if err := s.addRules(policy, selected, DirectionEgress, rule.To, rule.Ports); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *compileState) selectedLocalPods(policy *NativeNetworkPolicy) ([]ResolvedPod, error) {
	if policy == nil || policy.Spec == nil || policy.Spec.PodSelector == nil {
		return nil, errors.New("subject selector is unavailable")
	}
	selector, err := selectorForNative(policy.Spec.PodSelector)
	if err != nil {
		return nil, err
	}
	namespace := nativePolicyNamespace(policy)
	selected := make([]ResolvedPod, 0)
	for _, pod := range s.input.Pods {
		if !pod.Local || pod.HostNetwork || pod.Namespace != namespace {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			selected = append(selected, pod)
		}
	}
	return selected, nil
}

func (s *compileState) localPodsInNamespace(namespace string) []ResolvedPod {
	result := make([]ResolvedPod, 0)
	for _, pod := range s.input.Pods {
		if pod.Local && !pod.HostNetwork && pod.Namespace == namespace {
			result = append(result, pod)
		}
	}
	return result
}

func (s *compileState) addSelectedSubjects(pods []ResolvedPod, isolated, quarantined Direction) error {
	for _, pod := range pods {
		switch pod.CgroupResolutionFailure {
		case CgroupResolutionFailureNone:
		case CgroupResolutionFailureNotFound:
			return ResolutionError{
				Field:   fmt.Sprintf("pods[%q].cgroupIDs", podKey(pod)),
				Message: "contains a running container whose cgroup could not be resolved",
			}
		case CgroupResolutionFailureUnsupportedRuntime:
			return ResolutionError{
				Field:   fmt.Sprintf("pods[%q].cgroupIDs", podKey(pod)),
				Message: "contains a running container with an unsupported runtime identity",
			}
		}
		ipv4 := make([]netip.Addr, 0, len(pod.PodIPs))
		for _, address := range pod.PodIPs {
			if address.Is4() {
				ipv4 = append(ipv4, address)
			}
		}
		for _, cgroupID := range pod.CgroupIDs {
			entry, exists := s.subjects[cgroupID]
			if !exists {
				entry = &subjectState{subject: Subject{CgroupID: cgroupID, PodIPs: uniqueSortedAddrs(ipv4)}, podKey: podKey(pod)}
				s.subjects[cgroupID] = entry
				s.bypasses += len(entry.subject.PodIPs)
				if len(s.subjects) > MaxPolicySubjects {
					return CapacityError{Resource: "subject", Observed: len(s.subjects), Allowed: MaxPolicySubjects}
				}
				if observed := s.ruleEntryCount(); observed > MaxPolicyRules {
					return CapacityError{Resource: "rule", Observed: observed, Allowed: MaxPolicyRules}
				}
			} else if entry.podKey != podKey(pod) {
				return ResolutionError{Field: fmt.Sprintf("cgroupID[%d]", cgroupID), Message: "belongs to multiple pods"}
			}
			entry.subject.Isolated |= isolated
			entry.subject.Quarantined |= quarantined
		}
	}
	return nil
}

func (s *compileState) addRules(policy *NativeNetworkPolicy, subjects []ResolvedPod, direction Direction, peers []NativePeer, ports []NativePort) error {
	prefixes, err := s.resolvePeers(policy, peers)
	if err != nil {
		return err
	}
	for _, pod := range subjects {
		for _, cgroupID := range pod.CgroupIDs {
			for _, prefix := range prefixes {
				for _, port := range ports {
					protocol := ProtocolTCP
					if port.Protocol == "UDP" {
						protocol = ProtocolUDP
					}
					rule := Rule{CgroupID: cgroupID, Direction: direction, Peer: prefix, Protocol: protocol, Port: uint16(port.Port)}
					if _, exists := s.rules[rule]; exists {
						continue
					}
					observed := s.ruleEntryCount() + 1
					if observed > MaxPolicyRules {
						return CapacityError{Resource: "rule", Observed: observed, Allowed: MaxPolicyRules}
					}
					s.rules[rule] = struct{}{}
				}
			}
		}
	}
	return nil
}

func (s *compileState) resolvePeers(policy *NativeNetworkPolicy, peers []NativePeer) ([]netip.Prefix, error) {
	resolved := make([]netip.Prefix, 0)
	for _, peer := range peers {
		if peer.IPBlock != nil {
			prefixes, err := ExpandNativeIPBlock(*peer.IPBlock)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, prefixes...)
			continue
		}

		podSelector := labels.Everything()
		var namespaceSelector labels.Selector
		var err error
		if peer.PodSelector != nil {
			podSelector, err = selectorForNative(peer.PodSelector)
			if err != nil {
				return nil, err
			}
		}
		if peer.NamespaceSelector != nil {
			namespaceSelector, err = selectorForNative(peer.NamespaceSelector)
			if err != nil {
				return nil, err
			}
		}

		policyNamespace := nativePolicyNamespace(policy)
		for _, pod := range s.input.Pods {
			if pod.HostNetwork || !podSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			if namespaceSelector == nil {
				if pod.Namespace != policyNamespace {
					continue
				}
			} else {
				namespaceLabels, exists := s.namespaces[pod.Namespace]
				if !exists {
					return nil, ResolutionError{
						Field:   fmt.Sprintf("pods[%q].namespace", podKey(pod)),
						Message: "has no matching namespace entry",
					}
				}
				if !namespaceSelector.Matches(labels.Set(namespaceLabels)) {
					continue
				}
			}
			for _, address := range pod.PodIPs {
				if address.Is4() {
					resolved = append(resolved, netip.PrefixFrom(address, 32))
				}
			}
		}
	}
	return uniqueSortedPrefixes(resolved), nil
}

func (s *compileState) addRejected(policy *NativeNetworkPolicy, err error) {
	diagnostic := RejectedPolicy{Document: 1, Namespace: nativePolicyNamespace(policy), Name: nativePolicyName(policy), Message: err.Error()}
	if policy != nil && policy.Metadata != nil {
		diagnostic.Generation = policy.Metadata.Generation
	}
	var validationErr NativeValidationError
	if errors.As(err, &validationErr) {
		diagnostic.Document = validationErr.Document
		if diagnostic.Document <= 0 {
			diagnostic.Document = 1
		}
		if validationErr.Namespace != "" {
			diagnostic.Namespace = validationErr.Namespace
		}
		if validationErr.Name != "" {
			diagnostic.Name = validationErr.Name
		}
		diagnostic.Field = validationErr.Field
		diagnostic.Message = validationErr.Message
	}
	s.rejected = append(s.rejected, diagnostic)
}

func (s *compileState) policySet() PolicySet {
	set := PolicySet{NodeIPs: append([]netip.Addr(nil), s.input.NodeIPs...)}
	for _, entry := range s.subjects {
		subject := entry.subject
		subject.PodIPs = append([]netip.Addr(nil), subject.PodIPs...)
		set.Subjects = append(set.Subjects, subject)
	}
	for rule := range s.rules {
		set.Rules = append(set.Rules, rule)
	}
	sort.Slice(set.Subjects, func(i, j int) bool { return set.Subjects[i].CgroupID < set.Subjects[j].CgroupID })
	sort.Slice(set.Rules, func(i, j int) bool { return lessRule(set.Rules[i], set.Rules[j]) })
	return set
}

// ruleEntryCount returns the active-slot entries consumed by ordinary rules
// and by the documented node/self bypasses. Quarantine lives in subject state,
// so quarantined cgroups consume the same subject entry as isolated cgroups.
func (s *compileState) ruleEntryCount() int {
	return len(s.rules) + s.bypasses
}

func policySetRuleEntryCount(set PolicySet) int {
	count := len(set.Rules) + len(set.NodeIPs)
	for _, subject := range set.Subjects {
		count += len(subject.PodIPs)
	}
	return count
}

// ValidatePolicySet checks the invariants required by the enforcement boundary.
func ValidatePolicySet(set PolicySet) error {
	if len(set.NodeIPs) == 0 {
		return ResolutionError{Field: "nodeIPs", Message: "must contain at least one IPv4 Node address"}
	}
	for i, address := range set.NodeIPs {
		if !address.IsValid() || !address.Is4() {
			return ResolutionError{Field: fmt.Sprintf("nodeIPs[%d]", i), Message: "must be IPv4"}
		}
	}
	subjects := make(map[uint64]struct{}, len(set.Subjects))
	for i, subject := range set.Subjects {
		field := fmt.Sprintf("subjects[%d]", i)
		if subject.CgroupID == 0 {
			return ResolutionError{Field: field + ".cgroupID", Message: "must be non-zero"}
		}
		if subject.Isolated == 0 || subject.Isolated&^allDirections != 0 {
			return ResolutionError{Field: field + ".isolated", Message: "must contain only ingress or egress bits"}
		}
		if subject.Quarantined&^subject.Isolated != 0 {
			return ResolutionError{Field: field + ".quarantined", Message: "must be a subset of isolated"}
		}
		if _, exists := subjects[subject.CgroupID]; exists {
			return ResolutionError{Field: field + ".cgroupID", Message: "must be unique"}
		}
		subjects[subject.CgroupID] = struct{}{}
		for j, address := range subject.PodIPs {
			if !address.IsValid() || !address.Is4() {
				return ResolutionError{Field: fmt.Sprintf("%s.podIPs[%d]", field, j), Message: "must be IPv4"}
			}
		}
	}
	for i, rule := range set.Rules {
		field := fmt.Sprintf("rules[%d]", i)
		if _, exists := subjects[rule.CgroupID]; !exists {
			return ResolutionError{Field: field + ".cgroupID", Message: "must reference a subject"}
		}
		if rule.Direction != DirectionIngress && rule.Direction != DirectionEgress {
			return ResolutionError{Field: field + ".direction", Message: "must be exactly ingress or egress"}
		}
		if !rule.Peer.IsValid() || !rule.Peer.Addr().Is4() {
			return ResolutionError{Field: field + ".peer", Message: "must be an IPv4 prefix"}
		}
		if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP {
			return ResolutionError{Field: field + ".protocol", Message: "must be TCP or UDP"}
		}
		if rule.Port == 0 {
			return ResolutionError{Field: field + ".port", Message: "must be non-zero"}
		}
	}
	if len(set.Subjects) > MaxPolicySubjects {
		return CapacityError{Resource: "subject", Observed: len(set.Subjects), Allowed: MaxPolicySubjects}
	}
	if observed := policySetRuleEntryCount(set); observed > MaxPolicyRules {
		return CapacityError{Resource: "rule", Observed: observed, Allowed: MaxPolicyRules}
	}
	return nil
}

func selectorForNative(selector *NativeLabelSelector) (labels.Selector, error) {
	if selector == nil {
		return nil, errors.New("selector must be provided")
	}
	converted := &metav1.LabelSelector{MatchLabels: selector.MatchLabels}
	for _, expression := range selector.MatchExpressions {
		converted.MatchExpressions = append(converted.MatchExpressions, metav1.LabelSelectorRequirement{
			Key: expression.Key, Operator: metav1.LabelSelectorOperator(expression.Operator), Values: append([]string(nil), expression.Values...),
		})
	}
	return metav1.LabelSelectorAsSelector(converted)
}

func nativePolicyDirections(policy *NativeNetworkPolicy) Direction {
	if policy == nil || policy.Spec == nil {
		return allDirections
	}
	if policy.Spec.PolicyTypes == nil {
		directions := DirectionIngress
		if len(policy.Spec.Egress) > 0 {
			directions |= DirectionEgress
		}
		return directions
	}
	var directions Direction
	for _, policyType := range *policy.Spec.PolicyTypes {
		switch policyType {
		case "Ingress":
			directions |= DirectionIngress
		case "Egress":
			directions |= DirectionEgress
		}
	}
	if len(policy.Spec.Ingress) > 0 {
		directions |= DirectionIngress
	}
	if len(policy.Spec.Egress) > 0 {
		directions |= DirectionEgress
	}
	if directions == 0 {
		return allDirections
	}
	return directions
}

func nativePolicyNamespace(policy *NativeNetworkPolicy) string {
	if policy != nil && policy.Metadata != nil && policy.Metadata.Namespace != "" {
		return policy.Metadata.Namespace
	}
	return "default"
}

func nativePolicyName(policy *NativeNetworkPolicy) string {
	if policy != nil && policy.Metadata != nil {
		return policy.Metadata.Name
	}
	return ""
}

func nativePolicySortKey(policy NativeNetworkPolicy) string {
	return nativePolicyNamespace(&policy) + "\x00" + nativePolicyName(&policy) + fmt.Sprintf("\x00%010d\x00%s", policy.SourceDocument, policy.FieldPrefix)
}

func podHasIPv6(pod ResolvedPod) bool {
	for _, address := range pod.PodIPs {
		if address.Is6() {
			return true
		}
	}
	return false
}

func podKey(pod ResolvedPod) string { return pod.Namespace + "/" + pod.Name }

func cloneLabels(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func uniqueSortedAddrs(values []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(values))
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		value = value.Unmap()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}

func uniqueSortedPrefixes(values []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(values))
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = value.Masked()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Addr() != result[j].Addr() {
			return result[i].Addr().Less(result[j].Addr())
		}
		return result[i].Bits() < result[j].Bits()
	})
	return result
}

func uniqueSortedUint64(values []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(values))
	result := make([]uint64, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func lessRule(left, right Rule) bool {
	if left.CgroupID != right.CgroupID {
		return left.CgroupID < right.CgroupID
	}
	if left.Direction != right.Direction {
		return left.Direction < right.Direction
	}
	if left.Peer.Addr() != right.Peer.Addr() {
		return left.Peer.Addr().Less(right.Peer.Addr())
	}
	if left.Peer.Bits() != right.Peer.Bits() {
		return left.Peer.Bits() < right.Peer.Bits()
	}
	if left.Protocol != right.Protocol {
		return left.Protocol < right.Protocol
	}
	return left.Port < right.Port
}
