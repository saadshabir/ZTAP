package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"net/netip"
)

const validNativePolicyYAML = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-access
  namespace: team-a
spec:
  podSelector:
    matchLabels:
      app: web
    matchExpressions:
      - key: tier
        operator: In
        values: [frontend]
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              tenant: trusted
          podSelector: {}
        - ipBlock:
            cidr: 10.0.0.0/8
            except: [10.1.0.0/16]
      ports:
        - protocol: TCP
          port: 443
  egress:
    - to:
        - podSelector: {}
      ports:
        - port: 53
          protocol: UDP
`

func TestLoadNativePoliciesFromBytes(t *testing.T) {
	policies, err := LoadNativePoliciesFromBytes([]byte(validNativePolicyYAML))
	if err != nil {
		t.Fatalf("LoadNativePoliciesFromBytes failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(policies))
	}
	got := policies[0]
	if got.Metadata == nil || got.Metadata.Namespace != "team-a" || got.Metadata.Name != "web-access" {
		t.Fatalf("metadata = %#v, want team-a/web-access", got.Metadata)
	}
	if got.Spec == nil || len(got.Spec.Ingress) != 1 || len(got.Spec.Egress) != 1 {
		t.Fatalf("spec = %#v, want one ingress and one egress rule", got.Spec)
	}
	if got.Spec.Egress[0].Ports[0].Protocol != "UDP" || got.Spec.Egress[0].Ports[0].Port != 53 {
		t.Fatalf("egress port = %#v, want UDP/53", got.Spec.Egress[0].Ports[0])
	}
	if got.EffectivePolicyTypes() == nil || strings.Join(got.EffectivePolicyTypes(), ",") != "Ingress,Egress" {
		t.Fatalf("effective policy types = %v", got.EffectivePolicyTypes())
	}
}

func TestNativePolicyDefaultingAndListItems(t *testing.T) {
	input := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicyList
items:
  - metadata:
      name: deny-ingress
    spec:
      podSelector: {}
      ingress: []
  - metadata:
      name: allow-egress
    spec:
      podSelector:
        matchLabels:
          app: client
      egress:
        - to:
            - ipBlock:
                cidr: 192.0.2.0/24
          ports:
            - port: 443
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: second
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress: []
`

	policies, err := LoadNativePoliciesFromBytes([]byte(input))
	if err != nil {
		t.Fatalf("LoadNativePoliciesFromBytes failed: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("got %d policies, want 3", len(policies))
	}
	if got := strings.Join(policies[0].EffectivePolicyTypes(), ","); got != "Ingress" {
		t.Fatalf("default policy types for ingress-only policy = %q, want Ingress", got)
	}
	if got := strings.Join(policies[1].EffectivePolicyTypes(), ","); got != "Ingress,Egress" {
		t.Fatalf("default policy types for egress policy = %q, want Ingress,Egress", got)
	}
	if policies[0].FieldPrefix != "items[0]." || policies[0].SourceDocument != 1 {
		t.Fatalf("list source context = %q/document %d", policies[0].FieldPrefix, policies[0].SourceDocument)
	}
	if got := strings.Join(policies[2].EffectivePolicyTypes(), ","); got != "Egress" {
		t.Fatalf("explicit policy types = %q, want Egress", got)
	}
}

func TestNativePolicyIgnoresEmptyDocumentsAndPreservesDocumentIndex(t *testing.T) {
	input := validNativePolicyYAML + "---\n# empty document\n---\n" + validNativePolicyYAML
	policies, err := LoadNativePoliciesFromBytes([]byte(input))
	if err != nil {
		t.Fatalf("LoadNativePoliciesFromBytes failed: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(policies))
	}
	if policies[0].SourceDocument != 1 || policies[1].SourceDocument != 3 {
		t.Fatalf("source documents = %d,%d, want 1,3", policies[0].SourceDocument, policies[1].SourceDocument)
	}
}

func TestNativePolicyAcceptsStandardKubernetesMetadata(t *testing.T) {
	input := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: exported
  namespace: team-a
  uid: 4dc5bc08-c798-4f38-9c5b-798d79935572
  resourceVersion: "17"
  generation: 2
  creationTimestamp: 2026-09-10T12:00:00Z
  finalizers: [example.com/cleanup]
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: web
      uid: 7433acdb-c32b-429f-ab93-70c9f4476180
      controller: true
  managedFields:
    - manager: kubectl
      operation: Apply
      apiVersion: networking.k8s.io/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:spec: {}
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress: []
`
	policies, err := LoadNativePoliciesFromBytes([]byte(input))
	if err != nil {
		t.Fatalf("LoadNativePoliciesFromBytes failed for exported metadata: %v", err)
	}
	if got := policies[0].Metadata.Name; got != "exported" {
		t.Fatalf("metadata name = %q, want exported", got)
	}
}

func TestNativePolicyRejectsInvalidListAPIVersion(t *testing.T) {
	input := `apiVersion: v1
kind: NetworkPolicyList
items:
  - apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: item
    spec:
      podSelector: {}
      policyTypes: [Ingress]
      ingress: []
`
	_, err := LoadNativePoliciesFromBytes([]byte(input))
	var validationErr NativeValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %v, want NativeValidationError", err, err)
	}
	if validationErr.Field != "apiVersion" {
		t.Fatalf("field = %q, want apiVersion", validationErr.Field)
	}
}

func TestNativeListStructuralErrorIncludesItemIdentity(t *testing.T) {
	input := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicyList
items:
  - metadata:
      name: listed
      namespace: team-a
    spec:
      podSelector: {}
      unknown: true
`
	_, err := LoadNativePoliciesFromBytes([]byte(input))
	var validationErr NativeValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %v, want NativeValidationError", err, err)
	}
	if validationErr.Field != "items[0].spec.unknown" {
		t.Fatalf("field = %q, want items[0].spec.unknown", validationErr.Field)
	}
	if validationErr.Namespace != "team-a" || validationErr.Name != "listed" {
		t.Fatalf("identity = %s/%s, want team-a/listed", validationErr.Namespace, validationErr.Name)
	}
}

func TestNativePolicyTypesMustMatchRules(t *testing.T) {
	tests := []struct {
		name        string
		policyTypes string
		rules       string
	}{
		{name: "empty", policyTypes: "[]", rules: "ingress: []"},
		{name: "ingress omitted", policyTypes: "[Egress]", rules: "ingress:\n    - from:\n        - podSelector: {}\n      ports:\n        - port: 443"},
		{name: "egress omitted", policyTypes: "[Ingress]", rules: "egress:\n    - to:\n        - podSelector: {}\n      ports:\n        - port: 443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: policy-types
spec:
  podSelector: {}
  policyTypes: ` + tt.policyTypes + "\n  " + tt.rules + "\n"
			_, err := LoadNativePoliciesFromBytes([]byte(input))
			var validationErr NativeValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %T %v, want NativeValidationError", err, err)
			}
			if validationErr.Field != "spec.policyTypes" {
				t.Fatalf("field = %q, want spec.policyTypes", validationErr.Field)
			}
		})
	}
}

func TestNativePolicyRejectsUnsupportedContent(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		field string
	}{
		{
			name:  "wrong api version",
			yaml:  strings.Replace(validNativePolicyYAML, "networking.k8s.io/v1", "ztap/v1", 1),
			field: "apiVersion",
		},
		{
			name:  "missing api version",
			yaml:  strings.TrimPrefix(validNativePolicyYAML, "apiVersion: networking.k8s.io/v1\n"),
			field: "apiVersion",
		},
		{
			name:  "unrelated kind",
			yaml:  strings.Replace(validNativePolicyYAML, "kind: NetworkPolicy", "kind: ConfigMap", 1),
			field: "kind",
		},
		{
			name:  "missing name",
			yaml:  strings.Replace(validNativePolicyYAML, "  name: web-access\n", "", 1),
			field: "metadata.name",
		},
		{
			name:  "whitespace namespace",
			yaml:  strings.Replace(validNativePolicyYAML, "namespace: team-a", `namespace: " "`, 1),
			field: "metadata.namespace",
		},
		{
			name: "missing spec",
			yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: missing-spec
`,
			field: "spec",
		},
		{
			name: "missing pod selector",
			yaml: strings.Replace(validNativePolicyYAML, `  podSelector:
    matchLabels:
      app: web
    matchExpressions:
      - key: tier
        operator: In
        values: [frontend]
`, "", 1),
			field: "spec.podSelector",
		},
		{
			name:  "unknown top-level field",
			yaml:  validNativePolicyYAML + "unknown: true\n",
			field: "unknown",
		},
		{
			name:  "non-string selector value",
			yaml:  strings.Replace(validNativePolicyYAML, "app: web", "app: 123", 1),
			field: "spec.podSelector.matchLabels.app",
		},
		{
			name:  "invalid metadata label key",
			yaml:  strings.Replace(validNativePolicyYAML, "  namespace: team-a\n", "  namespace: team-a\n  labels:\n    invalid key: value\n", 1),
			field: `metadata.labels["invalid key"]`,
		},
		{
			name:  "invalid metadata label value",
			yaml:  strings.Replace(validNativePolicyYAML, "  namespace: team-a\n", "  namespace: team-a\n  labels:\n    app: invalid value\n", 1),
			field: `metadata.labels["app"]`,
		},
		{
			name:  "invalid metadata annotation key",
			yaml:  strings.Replace(validNativePolicyYAML, "  namespace: team-a\n", "  namespace: team-a\n  annotations:\n    invalid key: value\n", 1),
			field: `metadata.annotations["invalid key"]`,
		},
		{
			name:  "invalid selector expression",
			yaml:  strings.Replace(validNativePolicyYAML, "operator: In", "operator: Invalid", 1),
			field: "spec.podSelector",
		},
		{
			name: "empty peer",
			yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: empty-peer
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
      ports:
        - port: 443
`,
			field: "spec.ingress[0].from[0]",
		},
		{
			name: "ip block combined with selector",
			yaml: strings.Replace(validNativePolicyYAML, `        - ipBlock:
            cidr: 10.0.0.0/8
            except: [10.1.0.0/16]
`, `        - podSelector: {}
          ipBlock:
            cidr: 10.0.0.0/8
            except: [10.1.0.0/16]
`, 1),
			field: "spec.ingress[0].from[1]",
		},
		{
			name:  "protocol whitespace is not defaulted",
			yaml:  strings.Replace(validNativePolicyYAML, "protocol: TCP", `protocol: " TCP "`, 1),
			field: "spec.ingress[0].ports[0].protocol",
		},
		{
			name:  "sctp protocol",
			yaml:  strings.Replace(validNativePolicyYAML, "protocol: TCP", "protocol: SCTP", 1),
			field: "spec.ingress[0].ports[0].protocol",
		},
		{
			name:  "missing port value",
			yaml:  strings.Replace(validNativePolicyYAML, "          port: 443\n", "", 1),
			field: "spec.ingress[0].ports[0].port",
		},
		{
			name:  "port out of range",
			yaml:  strings.Replace(validNativePolicyYAML, "port: 443", "port: 65536", 1),
			field: "spec.ingress[0].ports[0].port",
		},
		{
			name:  "malformed port value",
			yaml:  strings.Replace(validNativePolicyYAML, "port: 443", "port: true", 1),
			field: "spec.ingress[0].ports[0].port",
		},
		{
			name:  "duplicate metadata key",
			yaml:  strings.Replace(validNativePolicyYAML, "  name: web-access\n", "  name: web-access\n  name: duplicate\n", 1),
			field: "metadata.name",
		},
		{
			name: "peerless rule",
			yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: peerless
spec:
  podSelector: {}
  ingress:
    - from: []
      ports:
        - port: 443
`,
			field: "spec.ingress[0].from",
		},
		{
			name:  "portless rule",
			yaml:  strings.Replace(validNativePolicyYAML, "      ports:\n        - protocol: TCP\n          port: 443\n", "      ports: []\n", 1),
			field: "spec.ingress[0].ports",
		},
		{
			name:  "named port",
			yaml:  strings.Replace(validNativePolicyYAML, "port: 443", "port: https", 1),
			field: "spec.ingress[0].ports[0].port",
		},
		{
			name:  "end port",
			yaml:  strings.Replace(validNativePolicyYAML, "port: 443", "port: 443\n          endPort: 444", 1),
			field: "spec.ingress[0].ports[0].endPort",
		},
		{
			name:  "ipv6 cidr",
			yaml:  strings.Replace(validNativePolicyYAML, "cidr: 10.0.0.0/8", "cidr: 2001:db8::/32", 1),
			field: "spec.ingress[0].from[1].ipBlock",
		},
		{
			name:  "ip block exception outside cidr",
			yaml:  strings.Replace(validNativePolicyYAML, "except: [10.1.0.0/16]", "except: [192.0.2.0/24]", 1),
			field: "spec.ingress[0].from[1].ipBlock",
		},
		{
			name:  "cidr whitespace is invalid",
			yaml:  strings.Replace(validNativePolicyYAML, "cidr: 10.0.0.0/8", `cidr: " 10.0.0.0/8 "`, 1),
			field: "spec.ingress[0].from[1].ipBlock",
		},
		{
			name:  "ipv6 ip block exception",
			yaml:  strings.Replace(validNativePolicyYAML, "except: [10.1.0.0/16]", "except: [2001:db8::/64]", 1),
			field: "spec.ingress[0].from[1].ipBlock",
		},
		{
			name:  "policy types must be a list",
			yaml:  strings.Replace(validNativePolicyYAML, "policyTypes: [Ingress, Egress]", "policyTypes: Ingress", 1),
			field: "spec.policyTypes",
		},
		{
			name: "ingress must be a list",
			yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: malformed-ingress
spec:
  podSelector: {}
  ingress: {}
`,
			field: "spec.ingress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadNativePoliciesFromBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected validation error")
			}
			var validationErr NativeValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want NativeValidationError: %v", err, err)
			}
			if validationErr.Field != tt.field && !strings.HasPrefix(validationErr.Field, tt.field+".") {
				t.Fatalf("field = %q, want %q", validationErr.Field, tt.field)
			}
			if validationErr.ExitCode() != 1 {
				t.Fatalf("exit code = %d, want 1", validationErr.ExitCode())
			}
		})
	}
}

func TestDecodeNativePoliciesRejectsMalformedYAML(t *testing.T) {
	_, err := LoadNativePoliciesFromBytes([]byte("kind: [NetworkPolicy\n"))
	if err == nil {
		t.Fatal("expected decode error")
	}
	var decodeErr NativeDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("error type = %T, want NativeDecodeError: %v", err, err)
	}
	if decodeErr.ExitCode() != 2 {
		t.Fatalf("exit code = %d, want 2", decodeErr.ExitCode())
	}
}

func TestLoadNativePoliciesRejectsEmptyInput(t *testing.T) {
	_, err := LoadNativePoliciesFromBytes([]byte("---\n# no policies\n"))
	var validationErr NativeValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %v, want NativeValidationError", err, err)
	}
	if validationErr.Field != "document" {
		t.Fatalf("field = %q, want document", validationErr.Field)
	}
}

func TestNativePolicyErrorPreservesMultiDocumentContext(t *testing.T) {
	input := validNativePolicyYAML + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: second-bad
  namespace: team-b
spec:
  podSelector: {}
  ingress:
    - from: []
      ports:
        - port: 443
`
	_, err := LoadNativePoliciesFromBytes([]byte(input))
	var validationErr NativeValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %v, want NativeValidationError", err, err)
	}
	if validationErr.Document != 2 || validationErr.Namespace != "team-b" || validationErr.Name != "second-bad" {
		t.Fatalf("context = document %d %s/%s, want document 2 team-b/second-bad", validationErr.Document, validationErr.Namespace, validationErr.Name)
	}
}

func TestExpandNativeIPBlock(t *testing.T) {
	prefixes, err := ExpandNativeIPBlock(NativeIPBlock{
		CIDR:   "10.0.0.0/30",
		Except: []string{"10.0.0.0/31"},
	})
	if err != nil {
		t.Fatalf("ExpandNativeIPBlock failed: %v", err)
	}
	want := netip.MustParsePrefix("10.0.0.2/31")
	if len(prefixes) != 1 || prefixes[0] != want {
		t.Fatalf("prefixes = %v, want [%s]", prefixes, want)
	}
}

func TestExpandNativeIPBlockIsIndependentOfExceptionOrder(t *testing.T) {
	left, err := ExpandNativeIPBlock(NativeIPBlock{
		CIDR:   "10.0.0.0/24",
		Except: []string{"10.0.0.0/26", "10.0.0.64/26"},
	})
	if err != nil {
		t.Fatalf("first expansion failed: %v", err)
	}
	right, err := ExpandNativeIPBlock(NativeIPBlock{
		CIDR:   "10.0.0.0/24",
		Except: []string{"10.0.0.64/26", "10.0.0.0/26"},
	})
	if err != nil {
		t.Fatalf("second expansion failed: %v", err)
	}
	if len(left) != len(right) {
		t.Fatalf("prefix counts differ: %v vs %v", left, right)
	}
	for i := range left {
		if left[i] != right[i] {
			t.Fatalf("prefixes differ by exception order: %v vs %v", left, right)
		}
	}
}

func TestExpandNativeIPBlockCapUsesFinalCanonicalResult(t *testing.T) {
	narrow := make([]string, 0, MaxIPBlockExpansion+1)
	for i := 0; i < MaxIPBlockExpansion+1; i++ {
		value := i * 2
		address := netip.AddrFrom4([4]byte{10, 0, byte(value >> 8), byte(value)})
		narrow = append(narrow, address.String()+"/32")
	}

	narrowFirst := append(append([]string(nil), narrow...), "10.0.0.0/9")
	broadFirst := append([]string{"10.0.0.0/9"}, narrow...)
	left, err := ExpandNativeIPBlock(NativeIPBlock{CIDR: "10.0.0.0/8", Except: narrowFirst})
	if err != nil {
		t.Fatalf("narrow-first expansion failed: %v", err)
	}
	right, err := ExpandNativeIPBlock(NativeIPBlock{CIDR: "10.0.0.0/8", Except: broadFirst})
	if err != nil {
		t.Fatalf("broad-first expansion failed: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.128.0.0/9")}
	if !reflect.DeepEqual(left, want) || !reflect.DeepEqual(right, want) {
		t.Fatalf("order-dependent expansion: narrow-first=%v broad-first=%v want=%v", left, right, want)
	}
}

func TestExpandNativeIPBlockRejectsLargeExpansion(t *testing.T) {
	excepts := make([]string, 0, MaxIPBlockExpansion+1)
	for i := 0; i < MaxIPBlockExpansion+1; i++ {
		value := i * 2
		address := netip.AddrFrom4([4]byte{10, 0, byte(value >> 8), byte(value)})
		excepts = append(excepts, address.String()+"/32")
	}
	_, err := ExpandNativeIPBlock(NativeIPBlock{CIDR: "10.0.0.0/8", Except: excepts})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want expansion-cap error", err)
	}
}
