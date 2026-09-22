package policy

import (
	"fmt"
	"net/netip"
	"testing"
)

const (
	referenceFixtureSubjects = 250
	referenceFixturePolicies = 25
	referenceFixtureRules    = 2500
)

// TestReferenceFixtureShape protects the documented compiler workload from
// drifting. This is deliberately a Go-only supporting fixture: the Phase 5
// release gate still requires separate real-cgroup, real-packet, CPU, and
// memory measurements on the documented Linux reference environment.
func TestReferenceFixtureShape(t *testing.T) {
	policies, input := referenceCompileFixture()
	result, err := CompileNativePolicies(policies, input)
	if err != nil {
		t.Fatalf("compile reference fixture: %v", err)
	}
	if got := len(result.PolicySet.Subjects); got != referenceFixtureSubjects {
		t.Fatalf("subjects = %d, want %d", got, referenceFixtureSubjects)
	}
	if got := len(result.PolicySet.Rules); got != referenceFixtureRules {
		t.Fatalf("rules = %d, want %d", got, referenceFixtureRules)
	}
	if len(result.Rejected) != 0 {
		t.Fatalf("rejected policies = %#v, want none", result.Rejected)
	}
}

// BenchmarkCompileReferenceFixture measures only native-policy compilation
// for the 250-Pod/25-policy/2,500-rule shape. It must not be used to claim the
// kernel-path reconciliation, packet latency, CPU, memory, or flow-loss gates
// from STREAMLINING_PLAN.md.
func BenchmarkCompileReferenceFixture(b *testing.B) {
	policies, input := referenceCompileFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := CompileNativePolicies(policies, input)
		if err != nil {
			b.Fatalf("compile reference fixture: %v", err)
		}
		if len(result.PolicySet.Subjects) != referenceFixtureSubjects || len(result.PolicySet.Rules) != referenceFixtureRules {
			b.Fatalf("compiled shape = %d subjects/%d rules, want %d/%d", len(result.PolicySet.Subjects), len(result.PolicySet.Rules), referenceFixtureSubjects, referenceFixtureRules)
		}
	}
}

func referenceCompileFixture() ([]NativeNetworkPolicy, ResolutionInput) {
	policies := make([]NativeNetworkPolicy, 0, referenceFixturePolicies)
	for bucket := 0; bucket < referenceFixturePolicies; bucket++ {
		peers := make([]NativePeer, 0, 10)
		for peer := 0; peer < 10; peer++ {
			peers = append(peers, NativePeer{IPBlock: &NativeIPBlock{
				CIDR: fmt.Sprintf("203.0.113.%d/32", bucket*10+peer+1),
			}})
		}
		policies = append(policies, nativePolicy(
			"default",
			fmt.Sprintf("reference-egress-%02d", bucket),
			map[string]string{"reference-bucket": fmt.Sprintf("%02d", bucket)},
			[]string{"Egress"},
			nil,
			[]NativeEgressRule{{
				To:    peers,
				Ports: []NativePort{{Protocol: "TCP", Port: 10000 + bucket}},
			}},
		))
	}

	input := ResolutionInput{
		NodeIPs:    []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Namespaces: []ResolvedNamespace{{Name: "default"}},
		Pods:       make([]ResolvedPod, 0, referenceFixtureSubjects),
	}
	for index := 0; index < referenceFixtureSubjects; index++ {
		bucket := index / (referenceFixtureSubjects / referenceFixturePolicies)
		input.Pods = append(input.Pods, ResolvedPod{
			Namespace: "default",
			Name:      fmt.Sprintf("reference-pod-%03d", index),
			Labels:    map[string]string{"reference-bucket": fmt.Sprintf("%02d", bucket)},
			PodIPs:    []netip.Addr{referencePodIP(index)},
			CgroupIDs: []uint64{uint64(10000 + index)},
			Local:     true,
		})
	}
	return policies, input
}

func referencePodIP(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(index / 65536), byte(index / 256), byte(index)})
}
