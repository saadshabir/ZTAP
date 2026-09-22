package policy

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCompileNativePoliciesExpandsSelectorsPortsAndAdditiveUnion(t *testing.T) {
	policies := []NativeNetworkPolicy{
		nativePolicy("team-a", "web-egress", map[string]string{"app": "web"}, []string{"Egress"}, nil, []NativeEgressRule{
			{
				To: []NativePeer{
					{PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "db"}}},
					{NamespaceSelector: &NativeLabelSelector{MatchLabels: map[string]string{"tenant": "trusted"}}, PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"role": "dns"}}},
					{IPBlock: &NativeIPBlock{CIDR: "203.0.113.0/24", Except: []string{"203.0.113.0/25"}}},
				},
				Ports: []NativePort{{Protocol: "TCP", Port: 443}, {Protocol: "UDP", Port: 53}},
			},
		}),
		nativePolicy("team-a", "web-ingress", map[string]string{"app": "web"}, []string{"Ingress"}, []NativeIngressRule{
			{
				From:  []NativePeer{{PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				Ports: []NativePort{{Protocol: "TCP", Port: 8443}},
			},
		}, nil),
		// An overlapping policy proves that ordinary rules combine as a set.
		nativePolicy("team-a", "web-egress-duplicate", map[string]string{"app": "web"}, []string{"Egress"}, nil, []NativeEgressRule{
			{
				To:    []NativePeer{{PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "db"}}}},
				Ports: []NativePort{{Protocol: "TCP", Port: 443}},
			},
		}),
	}
	input := ResolutionInput{
		NodeIPs: []netip.Addr{mustAddr("192.0.2.10"), mustAddr("192.0.2.10"), mustAddr("2001:db8::10")},
		Namespaces: []ResolvedNamespace{
			{Name: "team-a", Labels: map[string]string{"tenant": "ordinary"}},
			{Name: "trusted", Labels: map[string]string{"tenant": "trusted"}},
		},
		Pods: []ResolvedPod{
			{Namespace: "team-a", Name: "web", Labels: map[string]string{"app": "web"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{22, 21}, Local: true},
			{Namespace: "team-a", Name: "db", Labels: map[string]string{"app": "db"}, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}, CgroupIDs: []uint64{30}, Local: true},
			{Namespace: "team-a", Name: "client", Labels: map[string]string{"app": "client"}, PodIPs: []netip.Addr{mustAddr("10.0.0.4")}},
			{Namespace: "trusted", Name: "dns", Labels: map[string]string{"role": "dns"}, PodIPs: []netip.Addr{mustAddr("10.1.0.53")}},
			{Namespace: "trusted", Name: "wrong-role", Labels: map[string]string{"role": "other"}, PodIPs: []netip.Addr{mustAddr("10.1.0.54")}},
		},
	}

	result, err := CompileNativePolicies(policies, input)
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	if len(result.Rejected) != 0 {
		t.Fatalf("rejected = %#v, want none", result.Rejected)
	}
	if got, want := result.PolicySet.NodeIPs, []netip.Addr{mustAddr("192.0.2.10")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node IPs = %v, want %v", got, want)
	}
	if len(result.PolicySet.Subjects) != 2 {
		t.Fatalf("subjects = %#v, want two web cgroups", result.PolicySet.Subjects)
	}
	for _, subject := range result.PolicySet.Subjects {
		if subject.Isolated != DirectionIngress|DirectionEgress || subject.Quarantined != 0 {
			t.Fatalf("subject = %#v, want bidirectional isolation without quarantine", subject)
		}
		if !reflect.DeepEqual(subject.PodIPs, []netip.Addr{mustAddr("10.0.0.2")}) {
			t.Fatalf("subject pod IPs = %v", subject.PodIPs)
		}
	}

	// Per cgroup: ingress client TCP/8443 (1), plus three egress peers across
	// TCP/443 and UDP/53 (6). The overlapping TCP db rule is deduplicated.
	if got, want := len(result.PolicySet.Rules), 14; got != want {
		t.Fatalf("rule count = %d, want %d: %#v", got, want, result.PolicySet.Rules)
	}
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 21, Direction: DirectionEgress, Peer: mustPrefix("10.0.0.3/32"), Protocol: ProtocolTCP, Port: 443})
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 21, Direction: DirectionEgress, Peer: mustPrefix("10.1.0.53/32"), Protocol: ProtocolUDP, Port: 53})
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 21, Direction: DirectionEgress, Peer: mustPrefix("203.0.113.128/25"), Protocol: ProtocolTCP, Port: 443})
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 21, Direction: DirectionIngress, Peer: mustPrefix("10.0.0.4/32"), Protocol: ProtocolTCP, Port: 8443})
}

func TestCompileNativePoliciesDeletionRemovesOnlyDeletedContribution(t *testing.T) {
	dbPolicy := nativePolicy("default", "web-db", map[string]string{"app": "web"}, []string{"Egress"}, nil, []NativeEgressRule{{
		To:    []NativePeer{{PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "db"}}}},
		Ports: []NativePort{{Protocol: "TCP", Port: 443}},
	}})
	dnsPolicy := nativePolicy("default", "web-dns", map[string]string{"app": "web"}, []string{"Egress"}, nil, []NativeEgressRule{{
		To:    []NativePeer{{IPBlock: &NativeIPBlock{CIDR: "198.51.100.53/32"}}},
		Ports: []NativePort{{Protocol: "UDP", Port: 53}},
	}})
	input := basicResolutionInput(
		ResolvedPod{Namespace: "default", Name: "web", Labels: map[string]string{"app": "web"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
		ResolvedPod{Namespace: "default", Name: "db", Labels: map[string]string{"app": "db"}, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}},
	)

	both, err := CompileNativePolicies([]NativeNetworkPolicy{dbPolicy, dnsPolicy}, input)
	if err != nil {
		t.Fatalf("compile additive policy set: %v", err)
	}
	if len(both.PolicySet.Rules) != 2 {
		t.Fatalf("combined rules = %#v, want two contributions", both.PolicySet.Rules)
	}

	remainingDB, err := CompileNativePolicies([]NativeNetworkPolicy{dbPolicy}, input)
	if err != nil {
		t.Fatalf("compile after DNS policy deletion: %v", err)
	}
	if len(remainingDB.PolicySet.Rules) != 1 {
		t.Fatalf("rules after DNS deletion = %#v, want only DB contribution", remainingDB.PolicySet.Rules)
	}
	assertRulePresent(t, remainingDB.PolicySet, Rule{CgroupID: 1, Direction: DirectionEgress, Peer: mustPrefix("10.0.0.3/32"), Protocol: ProtocolTCP, Port: 443})

	remainingDNS, err := CompileNativePolicies([]NativeNetworkPolicy{dnsPolicy}, input)
	if err != nil {
		t.Fatalf("compile after DB policy deletion: %v", err)
	}
	if len(remainingDNS.PolicySet.Rules) != 1 {
		t.Fatalf("rules after DB deletion = %#v, want only DNS contribution", remainingDNS.PolicySet.Rules)
	}
	assertRulePresent(t, remainingDNS.PolicySet, Rule{CgroupID: 1, Direction: DirectionEgress, Peer: mustPrefix("198.51.100.53/32"), Protocol: ProtocolUDP, Port: 53})

	cleared, err := CompileNativePolicies(nil, input)
	if err != nil {
		t.Fatalf("compile after deleting all policies: %v", err)
	}
	if len(cleared.PolicySet.Subjects) != 0 || len(cleared.PolicySet.Rules) != 0 {
		t.Fatalf("policy deletion left stale state: %#v", cleared.PolicySet)
	}
}

func TestCompileNativePoliciesDefaultDenyAndPolicyTypeDefaulting(t *testing.T) {
	policy := nativePolicy("default", "default-deny", map[string]string{"app": "api"}, nil, nil, nil)
	result, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, basicResolutionInput(
		ResolvedPod{Namespace: "default", Name: "api", Labels: map[string]string{"app": "api"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
	))
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	if got := result.PolicySet.Subjects[0].Isolated; got != DirectionIngress {
		t.Fatalf("isolated = %d, want ingress", got)
	}
	if len(result.PolicySet.Rules) != 0 {
		t.Fatalf("default deny emitted rules: %#v", result.PolicySet.Rules)
	}
}

func TestCompileNativePoliciesRejectsSelectedCgroupResolutionFailure(t *testing.T) {
	for name, failure := range map[string]CgroupResolutionFailure{
		"not found":           CgroupResolutionFailureNotFound,
		"unsupported runtime": CgroupResolutionFailureUnsupportedRuntime,
	} {
		t.Run(name, func(t *testing.T) {
			input := basicResolutionInput(ResolvedPod{
				Namespace:               "default",
				Name:                    "api",
				Labels:                  map[string]string{"app": "api"},
				CgroupIDs:               []uint64{1},
				CgroupResolutionFailure: failure,
				Local:                   true,
			})

			_, err := CompileNativePolicies([]NativeNetworkPolicy{
				nativePolicy("default", "default-deny", map[string]string{"app": "api"}, nil, nil, nil),
			}, input)
			var resolutionErr ResolutionError
			if !errors.As(err, &resolutionErr) {
				t.Fatalf("error = %T %v, want ResolutionError", err, err)
			}
			if resolutionErr.Field != `pods["default/api"].cgroupIDs` {
				t.Fatalf("resolution error field = %q", resolutionErr.Field)
			}
		})
	}
}

func TestCompileNativePoliciesAllowsPendingAndUnselectedCgroupResolutionFailure(t *testing.T) {
	input := basicResolutionInput(
		ResolvedPod{
			Namespace: "default", Name: "pending", Labels: map[string]string{"app": "api"}, Local: true,
		},
		ResolvedPod{
			Namespace:               "default",
			Name:                    "unselected",
			Labels:                  map[string]string{"app": "other"},
			CgroupResolutionFailure: CgroupResolutionFailureUnsupportedRuntime,
			Local:                   true,
		},
	)

	result, err := CompileNativePolicies([]NativeNetworkPolicy{
		nativePolicy("default", "default-deny", map[string]string{"app": "api"}, nil, nil, nil),
	}, input)
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	if len(result.PolicySet.Subjects) != 0 {
		t.Fatalf("pending pod produced subjects: %#v", result.PolicySet.Subjects)
	}
}

func TestCompileNativePoliciesQuarantinesOnlyRejectedLocalSubjects(t *testing.T) {
	bad := nativePolicy("default", "bad-ingress", map[string]string{"app": "bad"}, []string{"Ingress"}, []NativeIngressRule{
		{From: []NativePeer{{IPBlock: &NativeIPBlock{CIDR: "198.51.100.0/24"}}}, Ports: []NativePort{{Protocol: "TCP", PortName: "https"}}},
	}, nil)
	bad.Metadata.Generation = 11
	good := nativePolicy("default", "good-egress", map[string]string{"app": "good"}, []string{"Egress"}, nil, []NativeEgressRule{
		{To: []NativePeer{{IPBlock: &NativeIPBlock{CIDR: "203.0.113.9/32"}}}, Ports: []NativePort{{Protocol: "TCP", Port: 443}}},
	})
	input := basicResolutionInput(
		ResolvedPod{Namespace: "default", Name: "bad", Labels: map[string]string{"app": "bad"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
		ResolvedPod{Namespace: "default", Name: "good", Labels: map[string]string{"app": "good"}, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}, CgroupIDs: []uint64{2}, Local: true},
		ResolvedPod{Namespace: "default", Name: "remote-bad", Labels: map[string]string{"app": "bad"}, PodIPs: []netip.Addr{mustAddr("10.0.1.2")}},
	)

	result, err := CompileNativePolicies([]NativeNetworkPolicy{bad, good}, input)
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	if len(result.Rejected) != 1 || result.Rejected[0].Name != "bad-ingress" || result.Rejected[0].Field != "spec.ingress[0].ports[0].port" {
		t.Fatalf("rejected = %#v", result.Rejected)
	}
	if result.Rejected[0].Generation != 11 {
		t.Fatalf("rejected generation = %d, want 11", result.Rejected[0].Generation)
	}
	badSubject := subjectByCgroup(t, result.PolicySet, 1)
	if badSubject.Isolated != DirectionIngress || badSubject.Quarantined != DirectionIngress {
		t.Fatalf("bad subject = %#v, want ingress quarantine", badSubject)
	}
	goodSubject := subjectByCgroup(t, result.PolicySet, 2)
	if goodSubject.Isolated != DirectionEgress || goodSubject.Quarantined != 0 {
		t.Fatalf("good subject = %#v, want accepted egress", goodSubject)
	}
	if len(result.PolicySet.Rules) != 1 {
		t.Fatalf("rules = %#v, want unrelated accepted rule", result.PolicySet.Rules)
	}
}

func TestCompileNativePoliciesQuarantinesSelectedIPv6Workload(t *testing.T) {
	policy := nativePolicy("default", "dual-stack", map[string]string{"app": "dual"}, []string{"Ingress", "Egress"}, nil, nil)
	input := basicResolutionInput(ResolvedPod{
		Namespace: "default", Name: "dual", Labels: map[string]string{"app": "dual"},
		PodIPs: []netip.Addr{mustAddr("10.0.0.2"), mustAddr("2001:db8::2")}, CgroupIDs: []uint64{7}, Local: true,
	})
	result, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, input)
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	subject := subjectByCgroup(t, result.PolicySet, 7)
	if subject.Quarantined != DirectionIngress|DirectionEgress {
		t.Fatalf("quarantined = %d, want both directions", subject.Quarantined)
	}
	if !reflect.DeepEqual(subject.PodIPs, []netip.Addr{mustAddr("10.0.0.2")}) {
		t.Fatalf("kernel-facing pod IPs = %v, want IPv4 only", subject.PodIPs)
	}
}

func TestCompileNativePoliciesUsesNodeAndSelfFactsWithoutServiceSynthesis(t *testing.T) {
	policy := nativePolicy("default", "service-explicit", map[string]string{"app": "client"}, []string{"Egress"}, nil, []NativeEgressRule{
		{
			To: []NativePeer{
				{PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "server"}}},
				{IPBlock: &NativeIPBlock{CIDR: "10.96.0.10/32"}},
			},
			Ports: []NativePort{{Protocol: "TCP", Port: 443}},
		},
	})
	input := basicResolutionInput(
		ResolvedPod{Namespace: "default", Name: "client", Labels: map[string]string{"app": "client"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
		ResolvedPod{Namespace: "default", Name: "server", Labels: map[string]string{"app": "server"}, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}},
		ResolvedPod{Namespace: "default", Name: "host-server", Labels: map[string]string{"app": "server"}, PodIPs: []netip.Addr{mustAddr("192.0.2.10")}, CgroupIDs: []uint64{99}, Local: true, HostNetwork: true},
	)
	result, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, input)
	if err != nil {
		t.Fatalf("CompileNativePolicies failed: %v", err)
	}
	if len(result.PolicySet.Subjects) != 1 || result.PolicySet.Subjects[0].CgroupID != 1 {
		t.Fatalf("subjects = %#v, hostNetwork pod must be excluded", result.PolicySet.Subjects)
	}
	if got, want := result.PolicySet.Subjects[0].PodIPs, []netip.Addr{mustAddr("10.0.0.2")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("self-bypass facts = %v, want %v", got, want)
	}
	if got, want := result.PolicySet.NodeIPs, []netip.Addr{mustAddr("192.0.2.10")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node-bypass facts = %v, want %v", got, want)
	}
	if len(result.PolicySet.Rules) != 2 {
		t.Fatalf("rules = %#v, want backend PodIP plus explicit ClusterIP only", result.PolicySet.Rules)
	}
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 1, Direction: DirectionEgress, Peer: mustPrefix("10.0.0.3/32"), Protocol: ProtocolTCP, Port: 443})
	assertRulePresent(t, result.PolicySet, Rule{CgroupID: 1, Direction: DirectionEgress, Peer: mustPrefix("10.96.0.10/32"), Protocol: ProtocolTCP, Port: 443})
}

func TestCompileNativePoliciesIsDeterministicUnderObjectOrdering(t *testing.T) {
	policies := []NativeNetworkPolicy{
		nativePolicy("a", "one", map[string]string{"app": "web"}, []string{"Egress"}, nil, []NativeEgressRule{{
			To:    []NativePeer{{NamespaceSelector: &NativeLabelSelector{MatchExpressions: []NativeLabelSelectorRequirement{{Key: "tenant", Operator: "In", Values: []string{"trusted"}}}}, PodSelector: &NativeLabelSelector{MatchLabels: map[string]string{"app": "db"}}}},
			Ports: []NativePort{{Protocol: "TCP", Port: 5432}},
		}}),
		nativePolicy("a", "two", map[string]string{"app": "web"}, []string{"Ingress"}, []NativeIngressRule{{
			From:  []NativePeer{{IPBlock: &NativeIPBlock{CIDR: "198.51.100.0/24", Except: []string{"198.51.100.64/26"}}}},
			Ports: []NativePort{{Protocol: "UDP", Port: 53}},
		}}, nil),
	}
	input := ResolutionInput{
		NodeIPs:    []netip.Addr{mustAddr("192.0.2.11"), mustAddr("192.0.2.10")},
		Namespaces: []ResolvedNamespace{{Name: "a", Labels: map[string]string{"tenant": "local"}}, {Name: "b", Labels: map[string]string{"tenant": "trusted"}}},
		Pods: []ResolvedPod{
			{Namespace: "a", Name: "web", Labels: map[string]string{"app": "web"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{2, 1}, Local: true},
			{Namespace: "b", Name: "db-2", Labels: map[string]string{"app": "db"}, PodIPs: []netip.Addr{mustAddr("10.1.0.4")}},
			{Namespace: "b", Name: "db-1", Labels: map[string]string{"app": "db"}, PodIPs: []netip.Addr{mustAddr("10.1.0.3")}},
		},
	}
	want, err := CompileNativePolicies(policies, input)
	if err != nil {
		t.Fatalf("baseline compile failed: %v", err)
	}

	for seed := uint64(1); seed <= 25; seed++ {
		shuffledPolicies := append([]NativeNetworkPolicy(nil), policies...)
		shuffledInput := input
		shuffledInput.NodeIPs = append([]netip.Addr(nil), input.NodeIPs...)
		shuffledInput.Namespaces = append([]ResolvedNamespace(nil), input.Namespaces...)
		shuffledInput.Pods = append([]ResolvedPod(nil), input.Pods...)
		rng := rand.New(rand.NewPCG(seed, seed+100))
		rng.Shuffle(len(shuffledPolicies), func(i, j int) { shuffledPolicies[i], shuffledPolicies[j] = shuffledPolicies[j], shuffledPolicies[i] })
		rng.Shuffle(len(shuffledInput.NodeIPs), func(i, j int) {
			shuffledInput.NodeIPs[i], shuffledInput.NodeIPs[j] = shuffledInput.NodeIPs[j], shuffledInput.NodeIPs[i]
		})
		rng.Shuffle(len(shuffledInput.Namespaces), func(i, j int) {
			shuffledInput.Namespaces[i], shuffledInput.Namespaces[j] = shuffledInput.Namespaces[j], shuffledInput.Namespaces[i]
		})
		rng.Shuffle(len(shuffledInput.Pods), func(i, j int) {
			shuffledInput.Pods[i], shuffledInput.Pods[j] = shuffledInput.Pods[j], shuffledInput.Pods[i]
		})

		got, compileErr := CompileNativePolicies(shuffledPolicies, shuffledInput)
		if compileErr != nil {
			t.Fatalf("seed %d compile failed: %v", seed, compileErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d produced nondeterministic result\ngot:  %#v\nwant: %#v", seed, got, want)
		}
	}
}

func TestCompileNativePoliciesRejectsPodWithoutNamespaceFacts(t *testing.T) {
	for _, operator := range []string{"NotIn", "DoesNotExist"} {
		t.Run(operator, func(t *testing.T) {
			values := []string(nil)
			if operator == "NotIn" {
				values = []string{"true"}
			}
			policy := nativePolicy("default", "negative-namespace-selector", map[string]string{"app": "client"}, []string{"Egress"}, nil, []NativeEgressRule{{
				To: []NativePeer{{
					NamespaceSelector: &NativeLabelSelector{MatchExpressions: []NativeLabelSelectorRequirement{{
						Key: "trusted", Operator: operator, Values: values,
					}}},
				}},
				Ports: []NativePort{{Protocol: "TCP", Port: 443}},
			}})
			input := ResolutionInput{
				NodeIPs:    []netip.Addr{mustAddr("192.0.2.10")},
				Namespaces: []ResolvedNamespace{{Name: "default"}},
				Pods: []ResolvedPod{
					{Namespace: "default", Name: "client", Labels: map[string]string{"app": "client"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
					{Namespace: "missing", Name: "server", PodIPs: []netip.Addr{mustAddr("10.1.0.2")}},
				},
			}

			_, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, input)
			var resolutionErr ResolutionError
			if !errors.As(err, &resolutionErr) || resolutionErr.Field != `pods["missing/server"].namespace` {
				t.Fatalf("error = %T %v, want missing namespace ResolutionError", err, err)
			}
		})
	}
}

func TestResolvePeersRejectsMissingNamespaceBeforeNegativeSelectorMatch(t *testing.T) {
	for _, operator := range []string{"NotIn", "DoesNotExist"} {
		t.Run(operator, func(t *testing.T) {
			values := []string(nil)
			if operator == "NotIn" {
				values = []string{"true"}
			}
			state := compileState{
				input: ResolutionInput{Pods: []ResolvedPod{{
					Namespace: "missing", Name: "server", PodIPs: []netip.Addr{mustAddr("10.1.0.2")},
				}}},
				namespaces: map[string]map[string]string{},
			}
			policy := nativePolicy("default", "negative-namespace-selector", map[string]string{"app": "client"}, []string{"Egress"}, nil, nil)
			peers := []NativePeer{{
				NamespaceSelector: &NativeLabelSelector{MatchExpressions: []NativeLabelSelectorRequirement{{
					Key: "trusted", Operator: operator, Values: values,
				}}},
			}}

			_, err := state.resolvePeers(&policy, peers)
			var resolutionErr ResolutionError
			if !errors.As(err, &resolutionErr) || resolutionErr.Field != `pods["missing/server"].namespace` {
				t.Fatalf("error = %T %v, want missing namespace ResolutionError", err, err)
			}
		})
	}
}

func TestCompileNativePoliciesCapacityErrors(t *testing.T) {
	t.Run("subjects", func(t *testing.T) {
		pods := make([]ResolvedPod, 0, MaxPolicySubjects+1)
		for i := 1; i <= MaxPolicySubjects+1; i++ {
			pods = append(pods, ResolvedPod{Namespace: "default", Name: "pod-" + netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String(), Labels: map[string]string{"app": "selected"}, CgroupIDs: []uint64{uint64(i)}, Local: true})
		}
		input := basicResolutionInput(pods...)
		policy := nativePolicy("default", "all", map[string]string{"app": "selected"}, []string{"Ingress"}, nil, nil)
		_, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, input)
		var capacityErr CapacityError
		if !errors.As(err, &capacityErr) || capacityErr.Resource != "subject" || capacityErr.Observed != MaxPolicySubjects+1 {
			t.Fatalf("error = %T %v, want subject CapacityError", err, err)
		}
	})

	t.Run("rules", func(t *testing.T) {
		pods := make([]ResolvedPod, 0, 129)
		for i := 1; i <= 129; i++ {
			pods = append(pods, ResolvedPod{Namespace: "default", Name: "pod-" + netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String(), Labels: map[string]string{"app": "selected"}, CgroupIDs: []uint64{uint64(i)}, Local: true})
		}
		peers := make([]NativePeer, 0, 128)
		for i := 1; i <= 128; i++ {
			peer := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
			peers = append(peers, NativePeer{IPBlock: &NativeIPBlock{CIDR: peer.String() + "/32"}})
		}
		policy := nativePolicy("default", "many", map[string]string{"app": "selected"}, []string{"Egress"}, nil, []NativeEgressRule{{To: peers, Ports: []NativePort{{Protocol: "TCP", Port: 443}}}})
		_, err := CompileNativePolicies([]NativeNetworkPolicy{policy}, basicResolutionInput(pods...))
		var capacityErr CapacityError
		if !errors.As(err, &capacityErr) || capacityErr.Resource != "rule" || capacityErr.Observed != MaxPolicyRules+1 {
			t.Fatalf("error = %T %v, want rule CapacityError", err, err)
		}
	})

	t.Run("node bypasses", func(t *testing.T) {
		nodeIPs := make([]netip.Addr, 0, MaxPolicyRules+1)
		for i := 0; i < MaxPolicyRules+1; i++ {
			nodeIPs = append(nodeIPs, netip.AddrFrom4([4]byte{192, byte(i >> 16), byte(i >> 8), byte(i)}))
		}
		_, err := CompileNativePolicies(nil, ResolutionInput{NodeIPs: nodeIPs})
		var capacityErr CapacityError
		if !errors.As(err, &capacityErr) || capacityErr.Resource != "rule" || capacityErr.Observed != MaxPolicyRules+1 {
			t.Fatalf("error = %T %v, want node-bypass CapacityError", err, err)
		}
	})
}

func TestPolicySetRuleEntryCountIncludesNodeAndSelfBypasses(t *testing.T) {
	set := PolicySet{
		NodeIPs: []netip.Addr{mustAddr("192.0.2.10"), mustAddr("192.0.2.11")},
		Subjects: []Subject{{
			CgroupID: 1,
			PodIPs:   []netip.Addr{mustAddr("10.0.0.2"), mustAddr("10.0.0.3")},
		}},
		Rules: make([]Rule, 3),
	}
	if got, want := policySetRuleEntryCount(set), 7; got != want {
		t.Fatalf("rule entry count = %d, want %d", got, want)
	}
}

func TestValidatePolicySetRejectsQuarantineOutsideIsolation(t *testing.T) {
	err := ValidatePolicySet(PolicySet{
		NodeIPs:  []netip.Addr{mustAddr("192.0.2.10")},
		Subjects: []Subject{{CgroupID: 1, Isolated: DirectionIngress, Quarantined: DirectionEgress}},
	})
	var resolutionErr ResolutionError
	if !errors.As(err, &resolutionErr) || resolutionErr.Field != "subjects[0].quarantined" {
		t.Fatalf("error = %T %v, want quarantine ResolutionError", err, err)
	}
}

func TestCuratedNativeExamplesValidateAndCompile(t *testing.T) {
	tests := []struct {
		name  string
		input ResolutionInput
		want  PolicySet
	}{
		{
			name: "default-deny.yaml",
			input: basicResolutionInput(
				ResolvedPod{Namespace: "default", Name: "api", Labels: map[string]string{"app": "api"}, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}, CgroupIDs: []uint64{1}, Local: true},
			),
			want: PolicySet{
				NodeIPs:  []netip.Addr{mustAddr("192.0.2.10")},
				Subjects: []Subject{{CgroupID: 1, Isolated: DirectionIngress | DirectionEgress, PodIPs: []netip.Addr{mustAddr("10.0.0.2")}}},
			},
		},
		{
			name: "allow-dns.yaml",
			input: basicResolutionInput(
				ResolvedPod{Namespace: "default", Name: "client", Labels: map[string]string{"app": "client"}, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}, CgroupIDs: []uint64{2}, Local: true},
			),
			want: PolicySet{
				NodeIPs:  []netip.Addr{mustAddr("192.0.2.10")},
				Subjects: []Subject{{CgroupID: 2, Isolated: DirectionEgress, PodIPs: []netip.Addr{mustAddr("10.0.0.3")}}},
				Rules: []Rule{
					{CgroupID: 2, Direction: DirectionEgress, Peer: mustPrefix("10.96.0.10/32"), Protocol: ProtocolTCP, Port: 53},
					{CgroupID: 2, Direction: DirectionEgress, Peer: mustPrefix("10.96.0.10/32"), Protocol: ProtocolUDP, Port: 53},
				},
			},
		},
		{
			name: "web-to-db.yaml",
			input: basicResolutionInput(
				ResolvedPod{Namespace: "default", Name: "web", Labels: map[string]string{"app": "web"}, PodIPs: []netip.Addr{mustAddr("10.0.0.4")}, CgroupIDs: []uint64{3}, Local: true},
				ResolvedPod{Namespace: "default", Name: "db", Labels: map[string]string{"app": "db"}, PodIPs: []netip.Addr{mustAddr("10.0.0.5")}, CgroupIDs: []uint64{4}, Local: true},
			),
			want: PolicySet{
				NodeIPs: []netip.Addr{mustAddr("192.0.2.10")},
				Subjects: []Subject{
					{CgroupID: 3, Isolated: DirectionEgress, PodIPs: []netip.Addr{mustAddr("10.0.0.4")}},
					{CgroupID: 4, Isolated: DirectionIngress, PodIPs: []netip.Addr{mustAddr("10.0.0.5")}},
				},
				Rules: []Rule{
					{CgroupID: 3, Direction: DirectionEgress, Peer: mustPrefix("10.0.0.5/32"), Protocol: ProtocolTCP, Port: 5432},
					{CgroupID: 4, Direction: DirectionIngress, Peer: mustPrefix("10.0.0.4/32"), Protocol: ProtocolTCP, Port: 5432},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "examples", "native", tt.name))
			if err != nil {
				t.Fatalf("read example: %v", err)
			}
			policies, err := LoadNativePoliciesFromBytes(data)
			if err != nil {
				t.Fatalf("validate example: %v", err)
			}
			result, err := CompileNativePolicies(policies, tt.input)
			if err != nil {
				t.Fatalf("compile example: %v", err)
			}
			if len(result.Rejected) != 0 {
				t.Fatalf("example was rejected: %#v", result.Rejected)
			}
			if !reflect.DeepEqual(result.PolicySet, tt.want) {
				t.Fatalf("compiled policy set\ngot:  %#v\nwant: %#v", result.PolicySet, tt.want)
			}
		})
	}
}

func nativePolicy(namespace, name string, subjectLabels map[string]string, policyTypes []string, ingress []NativeIngressRule, egress []NativeEgressRule) NativeNetworkPolicy {
	var types *[]string
	if policyTypes != nil {
		copyOfTypes := append([]string(nil), policyTypes...)
		types = &copyOfTypes
	}
	return NativeNetworkPolicy{
		APIVersion: NativeNetworkPolicyAPIVersion,
		Kind:       NativeNetworkPolicyKind,
		Metadata:   &NativeObjectMeta{Namespace: namespace, Name: name},
		Spec: &NativeNetworkPolicySpec{
			PodSelector: &NativeLabelSelector{MatchLabels: subjectLabels},
			PolicyTypes: types,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func basicResolutionInput(pods ...ResolvedPod) ResolutionInput {
	return ResolutionInput{
		NodeIPs:    []netip.Addr{mustAddr("192.0.2.10")},
		Namespaces: []ResolvedNamespace{{Name: "default"}},
		Pods:       pods,
	}
}

func mustAddr(value string) netip.Addr { return netip.MustParseAddr(value) }

func mustPrefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }

func subjectByCgroup(t *testing.T, set PolicySet, cgroupID uint64) Subject {
	t.Helper()
	for _, subject := range set.Subjects {
		if subject.CgroupID == cgroupID {
			return subject
		}
	}
	t.Fatalf("cgroup %d not found in %#v", cgroupID, set.Subjects)
	return Subject{}
}

func assertRulePresent(t *testing.T, set PolicySet, want Rule) {
	t.Helper()
	for _, rule := range set.Rules {
		if rule == want {
			return
		}
	}
	t.Fatalf("rule %#v not found in %#v", want, set.Rules)
}
