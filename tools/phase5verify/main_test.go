package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	testKernelRelease = "6.1.0-test"
	testRunID         = "test-phase5-run"
)

func TestVerifyDirectoryAcceptsCompleteEvidenceSet(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, value any) {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), payload, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("phase5-performance.json", referenceEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects:         referenceSubjects,
		Policies:         referencePolicies,
		Rules:            referenceRules,
		ApplySamplesMS:   []float64{100, 150, 200},
		ApplyP95MS:       200,
		ApplyBudgetMS:    applyBudgetMS,
		MapMemory:        referenceMapMemoryEntries(2),
		MapMemorySamples: repeatedSamples + 2,
		MapMemoryHistory: validMapMemoryHistory(),
		MapMemoryStable:  true,
		KernelPathScope:  referenceKernelPathScope,
	})
	write("phase5-flow.json", flowEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		RequestedRate: flowRate, TrafficPattern: flowTrafficPattern, DurationSeconds: flowSeconds, Decisions: flowRate * flowSeconds,
		DeliveredEvents: flowRate * flowSeconds, AccountingTotal: flowRate * flowSeconds, AccountingBalanced: true,
		Scope: flowScope,
	})
	write("phase5-packet.json", validPacketEvidence())
	write("phase5-agent.json", activationEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, CgroupRoot: "/sys/fs/cgroup", BPFFSRoot: "/sys/fs/bpf", Scope: activationScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		ActivationMS: []float64{100, 200, 300}, ActivationP95: 300, BudgetMS: activationBudget,
	})
	write("phase5-agent-reconcile.json", reconciliationEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: reconciliationScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules, Samples: repeatedSamples,
		ReconcileMS: []float64{100, 200, 300}, ReconcileP95: 300, BudgetMS: reconcileBudget,
	})
	write("phase5-agent-event.json", eventEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: eventScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		EventMS: []float64{100, 200, 300}, EventP95: 300, BudgetMS: eventBudget,
	})
	write("phase5-agent-pod-start.json", podStartEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: podStartScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		Samples: repeatedSamples, InitialClassifications: referenceSubjects,
		PodStart: []float64{1, 2, 3}, PodStartP95: 3,
	})
	write("phase5-agent-restart.json", restartEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: restartScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		RestartMS: []float64{10, 20, 30}, RestartP95: 30,
	})
	write("phase5-agent-crash.json", crashEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: crashScope,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		Samples: repeatedSamples, CrashGapMS: []float64{1, 2, 3}, CrashGapP95: 3,
	})
	write("phase5-agent-resource.json", resourceEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: resourceScope,
		Samples: repeatedSamples, QuietSeconds: 5, Subjects: referenceSubjects,
		Policies: referencePolicies, Rules: referenceRules,
		ClockTicks:     100,
		CPUCoreSamples: []float64{0.01, 0.02, 0.03}, RSSMiBSamples: []float64{100, 110, 120},
		MaxCPUCore: 0.03, MaxRSSMiB: 120, CPUBudgetCores: cpuBudgetCores, RSSBudgetMiB: rssBudgetMiB,
	})

	if err := verifyDirectory(directory, testRunID); err != nil {
		t.Fatalf("complete evidence set rejected: %v", err)
	}
	for _, scopeCase := range []struct {
		name  string
		scope string
	}{
		{name: "phase5-performance.json", scope: referenceKernelPathScope},
		{name: "phase5-flow.json", scope: flowScope},
		{name: "phase5-packet.json", scope: packetScope},
		{name: "phase5-agent.json", scope: activationScope},
		{name: "phase5-agent-reconcile.json", scope: reconciliationScope},
		{name: "phase5-agent-event.json", scope: eventScope},
		{name: "phase5-agent-pod-start.json", scope: podStartScope},
		{name: "phase5-agent-restart.json", scope: restartScope},
		{name: "phase5-agent-crash.json", scope: crashScope},
		{name: "phase5-agent-resource.json", scope: resourceScope},
	} {
		path := filepath.Join(directory, scopeCase.name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s for scope mutation: %v", scopeCase.name, err)
		}
		mutated := strings.Replace(string(original), scopeCase.scope, scopeCase.scope+" (forged)", 1)
		if mutated == string(original) {
			t.Fatalf("scope %s was not present in %s", scopeCase.scope, scopeCase.name)
		}
		if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
			t.Fatalf("write forged %s: %v", scopeCase.name, err)
		}
		if err := verifyDirectory(directory, testRunID); err == nil {
			t.Fatalf("evidence set accepted forged producer scope in %s", scopeCase.name)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatalf("restore %s after scope mutation: %v", scopeCase.name, err)
		}
	}
	if err := verifyDirectory(directory, "different-run"); err == nil {
		t.Fatal("evidence set accepted an unexpected run ID")
	}
	if err := os.WriteFile(filepath.Join(directory, "phase5-extra.json"), []byte(`{"unexpected":true}`), 0o600); err != nil {
		t.Fatalf("write unexpected evidence: %v", err)
	}
	if err := verifyDirectory(directory, testRunID); err == nil {
		t.Fatal("evidence set accepted an unexpected direct Phase 5 JSON artifact")
	}
	if err := os.Remove(filepath.Join(directory, "phase5-extra.json")); err != nil {
		t.Fatalf("remove unexpected direct evidence: %v", err)
	}
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("create nested evidence directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "phase5-extra.json"), []byte(`{"unexpected":true}`), 0o600); err != nil {
		t.Fatalf("write unexpected nested evidence: %v", err)
	}
	if err := verifyDirectory(directory, testRunID); err == nil {
		t.Fatal("evidence set accepted an unexpected nested Phase 5 JSON artifact")
	}
	if err := os.Remove(filepath.Join(nested, "phase5-extra.json")); err != nil {
		t.Fatalf("remove unexpected nested evidence: %v", err)
	}
	caseVariant := filepath.Join(directory, "Phase5-performance.json")
	if err := os.WriteFile(caseVariant, []byte(`{"unexpected":true}`), 0o600); err != nil {
		t.Fatalf("write case-variant evidence: %v", err)
	}
	if err := verifyDirectory(directory, testRunID); err == nil {
		t.Fatal("evidence set accepted a case-variant Phase 5 JSON artifact")
	}
	if err := os.Remove(caseVariant); err != nil {
		t.Fatalf("remove case-variant evidence: %v", err)
	}
	if err := os.Remove(nested); err != nil {
		t.Fatalf("remove nested evidence directory: %v", err)
	}
	symlinkTarget := filepath.Join(directory, "symlink-target")
	if err := os.Mkdir(symlinkTarget, 0o700); err != nil {
		t.Fatalf("create symlink target: %v", err)
	}
	if err := os.Symlink(symlinkTarget, filepath.Join(directory, "evidence-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := verifyDirectory(directory, testRunID); err == nil {
		t.Fatal("evidence set accepted a symlinked evidence-tree entry")
	}
}

func validPacketEvidence() packetEvidence {
	return packetEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules, Samples: repeatedSamples,
		RoundTripsPerSample: packetRoundTrips, TCPBytesPerSample: packetTCPBytes,
		BaselineLatencyP99US: []float64{1, 2, 3}, EnforcedLatencyP99US: []float64{2, 4, 5},
		LatencyDeltaP99US: 2, LatencyBudgetUS: latencyBudgetUS,
		BaselineTCPMbps: []float64{100, 100, 100}, EnforcedTCPMbps: []float64{95, 90, 100},
		MaxThroughputRegression: 10, ThroughputBudgetPercent: throughputBudget,
		Scope: packetScope,
	}
}

func validMapMemoryHistory() []mapMemorySnapshot {
	stages := []string{"before_warmup", "after_warmup", "after_apply_1", "after_apply_2", "after_apply_3"}
	history := make([]mapMemorySnapshot, 0, len(stages))
	for _, stage := range stages {
		history = append(history, mapMemorySnapshot{
			Stage: stage,
			Maps:  referenceMapMemoryEntries(2),
		})
	}
	return history
}

func referenceMapMemoryEntries(cpus int) []mapMemoryEvidence {
	entries := make([]mapMemoryEvidence, len(referenceMapMemoryShape))
	copy(entries, referenceMapMemoryShape)
	for index := range entries {
		capacity, err := calculatedMapCapacity(entries[index], cpus)
		if err != nil {
			panic(err)
		}
		entries[index].CalculatedCapacityBytes = capacity
	}
	return entries
}

func TestValidateFlowRequiresComponentAccounting(t *testing.T) {
	evidence := flowEvidence{
		RunID:              testRunID,
		Subjects:           referenceSubjects,
		Policies:           referencePolicies,
		Rules:              referenceRules,
		RequestedRate:      flowRate,
		TrafficPattern:     flowTrafficPattern,
		DurationSeconds:    flowSeconds,
		Decisions:          flowRate * flowSeconds,
		DeliveredEvents:    flowRate * flowSeconds,
		RateLimitedEvents:  1,
		AccountingTotal:    flowRate * flowSeconds,
		AccountingBalanced: true,
		Scope:              flowScope,
	}
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted accounting total that omits a component")
	}
}

func TestValidateFlowRejectsImpossibleDecisionRate(t *testing.T) {
	decisions := uint64(flowRate*flowSeconds + flowRate*2)
	evidence := flowEvidence{
		RunID:              testRunID,
		Subjects:           referenceSubjects,
		Policies:           referencePolicies,
		Rules:              referenceRules,
		RequestedRate:      flowRate,
		TrafficPattern:     flowTrafficPattern,
		DurationSeconds:    flowSeconds,
		Decisions:          decisions,
		DeliveredEvents:    decisions,
		AccountingTotal:    decisions,
		AccountingBalanced: true,
		Scope:              flowScope,
	}
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted a decision count above the one-packet-per-millisecond rate")
	}
}

func TestValidateFlowRejectsInflatedDuration(t *testing.T) {
	evidence := flowEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		RequestedRate: flowRate, TrafficPattern: flowTrafficPattern, DurationSeconds: flowMaxSeconds + 1,
		Decisions: flowRate * flowSeconds, DeliveredEvents: flowRate * flowSeconds,
		AccountingTotal: flowRate * flowSeconds, AccountingBalanced: true, Scope: flowScope,
	}
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted an overlong flow measurement duration")
	}
}

func TestValidateReferenceRecomputesMapMemoryHistory(t *testing.T) {
	evidence := referenceEvidence{
		TimestampUTC:     "2026-09-19T00:00:00Z",
		RunID:            testRunID,
		GoVersion:        "go1.26.6",
		GOOS:             "linux",
		GOARCH:           "amd64",
		CPUs:             2,
		Subjects:         referenceSubjects,
		Policies:         referencePolicies,
		Rules:            referenceRules,
		ApplySamplesMS:   []float64{100, 150, 200},
		ApplyP95MS:       200,
		ApplyBudgetMS:    applyBudgetMS,
		KernelPathScope:  referenceKernelPathScope,
		MapMemory:        validMapMemoryHistory()[len(validMapMemoryHistory())-1].Maps,
		MapMemorySamples: repeatedSamples + 2,
		MapMemoryHistory: validMapMemoryHistory(),
		MapMemoryStable:  true,
	}
	if err := validateReference(evidence); err != nil {
		t.Fatalf("valid map memory history rejected: %v", err)
	}
	evidence.Policies--
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted a reduced policy fixture")
	}
	evidence.Policies++
	evidence.MapMemoryHistory[0].Maps[0].CalculatedCapacityBytes++
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted a fabricated map capacity")
	}
	evidence.MapMemoryHistory[0].Maps[0].CalculatedCapacityBytes--
	evidence.MapMemoryHistory[2].Maps[0].MaxEntries++
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted changed map capacity in history")
	}
	evidence.MapMemoryHistory[2].Maps[0].MaxEntries--
	evidence.MapMemoryHistory[1].Stage = "after_apply_0"
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted an unexpected map-history stage")
	}
	evidence.MapMemoryHistory[1].Stage = referenceMapMemoryStages[1]
	evidence.MapMemoryHistory[0].Maps = evidence.MapMemoryHistory[0].Maps[:len(evidence.MapMemoryHistory[0].Maps)-1]
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted an incomplete engine map inventory")
	}
	evidence.MapMemoryHistory[0].Maps = referenceMapMemoryEntries(2)
	for snapshotIndex := range evidence.MapMemoryHistory {
		for mapIndex := range evidence.MapMemoryHistory[snapshotIndex].Maps {
			evidence.MapMemoryHistory[snapshotIndex].Maps[mapIndex].MemlockAvailable = true
			evidence.MapMemoryHistory[snapshotIndex].Maps[mapIndex].ObservedMemlockBytes = 100
		}
	}
	evidence.MapMemory = append([]mapMemoryEvidence(nil), evidence.MapMemoryHistory[len(evidence.MapMemoryHistory)-1].Maps...)
	evidence.MapMemoryHistory[2].Maps[0].ObservedMemlockBytes++
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted growing map memlock")
	}
	evidence.MapMemoryHistory[2].Maps[0].ObservedMemlockBytes--
	evidence.MapMemory[0].ObservedMemlockBytes++
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted final map summary memlock that differs from its retained snapshot")
	}
	evidence.MapMemory[0].ObservedMemlockBytes--
	evidence.MapMemoryHistory[0].Maps[0].ObservedMemlockBytes = 0
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted zero available map memlock")
	}
	evidence.MapMemoryHistory[0].Maps[0].MemlockAvailable = false
	if err := validateReference(evidence); err != nil {
		t.Fatalf("validateReference rejected first-population memlock allocation: %v", err)
	}
	evidence.MapMemoryHistory[2].Maps[0].MemlockAvailable = false
	evidence.MapMemoryHistory[2].Maps[0].ObservedMemlockBytes = 0
	if err := validateReference(evidence); err == nil {
		t.Fatal("validateReference accepted memlock availability loss after warm-up")
	}
}

func TestValidateMapMemoryRejectsUnknownDuplicateAndUnsortedEntries(t *testing.T) {
	entries := []mapMemoryEvidence{
		{Name: "a", Type: "Hash", MaxEntries: 1, KeySize: 4, ValueSize: 4, CapacityBounded: true, CalculatedCapacityBytes: 8},
		{Name: "b", Type: "Hash", MaxEntries: 1, KeySize: 4, ValueSize: 4, CapacityBounded: true, CalculatedCapacityBytes: 8},
	}
	if err := validateMapMemoryEntries(entries, 2); err != nil {
		t.Fatalf("valid sorted map entries rejected: %v", err)
	}
	entries[1].Name = "a"
	if err := validateMapMemoryEntries(entries, 2); err == nil {
		t.Fatal("validateMapMemoryEntries accepted duplicate map names")
	}
	entries[1].Name = "0"
	if err := validateMapMemoryEntries(entries, 2); err == nil {
		t.Fatal("validateMapMemoryEntries accepted unsorted map names")
	}
	entries[1] = mapMemoryEvidence{Name: "b", Type: "Unknown", MaxEntries: 1, KeySize: 4, ValueSize: 4, CapacityBounded: true, CalculatedCapacityBytes: 8}
	if err := validateMapMemoryEntries(entries, 2); err == nil {
		t.Fatal("validateMapMemoryEntries accepted an unknown map type")
	}
}

func TestValidateMapMemoryAcceptsUnboundedCgroupStorage(t *testing.T) {
	entries := []mapMemoryEvidence{{Name: "attached_cgroup", Type: "CGroupStorage", KeySize: 16, ValueSize: 8}}
	if err := validateMapMemoryEntries(entries, 2); err != nil {
		t.Fatalf("unbounded cgroup-storage evidence rejected: %v", err)
	}
}

func TestValidateMapMemoryRejectsUnavailableNonZeroMemlock(t *testing.T) {
	entries := []mapMemoryEvidence{{
		Name: "rules", Type: "Hash", MaxEntries: 1, KeySize: 4, ValueSize: 4,
		CapacityBounded: true, CalculatedCapacityBytes: 8, ObservedMemlockBytes: 1,
	}}
	if err := validateMapMemoryEntries(entries, 2); err == nil {
		t.Fatal("validateMapMemoryEntries accepted nonzero memlock with unavailable status")
	}
}

func TestValidateEvidenceSetRejectsMixedEnvironment(t *testing.T) {
	base := phase5EvidenceEnvironment{Artifact: "reference", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2}
	if err := validateEvidenceSetEnvironment(base, base); err != nil {
		t.Fatalf("consistent evidence environment rejected: %v", err)
	}
	if err := validateEvidenceSetEnvironment(phase5EvidenceEnvironment{Artifact: "missing-run"}, base); err == nil {
		t.Fatal("missing run ID accepted")
	}
	if err := validateEvidenceSetEnvironment(base, phase5EvidenceEnvironment{
		Artifact: "flow", RunID: "different-run", GoVersion: base.GoVersion, GOOS: base.GOOS, GOARCH: base.GOARCH, CPUs: base.CPUs,
	}); err == nil {
		t.Fatal("mixed run IDs accepted")
	}
	if err := validateEvidenceSetEnvironment(base, phase5EvidenceEnvironment{
		Artifact: "packet", RunID: base.RunID, GoVersion: base.GoVersion, GOOS: base.GOOS, GOARCH: "arm64", CPUs: base.CPUs,
	}); err == nil {
		t.Fatal("mixed architecture evidence accepted")
	}
	if err := validateEvidenceSetEnvironment(base, phase5EvidenceEnvironment{
		Artifact: "resource", RunID: base.RunID, GoVersion: base.GoVersion, GOOS: base.GOOS, GOARCH: base.GOARCH, CPUs: 4,
	}); err == nil {
		t.Fatal("mixed CPU profile evidence accepted")
	}
}

func TestValidateAgentKernelReleasesRejectsMixedHosts(t *testing.T) {
	base := phase5AgentProvenance{Artifact: "activation", KernelRelease: testKernelRelease}
	if err := validateAgentKernelReleases(base, base); err != nil {
		t.Fatalf("consistent agent provenance rejected: %v", err)
	}
	if err := validateAgentKernelReleases(base, phase5AgentProvenance{Artifact: "crash", KernelRelease: "6.8.0-other"}); err == nil {
		t.Fatal("mixed kernel releases accepted")
	}
}

func TestValidatePacketRecomputesAggregates(t *testing.T) {
	evidence := validPacketEvidence()
	if err := validatePacket(evidence); err != nil {
		t.Fatalf("valid packet evidence rejected: %v", err)
	}
	evidence.LatencyDeltaP99US = 1
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted an inconsistent latency aggregate")
	}
}

func TestValidatePacketRequiresPositiveMeasurements(t *testing.T) {
	evidence := validPacketEvidence()
	evidence.BaselineTCPMbps[0] = 0
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted a zero TCP measurement")
	}
}

func TestValidatePacketRequiresReferenceEnvironment(t *testing.T) {
	evidence := validPacketEvidence()
	evidence.Policies--
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted a reduced policy fixture")
	}
	evidence = validPacketEvidence()
	evidence.GOOS = "darwin"
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted non-Linux evidence")
	}
	evidence = validPacketEvidence()
	evidence.CPUs = 1
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted a non-reference CPU profile")
	}
	evidence = validPacketEvidence()
	evidence.CPUs = 4
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted an expanded CPU profile")
	}
	evidence = validPacketEvidence()
	evidence.TimestampUTC = "not-a-timestamp"
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted a non-RFC3339 timestamp")
	}
}

func TestValidatePodStartRequiresReferenceFixture(t *testing.T) {
	evidence := podStartEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		Samples: repeatedSamples, InitialClassifications: referenceSubjects,
		PodStart: []float64{1, 2, 3}, PodStartP95: 3, Scope: podStartScope,
	}
	if err := validatePodStart(evidence); err != nil {
		t.Fatalf("valid Pod-start evidence rejected: %v", err)
	}
	evidence.Policies--
	if err := validatePodStart(evidence); err == nil {
		t.Fatal("validatePodStart accepted a reduced policy fixture")
	}
}

func TestValidateEvidenceRequiresProducerMetadata(t *testing.T) {
	missingRunID := validPacketEvidence()
	missingRunID.RunID = ""
	if err := validatePacket(missingRunID); err == nil {
		t.Fatal("validatePacket accepted missing run ID metadata")
	}

	packet := validPacketEvidence()
	packet.Scope = ""
	if err := validatePacket(packet); err == nil {
		t.Fatal("validatePacket accepted missing scope metadata")
	}

	flow := flowEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules, Scope: flowScope,
		RequestedRate: flowRate, DurationSeconds: flowSeconds, Decisions: flowRate * flowSeconds,
		DeliveredEvents: flowRate * flowSeconds, AccountingTotal: flowRate * flowSeconds, AccountingBalanced: true,
	}
	if err := validateFlow(flow); err == nil {
		t.Fatal("validateFlow accepted missing traffic-pattern metadata")
	}
}

func TestValidateFlowRequiresReferenceFixture(t *testing.T) {
	evidence := flowEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		Subjects: referenceSubjects - 1, Policies: referencePolicies, Rules: referenceRules,
		RequestedRate: flowRate, TrafficPattern: flowTrafficPattern, DurationSeconds: flowSeconds,
		Decisions: flowRate * flowSeconds, DeliveredEvents: flowRate * flowSeconds,
		AccountingTotal: flowRate * flowSeconds, AccountingBalanced: true, Scope: flowScope,
	}
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted a flow transcript from the wrong fixture shape")
	}

	evidence.Subjects = referenceSubjects
	evidence.Rules = referenceRules - 1
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted a flow transcript from the wrong rule shape")
	}

	evidence.Rules = referenceRules
	evidence.Policies = referencePolicies - 1
	if err := validateFlow(evidence); err == nil {
		t.Fatal("validateFlow accepted a flow transcript from the wrong policy shape")
	}
}

func TestValidateCrashRequiresReferenceFixture(t *testing.T) {
	evidence := crashEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Subjects: referenceSubjects, Policies: referencePolicies, Rules: referenceRules,
		Samples: repeatedSamples, CrashGapMS: []float64{1, 2, 3}, CrashGapP95: 3, Scope: crashScope,
	}
	if err := validateCrash(evidence); err != nil {
		t.Fatalf("valid crash evidence rejected: %v", err)
	}
	evidence.Rules--
	if err := validateCrash(evidence); err == nil {
		t.Fatal("validateCrash accepted a reduced fixture shape")
	}
}

func TestReadEvidenceRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	directory := t.TempDir()
	unknownPath := filepath.Join(directory, "unknown.json")
	if err := os.WriteFile(unknownPath, []byte(`{"timestamp_utc":"2026-09-19T00:00:00Z","unexpected":true}`), 0o600); err != nil {
		t.Fatalf("write unknown-field evidence: %v", err)
	}
	var evidence activationEvidence
	if err := readEvidence(unknownPath, &evidence); err == nil {
		t.Fatal("readEvidence accepted an unknown field")
	}

	trailingPath := filepath.Join(directory, "trailing.json")
	if err := os.WriteFile(trailingPath, []byte(`{"timestamp_utc":"2026-09-19T00:00:00Z"} {}`), 0o600); err != nil {
		t.Fatalf("write trailing evidence: %v", err)
	}
	if err := readEvidence(trailingPath, &evidence); err == nil {
		t.Fatal("readEvidence accepted multiple JSON values")
	}

	duplicatePath := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"timestamp_utc":"2026-09-19T00:00:00Z","timestamp_utc":"2026-09-20T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write duplicate-field evidence: %v", err)
	}
	if err := readEvidence(duplicatePath, &evidence); err == nil {
		t.Fatal("readEvidence accepted duplicate JSON object fields")
	}

	caseVariantPath := filepath.Join(directory, "case-variant.json")
	if err := os.WriteFile(caseVariantPath, []byte(`{"Timestamp_UTC":"2026-09-19T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write case-variant evidence: %v", err)
	}
	if err := readEvidence(caseVariantPath, &evidence); err == nil {
		t.Fatal("readEvidence accepted a case-variant JSON field")
	}
}

func TestReadEvidenceRejectsMissingSchemaFields(t *testing.T) {
	directory := t.TempDir()
	activationPayload, err := json.Marshal(activationEvidence{})
	if err != nil {
		t.Fatalf("marshal activation evidence: %v", err)
	}
	var activationFields map[string]json.RawMessage
	if err := json.Unmarshal(activationPayload, &activationFields); err != nil {
		t.Fatalf("decode activation evidence: %v", err)
	}
	delete(activationFields, "scope")
	activationPayload, err = json.Marshal(activationFields)
	if err != nil {
		t.Fatalf("marshal missing top-level field evidence: %v", err)
	}
	activationPath := filepath.Join(directory, "activation.json")
	if err := os.WriteFile(activationPath, activationPayload, 0o600); err != nil {
		t.Fatalf("write missing top-level field evidence: %v", err)
	}
	var activation activationEvidence
	if err := readEvidence(activationPath, &activation); err == nil {
		t.Fatal("readEvidence accepted a missing top-level schema field")
	}

	referencePayload, err := json.Marshal(referenceEvidence{
		MapMemory:        referenceMapMemoryEntries(2),
		MapMemoryHistory: validMapMemoryHistory(),
	})
	if err != nil {
		t.Fatalf("marshal reference evidence: %v", err)
	}
	var referenceFields map[string]json.RawMessage
	if err := json.Unmarshal(referencePayload, &referenceFields); err != nil {
		t.Fatalf("decode reference evidence: %v", err)
	}
	var maps []map[string]json.RawMessage
	if err := json.Unmarshal(referenceFields["map_memory"], &maps); err != nil {
		t.Fatalf("decode map memory evidence: %v", err)
	}
	delete(maps[0], "memlock_available")
	referenceFields["map_memory"], err = json.Marshal(maps)
	if err != nil {
		t.Fatalf("marshal missing nested field evidence: %v", err)
	}
	referencePayload, err = json.Marshal(referenceFields)
	if err != nil {
		t.Fatalf("marshal nested field evidence: %v", err)
	}
	referencePath := filepath.Join(directory, "reference.json")
	if err := os.WriteFile(referencePath, referencePayload, 0o600); err != nil {
		t.Fatalf("write missing nested field evidence: %v", err)
	}
	var reference referenceEvidence
	if err := readEvidence(referencePath, &reference); err == nil {
		t.Fatal("readEvidence accepted a missing nested schema field")
	}
	delete(maps[0], "memlock_available")
	maps[0]["memlock_available"] = json.RawMessage("null")
	referenceFields["map_memory"], err = json.Marshal(maps)
	if err != nil {
		t.Fatalf("marshal null nested field evidence: %v", err)
	}
	referencePayload, err = json.Marshal(referenceFields)
	if err != nil {
		t.Fatalf("marshal null nested field evidence: %v", err)
	}
	if err := os.WriteFile(referencePath, referencePayload, 0o600); err != nil {
		t.Fatalf("write null nested field evidence: %v", err)
	}
	if err := readEvidence(referencePath, &reference); err == nil {
		t.Fatal("readEvidence accepted a null nested schema field")
	}
}

func TestValidateStrictJSONKeysRejectsExcessiveNesting(t *testing.T) {
	nested := strings.Repeat("[", maxEvidenceJSONDepth+1) + "0" + strings.Repeat("]", maxEvidenceJSONDepth+1)
	if err := validateStrictJSONKeys([]byte(nested)); err == nil {
		t.Fatal("strict JSON scanner accepted excessively nested JSON")
	}
}

func TestVerifyEnvironmentFileAcceptsReferenceProvenance(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	commit := strings.Repeat("a", 40)
	values := validEnvironmentValues("release")
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "v0.1.0", "amd64"); err != nil {
		t.Fatalf("valid environment evidence rejected: %v", err)
	}
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "v0.2.0", "amd64"); err == nil {
		t.Fatal("environment evidence accepted an unexpected release reference")
	}
	values["commit"] = "not-a-commit"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", "", "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment evidence accepted a malformed release commit without an expected value")
	}
	referencePayload, err := json.Marshal(referenceEvidence{
		RunID: "github-77-commit", GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		ApplySamplesMS: []float64{}, MapMemory: []mapMemoryEvidence{}, MapMemoryHistory: []mapMemorySnapshot{},
	})
	if err != nil {
		t.Fatalf("marshal reference provenance: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "phase5-performance.json"), referencePayload, 0o600); err != nil {
		t.Fatalf("write reference provenance: %v", err)
	}
	resourcePayload, err := json.Marshal(resourceEvidence{ClockTicks: 100, CPUCoreSamples: []float64{}, RSSMiBSamples: []float64{}})
	if err != nil {
		t.Fatalf("marshal resource provenance: %v", err)
	}
	resourcePath := filepath.Join(directory, "phase5-agent-resource.json")
	if err := os.WriteFile(resourcePath, resourcePayload, 0o600); err != nil {
		t.Fatalf("write resource provenance: %v", err)
	}
	if err := verifyEnvironmentMatchesEvidence(path, directory); err != nil {
		t.Fatalf("matching environment provenance rejected: %v", err)
	}
	if err := os.WriteFile(resourcePath, []byte(`{"process_clock_ticks_per_second":101}`), 0o600); err != nil {
		t.Fatalf("write mismatched resource provenance: %v", err)
	}
	if err := verifyEnvironmentMatchesEvidence(path, directory); err == nil {
		t.Fatal("environment provenance accepted a mismatched process clock rate")
	}
	if err := os.WriteFile(resourcePath, resourcePayload, 0o600); err != nil {
		t.Fatalf("restore resource provenance: %v", err)
	}
	values["commit"] = commit
	values["ref"] = "refs/tags/v0.1"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment evidence accepted an invalid release reference")
	}
	values = validEnvironmentValues("release")
	values["workflow_path"] = ".github/workflows/other.yml"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment evidence accepted an invalid release workflow")
	}
	values = validEnvironmentValues("release")
	values["phase5_run_id"] = "other-run"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentMatchesEvidence(path, directory); err == nil {
		t.Fatal("environment provenance accepted a mismatched Phase 5 run ID")
	}
	if err := verifyEnvironmentFile(path, "different-run", "12345", commit, "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment evidence accepted an unexpected Phase 5 run ID")
	}
}

func TestVerifyEnvironmentMatchesEvidenceRejectsMixedToolchain(t *testing.T) {
	directory := t.TempDir()
	environmentPath := filepath.Join(directory, "phase5-environment.txt")
	writeEnvironmentFixture(t, environmentPath, validEnvironmentValues("release"))
	payload, err := json.Marshal(referenceEvidence{GoVersion: "go1.27.1", GOOS: "linux", GOARCH: "amd64", CPUs: 2})
	if err != nil {
		t.Fatalf("marshal mixed reference evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "phase5-performance.json"), payload, 0o600); err != nil {
		t.Fatalf("write mixed reference evidence: %v", err)
	}
	if err := verifyEnvironmentMatchesEvidence(environmentPath, directory); err == nil {
		t.Fatal("environment provenance accepted a mixed Go toolchain")
	}
}

func TestVerifyEnvironmentFileRequiresRecordedHostMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	commit := strings.Repeat("a", 40)
	values := validEnvironmentValues("release")
	delete(values, "go_version")
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "", "amd64"); err == nil {
		t.Fatal("environment verifier accepted missing recorded host metadata")
	}
}

func TestVerifyEnvironmentFileRejectsImpossibleReferenceCPUProfile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	commit := strings.Repeat("a", 40)
	values := validEnvironmentValues("release")
	values["nproc"] = "1"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment verifier accepted a host smaller than the reference CPU profile")
	}
}

func TestVerifyEnvironmentFileRejectsZeroMigrationRunID(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	commit := strings.Repeat("a", 40)
	values := validEnvironmentValues("release")
	values["migration_ci_run_id"] = "0"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "", commit, "v0.1.0", "amd64"); err == nil {
		t.Fatal("environment verifier accepted a zero trusted Migration CI run ID")
	}
}

func TestVerifyEnvironmentFileRejectsMalformedHostMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	commit := strings.Repeat("a", 40)
	values := validEnvironmentValues("release")
	values["go_version"] = "go version go1.26.6 darwin/arm64"
	values["uname"] = "Darwin runner 24.0.0 arm64"
	values["cpu_max"] = "not-a-quota"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFile(path, "github-77-commit", "12345", commit, "", "amd64"); err == nil {
		t.Fatal("environment verifier accepted malformed host metadata")
	}
}

func TestVerifyPreflightEnvironmentFileAcceptsDispatchProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "performance-preflight-environment.txt")
	values := validEnvironmentValues("preflight")
	writeEnvironmentFixture(t, path, values)
	expected := environmentContext{
		Mode: "preflight", RunID: "github-77-commit", MigrationRunID: "12345", Commit: strings.Repeat("a", 40),
		Ref: "refs/heads/codex/streamline-ztap", WorkflowRunID: "77", WorkflowEvent: "workflow_dispatch",
		WorkflowPath: ".github/workflows/migration-ci.yml", MigrationBranch: "codex/streamline-ztap", Arch: "amd64",
	}
	if err := verifyEnvironmentFileForContext(path, expected); err != nil {
		t.Fatalf("valid preflight environment rejected: %v", err)
	}
	values["workflow_event"] = "push"
	writeEnvironmentFixture(t, path, values)
	if err := verifyEnvironmentFileForContext(path, expected); err == nil {
		t.Fatal("preflight verifier accepted a non-dispatch workflow event")
	}
}

func TestVerifyCPUQuotaProvenanceSelectsTightestObservedAncestor(t *testing.T) {
	values := validEnvironmentValues("release")
	observations := []cpuMaxObservation{
		{Path: "/sys/fs/cgroup/runner/job", Status: "recorded", Value: "max 100000"},
		{Path: "/sys/fs/cgroup/runner", Status: "recorded", Value: "250000 100000"},
		{Path: "/sys/fs/cgroup", Status: "recorded", Value: "max 100000"},
	}
	encoded, err := json.Marshal(observations)
	if err != nil {
		t.Fatalf("marshal quota observations: %v", err)
	}
	values["cpu_max_hierarchy_json"] = string(encoded)
	values["cpu_max_path"] = "/sys/fs/cgroup/runner/cpu.max"
	values["cpu_max"] = "250000 100000"
	if err := verifyCPUQuotaProvenance(values); err != nil {
		t.Fatalf("valid hierarchical CPU quota rejected: %v", err)
	}
}

func TestVerifyCPUQuotaProvenanceRejectsInventedOrInsufficientQuota(t *testing.T) {
	values := validEnvironmentValues("release")
	values["cpu_max"] = "200000 100000"
	if err := verifyCPUQuotaProvenance(values); err == nil {
		t.Fatal("quota verifier accepted a value not recorded at its claimed path")
	}

	observations := []cpuMaxObservation{
		{Path: "/sys/fs/cgroup/runner/job", Status: "recorded", Value: "150000 100000"},
		{Path: "/sys/fs/cgroup/runner", Status: "missing"},
		{Path: "/sys/fs/cgroup", Status: "missing"},
	}
	encoded, err := json.Marshal(observations)
	if err != nil {
		t.Fatalf("marshal insufficient quota observations: %v", err)
	}
	values = validEnvironmentValues("release")
	values["cpu_max_hierarchy_json"] = string(encoded)
	values["cpu_max_path"] = "/sys/fs/cgroup/runner/job/cpu.max"
	values["cpu_max"] = "150000 100000"
	if err := verifyCPUQuotaProvenance(values); err == nil {
		t.Fatal("quota verifier accepted an effective limit below two CPUs")
	}

	values = validEnvironmentValues("release")
	observations = []cpuMaxObservation{
		{Path: "/sys/fs/cgroup/runner/job", Status: "missing"},
		{Path: "/sys/fs/cgroup/runner", Status: "missing"},
		{Path: "/sys/fs/cgroup", Status: "missing"},
	}
	encoded, err = json.Marshal(observations)
	if err != nil {
		t.Fatalf("marshal absent quota observations: %v", err)
	}
	values["cpu_max_status"] = "unavailable"
	values["cpu_max_path"] = "unavailable"
	values["cpu_max"] = "unavailable"
	values["cpu_max_hierarchy_json"] = string(encoded)
	if err := verifyCPUQuotaProvenance(values); err == nil {
		t.Fatal("quota verifier accepted absent cpu.max files as an invented quota")
	}
}

func validEnvironmentValues(mode string) map[string]string {
	ref := "refs/tags/v0.1.0"
	workflowPath := ".github/workflows/release.yml"
	workflowEvent := "push"
	migrationBranch := "main"
	if mode == "preflight" {
		ref = "refs/heads/codex/streamline-ztap"
		workflowPath = ".github/workflows/migration-ci.yml"
		workflowEvent = "workflow_dispatch"
		migrationBranch = "codex/streamline-ztap"
	}
	observations, _ := json.Marshal([]cpuMaxObservation{
		{Path: "/sys/fs/cgroup/runner/job", Status: "recorded", Value: "max 100000"},
		{Path: "/sys/fs/cgroup/runner", Status: "missing"},
		{Path: "/sys/fs/cgroup", Status: "missing"},
	})
	return map[string]string{
		"environment_schema":     "2",
		"environment_mode":       mode,
		"timestamp_utc":          "2026-09-19T00:00:00Z",
		"phase5_run_id":          "github-77-commit",
		"migration_ci_run_id":    "12345",
		"commit":                 strings.Repeat("a", 40),
		"ref":                    ref,
		"workflow_run_id":        "77",
		"workflow_event":         workflowEvent,
		"workflow_path":          workflowPath,
		"migration_ci_workflow":  ".github/workflows/migration-ci.yml",
		"migration_ci_event":     "push",
		"migration_ci_branch":    migrationBranch,
		"go_version":             "go version go1.26.6 linux/amd64",
		"goos":                   "linux",
		"goarch":                 "amd64",
		"nproc":                  "8",
		"allowed_cpu_list":       "0-7",
		"reference_cpu_set":      "0,1",
		"reference_nproc":        "2",
		"reference_gomaxprocs":   "2",
		"getconf_clk_tck":        "100",
		"uname":                  "Linux runner 6.1.0 x86_64 GNU/Linux",
		"cgroup2":                "cgroup2fs",
		"bpffs":                  "bpf_fs",
		"cgroup_mount_root":      "/",
		"cgroup_mount_point":     "/sys/fs/cgroup",
		"cgroup_membership_path": "/runner/job",
		"cgroup_process_path":    "/sys/fs/cgroup/runner/job",
		"cpu_max_status":         "recorded",
		"cpu_max_path":           "/sys/fs/cgroup/runner/job/cpu.max",
		"cpu_max":                "max 100000",
		"cpu_max_hierarchy_json": string(observations),
		"capture_errors_json":    "[]",
	}
}

func writeEnvironmentFixture(t *testing.T, path string, values map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var payload strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&payload, "%s=%s\n", key, values[key])
	}
	if err := os.WriteFile(path, []byte(payload.String()), 0o600); err != nil {
		t.Fatalf("write environment fixture: %v", err)
	}
}

func TestRecordedGoVersionRequiresNumericRelease(t *testing.T) {
	for _, value := range []string{
		"go version goevil linux/amd64",
		"go version go linux/amd64",
		"go version goX linux/amd64",
		"go version go1evil linux/amd64",
		"go version go1.26evil linux/amd64",
	} {
		if _, err := recordedGoVersion(value, "amd64"); err == nil {
			t.Fatalf("recordedGoVersion accepted malformed version %q", value)
		}
	}
	if got, err := recordedGoVersion("go version go1.26.6 linux/amd64", "amd64"); err != nil || got != "go1.26.6" {
		t.Fatalf("recordedGoVersion rejected valid version: got %q, err %v", got, err)
	}
}

func TestValidReleaseRefRejectsLeadingZeroComponents(t *testing.T) {
	for _, value := range []string{"v01.2.3", "v1.02.3", "v1.2.03"} {
		if validReleaseRef(value) {
			t.Fatalf("validReleaseRef accepted non-canonical tag %q", value)
		}
	}
	for _, value := range []string{"v0.1.0", "v1.2.3", "v10.20.30"} {
		if !validReleaseRef(value) {
			t.Fatalf("validReleaseRef rejected canonical tag %q", value)
		}
	}
}

func TestValidCommitRequiresFullHexadecimalID(t *testing.T) {
	for _, value := range []string{"", "abc", strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("g", 40)} {
		if validCommit(value) {
			t.Fatalf("validCommit accepted malformed commit ID %q", value)
		}
	}
	for _, value := range []string{strings.Repeat("a", 40), strings.Repeat("F", 64)} {
		if !validCommit(value) {
			t.Fatalf("validCommit rejected full hexadecimal commit ID %q", value)
		}
	}
}

func TestValidateEnvironmentRequiresDottedGoVersion(t *testing.T) {
	evidence := validPacketEvidence()
	evidence.GoVersion = "go1evil"
	if err := validatePacket(evidence); err == nil {
		t.Fatal("validatePacket accepted a fabricated Go version token")
	}
}

func TestVerifyEnvironmentFileRejectsDuplicateKeys(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	if err := os.WriteFile(path, []byte("timestamp_utc=2026-09-19T00:00:00Z\ntimestamp_utc=2026-09-19T00:00:00Z\n"), 0o600); err != nil {
		t.Fatalf("write duplicate environment evidence: %v", err)
	}
	if err := verifyEnvironmentFile(path, "", "", "", "", ""); err == nil {
		t.Fatal("environment verifier accepted duplicate keys")
	}
}

func TestVerifyEnvironmentFileRejectsUnknownKeys(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	if err := os.WriteFile(path, []byte("timestamp_utc=2026-09-19T00:00:00Z\nunknown=value\n"), 0o600); err != nil {
		t.Fatalf("write unknown environment evidence: %v", err)
	}
	if err := verifyEnvironmentFile(path, "", "", "", "", ""); err == nil {
		t.Fatal("environment verifier accepted an unknown key")
	}
}

func TestReadEnvironmentValuesRejectsOversizedEvidence(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "phase5-environment.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("\n", maxEnvironmentBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized environment evidence: %v", err)
	}
	if _, err := readEnvironmentValues(path); err == nil {
		t.Fatal("environment reader accepted an oversized evidence file")
	}
}

func hostedResourceEvidenceFixture(containerID string) string {
	return strings.Join([]string{
		"agent_namespace=ztap-system",
		"agent_pod=ztap-agent-abc12",
		"container_id=" + containerID,
		"cgroup_path=/sys/fs/cgroup/kubepods.slice/cri-containerd-" + containerID + ".scope",
		"observed_fixture_pods=250",
		"observed_fixture_policies=25",
		"reference_cpu_max=200000 100000",
		"reference_fixture_agent_enforcing=1",
		"reference_fixture_active_policy_epoch=1",
		"reference_fixture_enforced_cgroups=250",
		"reference_fixture_compiled_rules=2500",
		"reference_total_enforced_cgroups=251",
		"retained_smoke_client_cgroups=1",
		"reference_total_compiled_rules=2501",
		"retained_smoke_client_rules=1",
		"reference_fixture_status=active_waiting_for_quiet_interval",
		"memory_metric=memory.current (conservative cgroup memory upper bound; includes non-RSS charges)",
		"quiet_settle_seconds=10",
		"sample_interval_seconds=5",
		"memory_peak_sample_interval_ms=100",
		"samples=3",
		"scope=real capability-only DaemonSet in kind with 250 Pods, 25 policies, and 2500 rules",
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
		"cpu_budget_cores=0.10",
		"memory_current_budget_mib=200",
		"max_cpu_cores=0.03",
		"max_memory_current_mib=120.00",
		"budget_result=passed",
	}, "\n") + "\n"
}

func TestVerifyHostedEvidenceAcceptsReferenceBundle(t *testing.T) {
	ebpfDirectory := t.TempDir()
	capabilityDirectory := t.TempDir()
	containerID := strings.Repeat("0123456789abcdef", 4)
	write := func(directory, name, contents string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return path
	}
	write(ebpfDirectory, "ebpf-engine-tests.txt", "ebpf_engine_runtime_gate=passed\n")
	smokeEvidence := strings.Join([]string{
		"capability-only DaemonSet attached and enforced the smoke policy",
		"kindnet_networkpolicy_controller=disabled",
		"status_endpoints=passed",
		"packet_decisions_blocked_default_deny=1",
		"service_cluster_ip=10.96.0.10",
		"service_backend_pod_ip=10.244.0.3",
		"selector_peer_policy_epoch=2",
		"selector_peer_direct_podip=allowed",
		"selector_peer_service_clusterip=blocked",
		"explicit_clusterip_policy_epoch=3",
		"explicit_clusterip_ipblock_cidr=10.96.0.10/32",
		"explicit_clusterip_ipblock_service=allowed",
		"explicit_clusterip_ipblock_podip=blocked",
		"flow_expected_src_ip=10.244.0.2",
		"flow_expected_dst_ip=10.244.0.3",
		"flow_expected_dst_port=8080",
		`{"timestamp":"2026-09-19T00:00:00Z","policy_epoch":1,"cgroup_id":123,"direction":"egress","protocol":"TCP","src_ip":"10.244.0.2","src_port":40000,"dst_ip":"10.244.0.3","dst_port":8080,"action":"blocked","reason":"default_deny","schema_version":1}`,
		"flow_streaming=passed",
	}, "\n") + "\n"
	smokePath := write(capabilityDirectory, "capability-agent-smoke.txt", smokeEvidence)
	fixtureEvidence := "offline_fixture_shape=pods=250 policies=25 compiled_rules=2500\nfixture_live_shape=verified\nfixture_shape=pods=250 policies=25 pods_per_policy=10 peers_per_policy=10 compiled_rules=2500\n"
	fixturePath := write(capabilityDirectory, "capability-agent-reference-fixture.txt", fixtureEvidence)
	write(capabilityDirectory, "phase5-reference-fixture.yaml", referenceHostedFixture(true))
	resourceEvidence := hostedResourceEvidenceFixture(containerID)
	resourcePath := write(capabilityDirectory, "capability-agent-resource.txt", resourceEvidence)
	rollingEvidence := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_namespace=ztap-system",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_namespace=ztap-system",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	rollingPath := write(capabilityDirectory, "rolling-fail-open-evidence.txt", rollingEvidence)

	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err != nil {
		t.Fatalf("valid hosted evidence rejected: %v", err)
	}
	clusterEvidenceCases := []struct {
		name  string
		alter func(string) string
	}{
		{
			name: "missing selector Service denial",
			alter: func(text string) string {
				return strings.Replace(text, "selector_peer_service_clusterip=blocked\n", "", 1)
			},
		},
		{
			name: "missing explicit Service allow",
			alter: func(text string) string {
				return strings.Replace(text, "explicit_clusterip_ipblock_service=allowed\n", "", 1)
			},
		},
		{
			name: "duplicate ClusterIP address",
			alter: func(text string) string {
				return strings.Replace(text, "service_cluster_ip=10.96.0.10\n", "service_cluster_ip=10.96.0.10\nservice_cluster_ip=10.96.0.10\n", 1)
			},
		},
		{
			name: "mismatched explicit ClusterIP CIDR",
			alter: func(text string) string {
				return strings.Replace(text, "explicit_clusterip_ipblock_cidr=10.96.0.10/32", "explicit_clusterip_ipblock_cidr=10.96.0.11/32", 1)
			},
		},
		{
			name: "non-advancing policy epoch",
			alter: func(text string) string {
				return strings.Replace(text, "explicit_clusterip_policy_epoch=3", "explicit_clusterip_policy_epoch=2", 1)
			},
		},
		{
			name: "flow destination differs from Service backend",
			alter: func(text string) string {
				altered := strings.Replace(text, "flow_expected_dst_ip=10.244.0.3", "flow_expected_dst_ip=10.244.0.4", 1)
				return strings.Replace(altered, `"dst_ip":"10.244.0.3"`, `"dst_ip":"10.244.0.4"`, 1)
			},
		},
	}
	for _, test := range clusterEvidenceCases {
		t.Run(test.name, func(t *testing.T) {
			invalid := test.alter(smokeEvidence)
			if invalid == smokeEvidence {
				t.Fatal("test did not alter the hosted smoke transcript")
			}
			if err := os.WriteFile(smokePath, []byte(invalid), 0o600); err != nil {
				t.Fatalf("write altered hosted smoke evidence: %v", err)
			}
			if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
				t.Fatal("hosted verifier accepted invalid ClusterIP evidence")
			}
		})
	}
	if err := os.WriteFile(smokePath, []byte(smokeEvidence), 0o600); err != nil {
		t.Fatalf("restore valid smoke evidence after ClusterIP checks: %v", err)
	}
	missingCNIProfile := strings.Replace(smokeEvidence, "kindnet_networkpolicy_controller=disabled\n", "", 1)
	if err := os.WriteFile(smokePath, []byte(missingCNIProfile), 0o600); err != nil {
		t.Fatalf("write smoke evidence without CNI profile marker: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted smoke evidence without the single-enforcer profile marker")
	}
	if err := os.WriteFile(smokePath, []byte(smokeEvidence), 0o600); err != nil {
		t.Fatalf("restore valid smoke evidence after CNI-profile check: %v", err)
	}
	missingPacketCounter := strings.Replace(smokeEvidence, "packet_decisions_blocked_default_deny=1\n", "", 1)
	if err := os.WriteFile(smokePath, []byte(missingPacketCounter), 0o600); err != nil {
		t.Fatalf("write smoke evidence without packet counter: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted smoke evidence without the packet counter")
	}
	if err := os.WriteFile(smokePath, []byte(smokeEvidence), 0o600); err != nil {
		t.Fatalf("restore valid smoke evidence after packet-counter check: %v", err)
	}
	missingLiveShapeMarker := strings.Replace(fixtureEvidence, "fixture_live_shape=verified\n", "", 1)
	if err := os.WriteFile(fixturePath, []byte(missingLiveShapeMarker), 0o600); err != nil {
		t.Fatalf("write fixture evidence without live-shape marker: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted fixture evidence without the live-shape marker")
	}
	if err := os.WriteFile(fixturePath, []byte(fixtureEvidence), 0o600); err != nil {
		t.Fatalf("restore valid fixture evidence after live-shape check: %v", err)
	}
	missingActiveMarker := strings.Replace(resourceEvidence, "reference_fixture_agent_enforcing=1\n", "", 1)
	if err := os.WriteFile(resourcePath, []byte(missingActiveMarker), 0o600); err != nil {
		t.Fatalf("write resource evidence without active marker: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted resource evidence without the active-enforcing marker")
	}
	invalidActiveEpoch := strings.Replace(resourceEvidence, "reference_fixture_active_policy_epoch=1", "reference_fixture_active_policy_epoch=0", 1)
	if err := os.WriteFile(resourcePath, []byte(invalidActiveEpoch), 0o600); err != nil {
		t.Fatalf("write resource evidence with inactive policy epoch: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted resource evidence with an inactive policy epoch")
	}
	if err := os.WriteFile(resourcePath, []byte(resourceEvidence), 0o600); err != nil {
		t.Fatalf("restore valid resource evidence after active-state checks: %v", err)
	}

	mismatchedID := strings.Repeat("a", 64)
	mismatchedEvidence := strings.Replace(resourceEvidence,
		"cri-containerd-"+containerID+".scope",
		"cri-containerd-"+mismatchedID+".scope",
		1,
	)
	if mismatchedEvidence == resourceEvidence {
		t.Fatal("test fixture did not change the recorded cgroup identity")
	}
	if err := os.WriteFile(resourcePath, []byte(mismatchedEvidence), 0o600); err != nil {
		t.Fatalf("write mismatched resource evidence: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted a cgroup path that does not match its container ID")
	}
	invalidAgentPod := strings.Replace(resourceEvidence, "agent_pod=ztap-agent-abc12", "agent_pod=unrelated-workload", 1)
	if err := os.WriteFile(resourcePath, []byte(invalidAgentPod), 0o600); err != nil {
		t.Fatalf("write unrelated agent-pod evidence: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted a resource transcript for an unrelated Pod")
	}
	invalidAgentNamespace := strings.Replace(resourceEvidence, "agent_namespace=ztap-system", "agent_namespace=other-namespace", 1)
	if err := os.WriteFile(resourcePath, []byte(invalidAgentNamespace), 0o600); err != nil {
		t.Fatalf("write unrelated agent-namespace evidence: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted a resource transcript from an unrelated namespace")
	}
	if err := os.WriteFile(resourcePath, []byte(resourceEvidence), 0o600); err != nil {
		t.Fatalf("restore valid resource evidence: %v", err)
	}
	invalidAgentPodSyntax := strings.Replace(resourceEvidence, "agent_pod=ztap-agent-abc12", "agent_pod=ztap-agent-invalid_name", 1)
	if err := os.WriteFile(resourcePath, []byte(invalidAgentPodSyntax), 0o600); err != nil {
		t.Fatalf("write malformed agent-pod evidence: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted a malformed agent Pod name")
	}
	if err := os.WriteFile(resourcePath, []byte(resourceEvidence), 0o600); err != nil {
		t.Fatalf("restore valid resource evidence before rolling check: %v", err)
	}
	invalidRollingNamespace := strings.Replace(rollingEvidence, "replacement_namespace=ztap-system", "replacement_namespace=other-namespace", 1)
	if err := os.WriteFile(rollingPath, []byte(invalidRollingNamespace), 0o600); err != nil {
		t.Fatalf("write unrelated rolling namespace evidence: %v", err)
	}
	if err := verifyHostedEvidence(ebpfDirectory, capabilityDirectory); err == nil {
		t.Fatal("hosted verifier accepted rolling evidence from an unrelated namespace")
	}
}

func TestValidateHostedFlowEvidenceRejectsMissingJSONRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	if err := os.WriteFile(path, []byte("capability-only DaemonSet attached and enforced the smoke policy\nflow_streaming=passed\n"), 0o600); err != nil {
		t.Fatalf("write smoke evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a marker without a JSON record")
	}
}

func TestValidateHostedFlowEvidenceIgnoresLabeledSecurityContextJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	payload := strings.Join([]string{
		`agent_security_context_json={"allowPrivilegeEscalation":false,"privileged":false}`,
		"flow_expected_src_ip=10.244.0.2",
		"flow_expected_dst_ip=10.244.0.3",
		"flow_expected_dst_port=8080",
		`{"timestamp":"2026-09-19T00:00:00Z","policy_epoch":1,"cgroup_id":123,"direction":"egress","protocol":"TCP","src_ip":"10.244.0.2","src_port":40000,"dst_ip":"10.244.0.3","dst_port":8080,"action":"blocked","reason":"default_deny","schema_version":1}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write labeled security-context evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err != nil {
		t.Fatalf("labeled security-context JSON interfered with flow evidence: %v", err)
	}
}

func TestValidateHostedFlowEvidenceRejectsUnexpectedFlowTuple(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	payload := strings.Join([]string{
		"flow_expected_src_ip=10.244.0.2",
		"flow_expected_dst_ip=10.244.0.3",
		"flow_expected_dst_port=8080",
		"{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"TCP\",\"src_ip\":\"10.244.0.99\",\"src_port\":40000,\"dst_ip\":\"10.244.0.3\",\"dst_port\":8080,\"action\":\"blocked\",\"reason\":\"default_deny\",\"schema_version\":1}",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write unexpected-tuple flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a blocked flow for an unexpected tuple")
	}
}

func TestValidateHostedFlowEvidenceRejectsNonDefaultDenyReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	payload := strings.Join([]string{
		"flow_expected_src_ip=10.244.0.2",
		"flow_expected_dst_ip=10.244.0.3",
		"flow_expected_dst_port=8080",
		"{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"TCP\",\"src_ip\":\"10.244.0.2\",\"src_port\":40000,\"dst_ip\":\"10.244.0.3\",\"dst_port\":8080,\"action\":\"blocked\",\"reason\":\"quarantine\",\"schema_version\":1}",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write non-default-deny flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a blocked flow with a non-default-deny reason")
	}
}

func TestValidateHostedFlowEvidenceRejectsZeroTCPSourcePort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	payload := strings.Join([]string{
		"flow_expected_src_ip=10.244.0.2",
		"flow_expected_dst_ip=10.244.0.3",
		"flow_expected_dst_port=8080",
		"{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"TCP\",\"src_ip\":\"10.244.0.2\",\"src_port\":0,\"dst_ip\":\"10.244.0.3\",\"dst_port\":8080,\"action\":\"blocked\",\"reason\":\"default_deny\",\"schema_version\":1}",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write zero-source-port flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a TCP record with a zero source port")
	}
}

func TestValidateHostedFlowEvidenceRejectsMalformedJSONRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	if err := os.WriteFile(path, []byte("{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"TCP\",\"src_ip\":\"10.244.0.2\",\"src_port\":40000,\"dst_ip\":\"10.244.0.3\",\"dst_port\":8080,\"action\":\"blocked\",\"schema_version\":1}\n"), 0o600); err != nil {
		t.Fatalf("write malformed flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted an incomplete JSON record")
	}
	if err := os.WriteFile(path, []byte("{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"ICMP\",\"src_ip\":\"10.244.0.2\",\"src_port\":null,\"dst_ip\":\"10.244.0.3\",\"dst_port\":0,\"action\":\"blocked\",\"reason\":\"policy denied\",\"schema_version\":1}\n"), 0o600); err != nil {
		t.Fatalf("write null flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a null required field")
	}
}

func TestValidateHostedFlowEvidenceRejectsWhitespaceReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-smoke.txt")
	payload := "{\"timestamp\":\"2026-09-19T00:00:00Z\",\"policy_epoch\":1,\"cgroup_id\":123,\"direction\":\"egress\",\"protocol\":\"UDP\",\"src_ip\":\"10.244.0.2\",\"src_port\":40000,\"dst_ip\":\"10.244.0.3\",\"dst_port\":8080,\"action\":\"blocked\",\"reason\":\"   \",\"schema_version\":1}\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write whitespace-reason flow evidence: %v", err)
	}
	if err := validateHostedFlowEvidence(path); err == nil {
		t.Fatal("hosted flow verifier accepted a whitespace-only decision reason")
	}
}

func TestFindHostedEvidenceFileRejectsSymlinkRoot(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "evidence.txt"), []byte("evidence\n"), 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	root := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := findHostedEvidenceFile(root, "evidence.txt"); err == nil {
		t.Fatal("findHostedEvidenceFile followed a symlink root")
	}
}

func TestFindHostedEvidenceFileRejectsCaseVariant(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Evidence.txt"), []byte("evidence\n"), 0o600); err != nil {
		t.Fatalf("write case-variant evidence: %v", err)
	}
	if _, err := findHostedEvidenceFile(root, "evidence.txt"); err == nil {
		t.Fatal("findHostedEvidenceFile accepted a case-variant evidence name")
	}
}

func TestEvidenceReadersRejectSymlinkFiles(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write target evidence: %v", err)
	}
	link := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var evidence referenceEvidence
	if err := readEvidence(link, &evidence); err == nil {
		t.Fatal("readEvidence followed a symlink file")
	}
	if _, err := readEnvironmentValues(link); err == nil {
		t.Fatal("readEnvironmentValues followed a symlink file")
	}
	if _, err := readHostedEvidence(link); err == nil {
		t.Fatal("readHostedEvidence followed a symlink file")
	}
}

func TestReadHostedEvidenceRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-hosted-evidence.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4<<20+1)), 0o600); err != nil {
		t.Fatalf("write oversized hosted evidence: %v", err)
	}
	if _, err := readHostedEvidence(path); err == nil {
		t.Fatal("readHostedEvidence accepted an oversized file")
	}
}

func TestHostedKeyValuesRejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosted-evidence.txt")
	if err := os.WriteFile(path, []byte("status=passed\ncommand output without a key\n"), 0o600); err != nil {
		t.Fatalf("write malformed hosted evidence: %v", err)
	}
	if _, err := hostedKeyValues(path); err == nil {
		t.Fatal("hosted key/value reader accepted a malformed line")
	}
}

func TestValidateHostedResourceEvidenceRejectsUnexpectedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	containerID := strings.Repeat("0123456789abcdef", 4)
	payload := hostedResourceEvidenceFixture(containerID) + "unexpected_key=value\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write unexpected-key resource evidence: %v", err)
	}
	if err := validateHostedResourceEvidence(path); err == nil {
		t.Fatal("hosted resource verifier accepted an unexpected key")
	}
}

func TestValidHostedResourceIdentity(t *testing.T) {
	for _, value := range []string{"", "ztap-agent-", "ztap-agent--suffix", "ztap-agent-suffix-", "ztap-agent-invalid_name", "ztap-agent-UPPER"} {
		if validHostedAgentPodName(value) {
			t.Fatalf("validHostedAgentPodName accepted %q", value)
		}
	}
	for _, value := range []string{"ztap-agent-abc12", "ztap-agent-old-12345"} {
		if !validHostedAgentPodName(value) {
			t.Fatalf("validHostedAgentPodName rejected %q", value)
		}
	}
	if validHostedAgentPodName("ztap-agent-" + strings.Repeat("a", 245)) {
		t.Fatal("validHostedAgentPodName accepted a name longer than 253 bytes")
	}
	for _, value := range []string{"", "abcxyz", "abc/def"} {
		if validHostedHex(value) {
			t.Fatalf("validHostedHex accepted %q", value)
		}
	}
	for _, value := range []string{"0123456789abcdef", strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if validHostedContainerID(value) {
			t.Fatalf("validHostedContainerID accepted %q", value)
		}
	}
	for _, value := range []string{strings.Repeat("0", 64), strings.Repeat("A", 64)} {
		if !validHostedContainerID(value) {
			t.Fatalf("validHostedContainerID rejected %q", value)
		}
	}
	for _, value := range []string{"0123456789abcdef", strings.Repeat("A", 64)} {
		if !validHostedHex(value) {
			t.Fatalf("validHostedHex rejected %q", value)
		}
	}
	for _, value := range []string{"/sys/fs/cgroup/../outside", "/sys/fs/cgroup//agent", "/tmp/cgroup", "relative/cgroup"} {
		if validHostedCgroupPath(value) {
			t.Fatalf("validHostedCgroupPath accepted %q", value)
		}
	}
	if !validHostedCgroupPath("/sys/fs/cgroup/kubepods.slice/cri-containerd-0123.scope") {
		t.Fatal("validHostedCgroupPath rejected an in-root canonical path")
	}
	containerID := strings.Repeat("0123456789abcdef", 4)
	matchingPath := "/sys/fs/cgroup/kubepods.slice/cri-containerd-" + containerID + ".scope"
	if !validHostedContainerCgroupPath(matchingPath, containerID) {
		t.Fatal("validHostedContainerCgroupPath rejected a matching container identity")
	}
	kubeletPath := "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/cri-containerd-" + containerID + ".scope"
	if !validHostedContainerCgroupPath(kubeletPath, containerID) {
		t.Fatal("validHostedContainerCgroupPath rejected the kubelet-scoped hierarchy")
	}
	if validHostedContainerCgroupPath(matchingPath, strings.Repeat("a", 64)) {
		t.Fatal("validHostedContainerCgroupPath accepted a mismatched container identity")
	}
	unsupportedHierarchy := "/sys/fs/cgroup/system.slice/cri-containerd-" + containerID + ".scope"
	if validHostedContainerCgroupPath(unsupportedHierarchy, containerID) {
		t.Fatal("validHostedContainerCgroupPath accepted an unsupported hierarchy")
	}
}

func TestRequireHostedExactLineRejectsDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosted-evidence.txt")
	if err := os.WriteFile(path, []byte("pass\npass\n"), 0o600); err != nil {
		t.Fatalf("write duplicate hosted marker: %v", err)
	}
	if err := requireHostedExactLine(path, "pass"); err == nil {
		t.Fatal("hosted marker verifier accepted duplicate pass lines")
	}
}

func TestRequireHostedExactLineRejectsConflictingKeyedResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosted-evidence.txt")
	if err := os.WriteFile(path, []byte("flow_streaming=failed\nflow_streaming=passed\n"), 0o600); err != nil {
		t.Fatalf("write conflicting hosted marker: %v", err)
	}
	if err := requireHostedExactLine(path, "flow_streaming=passed"); err == nil {
		t.Fatal("hosted marker verifier accepted conflicting keyed results")
	}
}

func TestRequireHostedPositiveUintLineRejectsMissingInvalidAndDuplicateValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosted-evidence.txt")
	cases := []struct {
		name    string
		content string
	}{
		{name: "missing", content: "other=1\n"},
		{name: "zero", content: "packet_decisions_blocked_default_deny=0\n"},
		{name: "malformed", content: "packet_decisions_blocked_default_deny=1.0\n"},
		{name: "duplicate", content: "packet_decisions_blocked_default_deny=1\npacket_decisions_blocked_default_deny=2\n"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("write %s evidence: %v", testCase.name, err)
			}
			if err := requireHostedPositiveUintLine(path, "packet_decisions_blocked_default_deny"); err == nil {
				t.Fatalf("positive uint verifier accepted %s evidence", testCase.name)
			}
		})
	}
	if err := os.WriteFile(path, []byte("packet_decisions_blocked_default_deny=1\n"), 0o600); err != nil {
		t.Fatalf("write valid packet counter evidence: %v", err)
	}
	if err := requireHostedPositiveUintLine(path, "packet_decisions_blocked_default_deny"); err != nil {
		t.Fatalf("positive uint verifier rejected valid evidence: %v", err)
	}
}

func referenceHostedFixture(includePolicyBuckets bool) string {
	var fixture strings.Builder
	fixture.WriteString("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ztap-performance\n")
	for index := 0; index < referenceSubjects; index++ {
		fixture.WriteString("---\n")
		fmt.Fprintf(&fixture, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: reference-pod-%03d\n  namespace: ztap-performance\n  labels:\n    phase5-bucket: \"%02d\"\nspec:\n  containers:\n    - name: workload\n      image: busybox:1.36.1\n      imagePullPolicy: IfNotPresent\n      command: [\"sh\", \"-c\", \"sleep 3600\"]\n", index, index/(referenceSubjects/referencePolicies))
	}
	for index := 0; index < referencePolicies; index++ {
		fixture.WriteString("---\n")
		if includePolicyBuckets {
			fmt.Fprintf(&fixture, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: reference-policy-%02d\n  namespace: ztap-performance\n  labels:\n    phase5-bucket: \"%02d\"\nspec:\n  podSelector:\n    matchLabels:\n      phase5-bucket: \"%02d\"\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n", index, index, index)
			for peer := 0; peer < referenceRules/referenceSubjects; peer++ {
				fmt.Fprintf(&fixture, "      - ipBlock:\n          cidr: 198.18.%d.%d/32\n", index, peer)
			}
			fixture.WriteString("      ports:\n        - protocol: TCP\n          port: 10000\n")
			continue
		}
		fmt.Fprintf(&fixture, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: reference-policy-%02d\n  namespace: ztap-performance\nspec:\n  podSelector:\n    matchLabels:\n      phase5-bucket: \"%02d\"\n", index, index)
	}
	return fixture.String()
}

func TestValidateHostedObjectNamesRejectsDuplicate(t *testing.T) {
	text := "name: reference-pod-000\nname: reference-pod-000\n"
	if err := validateHostedObjectNames("fixture.yaml", text, "reference-pod-", 2, 3); err == nil {
		t.Fatal("hosted fixture verifier accepted a duplicate object name")
	}
}

func TestValidateHostedFixtureRequiresPerObjectBucketMarkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	if err := os.WriteFile(path, []byte(referenceHostedFixture(false)), 0o600); err != nil {
		t.Fatalf("write fixture without policy buckets: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted a fixture without per-object bucket markers")
	}
}

func TestValidateHostedFixtureRejectsPerPolicyPeerShapeCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(referenceHostedFixture(true), "198.18.0.9/32", "198.18.1.9/32", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with imbalanced policy peers: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted balanced aggregate peers with per-policy corruption")
	}
}

func TestValidateHostedFixtureRejectsMismatchedPolicySelectorBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(referenceHostedFixture(true), "matchLabels:\n      phase5-bucket: \"00\"", "matchLabels:\n      phase5-bucket: \"01\"", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with mismatched selector bucket: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted a mismatched policy selector bucket")
	}
}

func TestValidateHostedFixtureRequiresExactNamespaceDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(referenceHostedFixture(true), "metadata:\n  name: ztap-performance\n", "metadata:\n  name: other\n", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with invalid namespace document: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted an invalid namespace document")
	}
}

func TestValidateHostedFixtureRejectsDuplicateYAMLKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(referenceHostedFixture(true), "kind: Pod\nmetadata:\n", "kind: Pod\nmetadata:\nmetadata:\n", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with duplicate YAML keys: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted duplicate YAML keys")
	}
}

func TestValidateHostedFixtureRejectsNonStringYAMLKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(
		referenceHostedFixture(true),
		"  labels:\n    phase5-bucket: \"00\"\n",
		"  labels:\n    ? [phase5-extra]\n    : value\n    phase5-bucket: \"00\"\n",
		1,
	)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with non-string YAML key: %v", err)
	}
	err := validateHostedFixture(path)
	if err == nil {
		t.Fatal("hosted fixture verifier accepted a non-string YAML mapping key")
	}
	if !strings.Contains(err.Error(), "not a string") {
		t.Fatalf("non-string YAML key failed for an unrelated reason: %v", err)
	}
}

func TestValidateHostedFixtureRejectsYAMLAnchorsAndMerges(t *testing.T) {
	tests := []struct {
		name   string
		needle string
		repl   string
		want   string
	}{
		{
			name:   "anchor",
			needle: "metadata:\n  name: ztap-performance",
			repl:   "metadata: &namespace_meta\n  name: ztap-performance",
			want:   "anchors and aliases",
		},
		{
			name:   "merge",
			needle: "metadata:\n  name: ztap-performance",
			repl:   "metadata:\n  <<: {name: ztap-performance}\n  name: ztap-performance",
			want:   "merge keys",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := strings.Replace(referenceHostedFixture(true), test.needle, test.repl, 1)
			path := filepath.Join(t.TempDir(), test.name+".yaml")
			if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
				t.Fatalf("write %s fixture: %v", test.name, err)
			}
			err := validateHostedFixture(path)
			if err == nil {
				t.Fatal("hosted fixture verifier accepted YAML indirection")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("hosted fixture verifier returned an unrelated error: %v", err)
			}
		})
	}
}

func TestValidateHostedFixtureRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := strings.Replace(referenceHostedFixture(true), "phase5-bucket: \"00\"\n", "phase5-bucket: \"00\n", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted malformed YAML")
	}
}

func TestValidateHostedFixtureRejectsExcessiveYAMLNesting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	var nested strings.Builder
	nested.WriteString("nested:\n")
	for index := 0; index < maxHostedYAMLDepth+1; index++ {
		nested.WriteString(strings.Repeat("  ", index+1))
		nested.WriteString("nested:\n")
	}
	nested.WriteString(strings.Repeat("  ", maxHostedYAMLDepth+2))
	nested.WriteString("value: 1\n")
	fixture := strings.Replace(
		referenceHostedFixture(true),
		"apiVersion: v1\nkind: Namespace\n",
		"apiVersion: v1\nkind: Namespace\n"+nested.String(),
		1,
	)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write deeply nested fixture: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted excessive YAML nesting")
	}
}

func TestValidateHostedFixtureRejectsFieldsOutsideExpectedYAMLPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := referenceHostedFixture(true)
	fixture = strings.Replace(fixture, "  name: reference-pod-000\n", "", 1)
	fixture = strings.Replace(fixture, "spec:\n  containers:", "spec:\n  name: reference-pod-000\n  containers:", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with misplaced metadata name: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted a name outside metadata")
	}
}

func TestValidateHostedFixtureRejectsPeerOutsideNetworkPolicyTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
	fixture := referenceHostedFixture(true)
	fixture = strings.Replace(fixture, "        - ipBlock:\n            cidr: 198.18.0.9/32\n", "", 1)
	fixture = strings.Replace(fixture, "spec:\n  podSelector:\n", "spec:\n  unrelated:\n    - cidr: 198.18.0.9/32\n  podSelector:\n", 1)
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture with misplaced peer: %v", err)
	}
	if err := validateHostedFixture(path); err == nil {
		t.Fatal("hosted fixture verifier accepted a peer outside NetworkPolicy spec.egress.to")
	}
}

func TestValidateHostedFixtureRejectsPolicySemanticDrift(t *testing.T) {
	tests := []struct {
		name   string
		needle string
		repl   string
	}{
		{name: "policy type", needle: "    - Egress\n  egress:", repl: "    - Ingress\n  egress:"},
		{name: "protocol", needle: "protocol: TCP", repl: "protocol: UDP"},
		{name: "port", needle: "port: 10000", repl: "port: 10001"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := strings.Replace(referenceHostedFixture(true), test.needle, test.repl, 1)
			path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
			if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
				t.Fatalf("write semantic-drift fixture: %v", err)
			}
			if err := validateHostedFixture(path); err == nil {
				t.Fatal("hosted fixture verifier accepted policy semantic drift")
			}
		})
	}
}

func TestValidateHostedFixtureRejectsPodSemanticDrift(t *testing.T) {
	tests := []struct {
		name   string
		needle string
		repl   string
	}{
		{name: "image", needle: "image: busybox:1.36.1", repl: "image: alpine:3.20"},
		{name: "command", needle: "command: [\"sh\", \"-c\", \"sleep 3600\"]", repl: "command: [\"sh\", \"-c\", \"sleep 1\"]"},
		{name: "extra field", needle: "spec:\n  containers:", repl: "spec:\n  hostNetwork: true\n  containers:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := strings.Replace(referenceHostedFixture(true), test.needle, test.repl, 1)
			path := filepath.Join(t.TempDir(), "phase5-reference-fixture.yaml")
			if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
				t.Fatalf("write Pod semantic-drift fixture: %v", err)
			}
			if err := validateHostedFixture(path); err == nil {
				t.Fatal("hosted fixture verifier accepted Pod semantic drift")
			}
		})
	}
}

func TestValidateHostedResourceSamplesRequiresOrderedMeasurements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write malformed resource samples: %v", err)
	}
	if err := validateHostedResourceSamples(path, payload); err == nil {
		t.Fatal("hosted resource verifier accepted unordered or duplicate samples")
	}
}

func TestValidateHostedResourceSamplesRejectsFabricatedDerivedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.020000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write fabricated derived resource sample: %v", err)
	}
	if err := validateHostedResourceSamples(path, payload); err == nil {
		t.Fatal("hosted resource verifier accepted a fabricated CPU value")
	}
}

func TestValidateHostedResourceSamplesRejectsCounterReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=99999 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.000000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write reset resource sample: %v", err)
	}
	if err := validateHostedResourceSamples(path, payload); err == nil {
		t.Fatal("hosted resource verifier accepted a CPU counter reset")
	}
}

func TestValidateHostedResourceSamplesRejectsInterSampleCounterReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=140000 end_cpu_usec=200000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.012000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=200000 end_cpu_usec=250000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.010000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write inter-sample reset resource samples: %v", err)
	}
	if err := validateHostedResourceSamples(path, payload); err == nil {
		t.Fatal("hosted resource verifier accepted an inter-sample CPU counter reset")
	}
}

func TestValidateHostedResourceSamplesUsesMiddleMemoryPeak(t *testing.T) {
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=209715200 cpu_cores=0.010000000 memory_current_mib=200.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	samples, err := parseHostedResourceSamples("middle-memory-peak", payload)
	if err != nil {
		t.Fatalf("parse resource samples with a middle peak: %v", err)
	}
	if samples[0].PeakMemoryBytes != 209715200 || samples[0].MemoryCurrentMiB != 200 {
		t.Fatalf("middle memory peak = %+v, want 209715200 bytes/200 MiB", samples[0])
	}
}

func TestValidateHostedResourceSamplesRejectsPeakBelowEndpoint(t *testing.T) {
	payload := strings.Join([]string{
		"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=209715200 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
		"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
		"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
	}, "\n") + "\n"
	if err := validateHostedResourceSamples("peak-below-endpoint", payload); err == nil {
		t.Fatal("hosted resource verifier accepted a peak below an endpoint reading")
	}
}

func TestValidateHostedResourceEvidenceRejectsFabricatedMaximum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	containerID := strings.Repeat("0123456789abcdef", 4)
	payload := strings.Replace(hostedResourceEvidenceFixture(containerID), "max_cpu_cores=0.03", "max_cpu_cores=0.04", 1)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write fabricated resource evidence: %v", err)
	}
	if err := validateHostedResourceEvidence(path); err == nil {
		t.Fatal("hosted resource verifier accepted a fabricated maximum")
	} else if !strings.Contains(err.Error(), "want sample maximum") {
		t.Fatalf("hosted resource verifier rejected fabricated maximum for the wrong reason: %v", err)
	}
}

func TestValidateHostedResourceEvidenceRequiresExactEnforcedCgroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	containerID := strings.Repeat("0123456789abcdef", 4)
	payload := hostedResourceEvidenceFixture(containerID)
	payload = strings.Replace(payload, "reference_fixture_enforced_cgroups=250", "reference_fixture_enforced_cgroups=251", 1)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write over-counted fixture resource evidence: %v", err)
	}
	if err := validateHostedResourceEvidence(path); err == nil {
		t.Fatal("hosted resource verifier accepted a non-exact enforced-cgroup count")
	} else if !strings.Contains(err.Error(), "enforced cgroups, want exactly") {
		t.Fatalf("hosted resource verifier rejected the cgroup count for the wrong reason: %v", err)
	}
}

func TestValidateHostedResourceEvidenceRequiresScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	containerID := strings.Repeat("0123456789abcdef", 4)
	payload := strings.Replace(
		hostedResourceEvidenceFixture(containerID),
		"scope=real capability-only DaemonSet in kind with 250 Pods, 25 policies, and 2500 rules\n",
		"",
		1,
	)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write resource evidence without scope: %v", err)
	}
	if err := validateHostedResourceEvidence(path); err == nil {
		t.Fatal("hosted resource verifier accepted evidence without scope provenance")
	} else if !strings.Contains(err.Error(), "scope=") {
		t.Fatalf("hosted resource verifier rejected missing scope for the wrong reason: %v", err)
	}
}

func TestValidateHostedResourceEvidenceRequiresQuietInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-agent-resource.txt")
	containerID := strings.Repeat("0123456789abcdef", 4)
	payload := hostedResourceEvidenceFixture(containerID)
	for _, sample := range []struct{ complete, short string }{
		{
			"sample=1 start_cpu_usec=100000 end_cpu_usec=150000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=5000000000",
			"sample=1 start_cpu_usec=100000 end_cpu_usec=110000 start_memory_current_bytes=104857600 end_memory_current_bytes=104857600 peak_memory_current_bytes=104857600 cpu_cores=0.010000000 memory_current_mib=100.000000 elapsed_ns=1000000000",
		},
		{
			"sample=2 start_cpu_usec=200000 end_cpu_usec=300000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=5000000000",
			"sample=2 start_cpu_usec=200000 end_cpu_usec=220000 start_memory_current_bytes=115343360 end_memory_current_bytes=115343360 peak_memory_current_bytes=115343360 cpu_cores=0.020000000 memory_current_mib=110.000000 elapsed_ns=1000000000",
		},
		{
			"sample=3 start_cpu_usec=300000 end_cpu_usec=450000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=5000000000",
			"sample=3 start_cpu_usec=300000 end_cpu_usec=330000 start_memory_current_bytes=125829120 end_memory_current_bytes=125829120 peak_memory_current_bytes=125829120 cpu_cores=0.030000000 memory_current_mib=120.000000 elapsed_ns=1000000000",
		},
	} {
		payload = strings.Replace(payload, sample.complete, sample.short, 1)
	}
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write short resource evidence: %v", err)
	}
	if err := validateHostedResourceEvidence(path); err == nil {
		t.Fatal("hosted resource verifier accepted short sampling intervals")
	} else if !strings.Contains(err.Error(), "shorter than the documented five seconds") {
		t.Fatalf("hosted resource verifier rejected short intervals for the wrong reason: %v", err)
	}
}

func TestValidateHostedRollingEvidenceRejectsTimestampMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2499",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted mismatched timestamp arithmetic")
	}
}

func TestValidateHostedRollingEvidenceRejectsUnreadyReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=false",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write unready rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted an unready replacement")
	}
}

func TestValidateHostedRollingEvidenceRejectsUnreadyOldPod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=false",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write unready old-pod evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted an unready old pod")
	}
}

func TestValidateHostedRollingEvidenceRejectsDuplicateRequiredKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"baseline_selected_smoke_client=allowed",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted duplicate required keys")
	}
}

func TestValidateHostedRollingEvidenceRequiresReplacementInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-same",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-same",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=1000000000",
		"fail_open_interval_ms=0",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write invalid rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted an identity or interval that cannot prove a rollout gap")
	}
}

func TestValidateHostedRollingEvidenceRejectsSameUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=same-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=same-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write same-UID rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted identical old and replacement UIDs")
	}
}

func TestValidateHostedRollingEvidenceRejectsReplacementCreatedBeforeRollout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=2000000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:01Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=3000000000",
		"fail_open_start_ns=3000000000",
		"fail_open_end_ns=5000000000",
		"fail_open_interval_ms=2000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write pre-rollout replacement evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted a replacement created before rollout")
	}
}

func TestValidateHostedRollingEvidenceAcceptsSecondPrecisionCreationTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_namespace=ztap-system",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=2500000000",
		"replacement_namespace=ztap-system",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2700000000",
		"fail_open_start_ns=2600000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=900",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write second-precision rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err != nil {
		t.Fatalf("valid second-precision creation timestamp rejected: %v", err)
	}
}

func TestValidateHostedRollingEvidenceRejectsObservationBeforeCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=1000000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:05Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=6000000000",
		"fail_open_end_ns=8000000000",
		"fail_open_interval_ms=2000",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write pre-creation observation evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted observation before replacement creation")
	}
}

func TestValidateHostedRollingEvidenceRejectsCrossNodeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-control-plane",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-other-node",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-worker",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write cross-node rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted a replacement from another node")
	}
}

func TestValidateHostedRollingEvidenceRejectsAgentUnrelatedToSmokeClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rolling-fail-open-evidence.txt")
	payload := strings.Join([]string{
		"baseline_selected_smoke_client=blocked",
		"smoke_client_node=kind-worker",
		"old_pod=ztap-agent-old",
		"old_uid=old-uid",
		"old_node=kind-control-plane",
		"old_ready=true",
		"rollout_started_ns=500000000",
		"replacement_pod=ztap-agent-new",
		"replacement_uid=new-uid",
		"replacement_created_at=1970-01-01T00:00:02Z",
		"replacement_node=kind-control-plane",
		"replacement_ready=true",
		"replacement_observed_ns=2000000000",
		"fail_open_start_ns=1000000000",
		"fail_open_end_ns=3500000000",
		"fail_open_interval_ms=2500",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write unrelated-agent rolling evidence: %v", err)
	}
	if err := validateHostedRollingEvidence(path); err == nil {
		t.Fatal("rolling evidence verifier accepted an agent unrelated to smoke-client")
	}
}

func TestValidateActivationRequiresDocumentedBudget(t *testing.T) {
	evidence := activationEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, CgroupRoot: "/sys/fs/cgroup", BPFFSRoot: "/sys/fs/bpf", Scope: activationScope,
		Subjects:      referenceSubjects,
		Policies:      referencePolicies,
		Rules:         referenceRules,
		ActivationMS:  []float64{100, 200, 300},
		ActivationP95: 300,
		BudgetMS:      activationBudget,
	}
	if err := validateActivation(evidence); err != nil {
		t.Fatalf("valid activation evidence rejected: %v", err)
	}
	evidence.BudgetMS = 6000
	if err := validateActivation(evidence); err == nil {
		t.Fatal("validateActivation accepted a caller-expanded budget")
	}
}

func TestValidateActivationRequiresReferenceRoots(t *testing.T) {
	evidence := activationEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, CgroupRoot: "/sys/fs/cgroup", BPFFSRoot: "/sys/fs/bpf", Scope: activationScope,
		Subjects:      referenceSubjects,
		Policies:      referencePolicies,
		Rules:         referenceRules,
		ActivationMS:  []float64{100, 200, 300},
		ActivationP95: 300,
		BudgetMS:      activationBudget,
	}
	for name, mutate := range map[string]func(*activationEvidence){
		"cgroup root": func(value *activationEvidence) { value.CgroupRoot = "/tmp/cgroup" },
		"bpffs root":  func(value *activationEvidence) { value.BPFFSRoot = "/tmp/bpf" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := evidence
			mutate(&candidate)
			if err := validateActivation(candidate); err == nil {
				t.Fatalf("validateActivation accepted non-reference %s", name)
			}
		})
	}
}

func TestValidateResourceRecomputesMaximums(t *testing.T) {
	evidence := resourceEvidence{
		TimestampUTC: "2026-09-19T00:00:00Z", RunID: testRunID, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", CPUs: 2,
		KernelRelease: testKernelRelease, Scope: resourceScope,
		Samples:        repeatedSamples,
		QuietSeconds:   5,
		Subjects:       referenceSubjects,
		Policies:       referencePolicies,
		Rules:          referenceRules,
		ClockTicks:     100,
		CPUCoreSamples: []float64{0.01, 0.02, 0.03},
		RSSMiBSamples:  []float64{100, 110, 120},
		MaxCPUCore:     0.03,
		MaxRSSMiB:      120,
		CPUBudgetCores: cpuBudgetCores,
		RSSBudgetMiB:   rssBudgetMiB,
	}
	if err := validateResource(evidence); err != nil {
		t.Fatalf("valid resource evidence rejected: %v", err)
	}
	evidence.MaxRSSMiB = 119
	if err := validateResource(evidence); err == nil {
		t.Fatal("validateResource accepted an inconsistent RSS maximum")
	}
}
