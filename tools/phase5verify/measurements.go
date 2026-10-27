package main

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/saadshabir/ZTAP/internal/restartproof"
)

func validateReference(e referenceEvidence) error {
	if err := validateEnvironment("reference", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateExactScope("reference kernel path scope", e.KernelPathScope, referenceKernelPathScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("apply", e.ApplySamplesMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("apply p95", e.ApplySamplesMS, e.ApplyP95MS); err != nil {
		return err
	}
	if err := validateExpectedBudget("apply budget", e.ApplyBudgetMS, applyBudgetMS); err != nil {
		return err
	}
	if err := validateBudget("apply p95", e.ApplyP95MS, e.ApplyBudgetMS); err != nil {
		return err
	}
	if len(e.MapMemory) == 0 || e.MapMemorySamples != len(referenceMapMemoryStages) || len(e.MapMemoryHistory) != e.MapMemorySamples || !e.MapMemoryStable {
		return errors.New("map memory evidence is missing stability samples or is not marked stable")
	}
	if err := validateMapMemoryEntries(e.MapMemory, e.CPUs); err != nil {
		return err
	}
	if err := validateReferenceMapMemoryShape(e.MapMemory, e.CPUs); err != nil {
		return err
	}
	for index, snapshot := range e.MapMemoryHistory {
		if snapshot.Stage != referenceMapMemoryStages[index] {
			return fmt.Errorf("map memory snapshot %d stage = %q, want %q", index+1, snapshot.Stage, referenceMapMemoryStages[index])
		}
		if err := validateMapMemoryEntries(snapshot.Maps, e.CPUs); err != nil {
			return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
		}
		if err := validateReferenceMapMemoryShape(snapshot.Maps, e.CPUs); err != nil {
			return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
		}
		if index > 0 {
			// The first population can allocate map backing pages. Require
			// stable memlock only among the warmed, repeated apply samples.
			if err := compareMapMemory(e.MapMemoryHistory[index-1].Maps, snapshot.Maps, index > 1); err != nil {
				return fmt.Errorf("map memory snapshot %q: %w", snapshot.Stage, err)
			}
		}
	}
	if err := compareMapMemoryExact(e.MapMemoryHistory[len(e.MapMemoryHistory)-1].Maps, e.MapMemory); err != nil {
		return fmt.Errorf("final map memory snapshot: %w", err)
	}
	return nil
}

func validateReferenceMapMemoryShape(entries []mapMemoryEvidence, cpus int) error {
	expected := make([]mapMemoryEvidence, len(referenceMapMemoryShape))
	copy(expected, referenceMapMemoryShape)
	if len(entries) == len(referenceMapMemoryShape)+3 {
		expected = append(expected,
			mapMemoryEvidence{Name: "durable_v1", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 216, CapacityBounded: true},
			mapMemoryEvidence{Name: "program_registry", Type: "Hash", MaxEntries: 1024, KeySize: 4, ValueSize: 56, CapacityBounded: true},
			mapMemoryEvidence{Name: "subject_owners", Type: "Hash", MaxEntries: 32768, KeySize: 8, ValueSize: 656, CapacityBounded: true})
		slices.SortFunc(expected, func(a, b mapMemoryEvidence) int { return cmp.Compare(a.Name, b.Name) })
	}
	if len(entries) == len(referenceMapMemoryShape)+12 {
		expected = append(expected,
			mapMemoryEvidence{Name: "durable_v3", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 216, CapacityBounded: true},
			mapMemoryEvidence{Name: "configuration_0", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 16, CapacityBounded: true},
			mapMemoryEvidence{Name: "configuration_1", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 16, CapacityBounded: true},
			mapMemoryEvidence{Name: "program_registry", Type: "Hash", MaxEntries: 1024, KeySize: 4, ValueSize: 56, CapacityBounded: true},
			mapMemoryEvidence{Name: "subject_owners", Type: "Hash", MaxEntries: 32768, KeySize: 8, ValueSize: 656, CapacityBounded: true},
			mapMemoryEvidence{Name: "guard_owners", Type: "Hash", MaxEntries: 4, KeySize: 8, ValueSize: 536, CapacityBounded: true},
			mapMemoryEvidence{Name: "workload_class", Type: "Hash", MaxEntries: 32768, KeySize: 16, ValueSize: 1, CapacityBounded: true},
			mapMemoryEvidence{Name: "guard_config", Type: "Array", MaxEntries: 1, KeySize: 4, ValueSize: 16, CapacityBounded: true},
			mapMemoryEvidence{Name: "bootstrap_peers", Type: "Hash", MaxEntries: 64, KeySize: 8, ValueSize: 1, CapacityBounded: true},
			mapMemoryEvidence{Name: "host_owners", Type: "Hash", MaxEntries: 16384, KeySize: 8, ValueSize: 656, CapacityBounded: true},
			mapMemoryEvidence{Name: "guard_blocks", Type: "LRUCPUHash", MaxEntries: 4096, KeySize: 24, ValueSize: 8, CapacityBounded: true},
			mapMemoryEvidence{Name: "socket_netns", Type: "SkStorage", KeySize: 4, ValueSize: 8})
		slices.SortFunc(expected, func(a, b mapMemoryEvidence) int { return cmp.Compare(a.Name, b.Name) })
	}

	for index := range expected {
		capacity, err := calculatedMapCapacity(expected[index], cpus)
		if err != nil {
			return fmt.Errorf("calculate expected capacity for map %q: %w", expected[index].Name, err)
		}
		expected[index].CalculatedCapacityBytes = capacity
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("map memory contains %d maps, want the exact %d-map engine inventory", len(entries), len(expected))
	}
	for index, actual := range entries {
		want := expected[index]
		if actual.Name != want.Name || actual.Type != want.Type || actual.MaxEntries != want.MaxEntries ||
			actual.KeySize != want.KeySize || actual.ValueSize != want.ValueSize ||
			actual.CapacityBounded != want.CapacityBounded || actual.CalculatedCapacityBytes != want.CalculatedCapacityBytes {
			return fmt.Errorf("map %d = %#v, want %#v", index+1, actual, want)
		}
	}
	return nil
}

func validateMapMemoryEntries(entries []mapMemoryEvidence, cpus int) error {
	if len(entries) == 0 {
		return errors.New("map memory snapshot is empty")
	}
	if cpus <= 0 {
		return fmt.Errorf("map memory CPU count = %d, want positive", cpus)
	}
	knownTypes := map[string]struct{}{
		"Array": {}, "ArrayOfMaps": {}, "CGroupStorage": {}, "Hash": {},
		"LPMTrie": {}, "LRUHash": {}, "LRUCPUHash": {}, "PerCPUArray": {},
		"PerCPUHash": {}, "PerCPUCGroupStorage": {}, "RingBuf": {}, "SkStorage": {},
	}
	for index, memory := range entries {
		if memory.Name == "" || memory.Type == "" {
			return fmt.Errorf("invalid map memory entry %q", memory.Name)
		}
		if _, ok := knownTypes[memory.Type]; !ok {
			return fmt.Errorf("map %q has unknown type %q", memory.Name, memory.Type)
		}
		if index > 0 && memory.Name <= entries[index-1].Name {
			return fmt.Errorf("map entries are not strictly sorted by name at %q", memory.Name)
		}
		if memory.Type == "CGroupStorage" || memory.Type == "SkStorage" {
			if memory.MaxEntries != 0 || memory.CapacityBounded || memory.CalculatedCapacityBytes != 0 {
				return fmt.Errorf("cgroup-storage map %q must report an unbounded zero capacity", memory.Name)
			}
		} else if !memory.CapacityBounded || memory.MaxEntries == 0 || memory.CalculatedCapacityBytes == 0 {
			return fmt.Errorf("bounded map %q is missing a positive configured capacity", memory.Name)
		}
		if memory.Type != "RingBuf" && (memory.KeySize == 0 || memory.ValueSize == 0) {
			return fmt.Errorf("invalid key/value size for map %q", memory.Name)
		}
		if memory.MemlockAvailable && memory.ObservedMemlockBytes == 0 {
			return fmt.Errorf("map %q reports available memlock but zero observed bytes", memory.Name)
		}
		if !memory.MemlockAvailable && memory.ObservedMemlockBytes != 0 {
			return fmt.Errorf("map %q reports unavailable memlock with observed bytes %d", memory.Name, memory.ObservedMemlockBytes)
		}
		expected, err := calculatedMapCapacity(memory, cpus)
		if err != nil {
			return fmt.Errorf("map %q: %w", memory.Name, err)
		}
		if memory.CalculatedCapacityBytes != expected {
			return fmt.Errorf("map %q calculated capacity = %d, want %d", memory.Name, memory.CalculatedCapacityBytes, expected)
		}
	}
	return nil
}

func calculatedMapCapacity(memory mapMemoryEvidence, cpus int) (uint64, error) {
	if memory.Type == "CGroupStorage" || memory.Type == "SkStorage" {
		return 0, nil
	}
	if memory.Type == "RingBuf" {
		return uint64(memory.MaxEntries), nil
	}
	unitBytes := uint64(memory.KeySize) + uint64(memory.ValueSize)
	capacity := uint64(memory.MaxEntries)
	switch memory.Type {
	case "PerCPUHash", "PerCPUArray", "LRUCPUHash", "PerCPUCGroupStorage":
		if uint64(cpus) > ^uint64(0)/capacity {
			return 0, errors.New("per-CPU entry count overflows capacity calculation")
		}
		capacity *= uint64(cpus)
	}
	if unitBytes != 0 && capacity > ^uint64(0)/unitBytes {
		return 0, errors.New("map entry size overflows capacity calculation")
	}
	return capacity * unitBytes, nil
}

func compareMapMemory(previous, current []mapMemoryEvidence, compareMemlock bool) error {
	if len(previous) != len(current) {
		return fmt.Errorf("map count changed from %d to %d", len(previous), len(current))
	}
	for index := range previous {
		before := previous[index]
		after := current[index]
		if before.Name != after.Name || before.Type != after.Type ||
			before.MaxEntries != after.MaxEntries || before.KeySize != after.KeySize ||
			before.ValueSize != after.ValueSize || before.CapacityBounded != after.CapacityBounded ||
			before.CalculatedCapacityBytes != after.CalculatedCapacityBytes {
			return fmt.Errorf("map %q capacity changed from %#v to %#v", before.Name, before, after)
		}
		if compareMemlock && before.MemlockAvailable != after.MemlockAvailable {
			return fmt.Errorf("map %q memlock availability changed from %t to %t", before.Name, before.MemlockAvailable, after.MemlockAvailable)
		}
		if compareMemlock && before.MemlockAvailable && after.ObservedMemlockBytes > before.ObservedMemlockBytes {
			return fmt.Errorf("map %q observed memlock grew from %d to %d bytes", before.Name, before.ObservedMemlockBytes, after.ObservedMemlockBytes)
		}
	}
	return nil
}

func compareMapMemoryExact(expected, actual []mapMemoryEvidence) error {
	if err := compareMapMemory(expected, actual, true); err != nil {
		return err
	}
	for index := range expected {
		if expected[index].ObservedMemlockBytes != actual[index].ObservedMemlockBytes {
			return fmt.Errorf("map %q observed memlock changed from %d to %d bytes", expected[index].Name, expected[index].ObservedMemlockBytes, actual[index].ObservedMemlockBytes)
		}
	}
	return nil
}

func validateFlow(e flowEvidence) error {
	if err := validateEnvironment("flow", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return fmt.Errorf("flow %w", err)
	}
	if err := validateExactScope("flow scope", e.Scope, flowScope); err != nil {
		return err
	}
	if strings.TrimSpace(e.TrafficPattern) != flowTrafficPattern {
		return fmt.Errorf("flow traffic pattern = %q, want %q", e.TrafficPattern, flowTrafficPattern)
	}
	if e.RequestedRate != flowRate || math.IsNaN(e.DurationSeconds) || math.IsInf(e.DurationSeconds, 0) || e.DurationSeconds < flowSeconds || e.DurationSeconds > flowMaxSeconds {
		return fmt.Errorf("flow target is %d decisions/s for %.3fs, want %d/s for %d-%ds", e.RequestedRate, e.DurationSeconds, flowRate, flowSeconds, flowMaxSeconds)
	}
	if e.Decisions < uint64(flowRate*flowSeconds) {
		return fmt.Errorf("decisions = %d, want at least %d", e.Decisions, flowRate*flowSeconds)
	}
	maximumDecisions := (e.DurationSeconds + 1) * float64(flowRate)
	if float64(e.Decisions) > maximumDecisions {
		return fmt.Errorf("decisions = %d, exceed %.0f decisions allowed by %.3fs run", e.Decisions, maximumDecisions, e.DurationSeconds)
	}
	accounted := e.DeliveredEvents
	if e.RateLimitedEvents > ^uint64(0)-accounted {
		return errors.New("flow accounting component sum overflows uint64")
	}
	accounted += e.RateLimitedEvents
	if e.RingFullEvents > ^uint64(0)-accounted {
		return errors.New("flow accounting component sum overflows uint64")
	}
	accounted += e.RingFullEvents
	if accounted != e.AccountingTotal || e.AccountingTotal != e.Decisions || !e.AccountingBalanced {
		return fmt.Errorf("accounting is unbalanced: decisions=%d total=%d balanced=%t", e.Decisions, e.AccountingTotal, e.AccountingBalanced)
	}
	return nil
}

func validatePacket(e packetEvidence) error {
	if err := validateEnvironment("packet", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateExactScope("packet scope", e.Scope, packetScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.RoundTripsPerSample != packetRoundTrips || e.TCPBytesPerSample != packetTCPBytes {
		return fmt.Errorf("packet sample shape is %d samples/%d round-trips/%d TCP bytes, want %d/%d/%d", e.Samples, e.RoundTripsPerSample, e.TCPBytesPerSample, repeatedSamples, packetRoundTrips, packetTCPBytes)
	}
	for name, values := range map[string][]float64{
		"baseline latency": e.BaselineLatencyP99US,
		"enforced latency": e.EnforcedLatencyP99US,
		"baseline TCP":     e.BaselineTCPMbps,
		"enforced TCP":     e.EnforcedTCPMbps,
	} {
		if err := validatePositiveSamples(name, values, repeatedSamples); err != nil {
			return err
		}
	}
	if err := validateExpectedBudget("UDP latency budget", e.LatencyBudgetUS, latencyBudgetUS); err != nil {
		return err
	}
	if err := validateBudget("UDP latency delta", e.LatencyDeltaP99US, e.LatencyBudgetUS); err != nil {
		return err
	}
	if err := validateExpectedBudget("TCP throughput budget", e.ThroughputBudgetPercent, throughputBudget); err != nil {
		return err
	}
	if err := validateBudget("TCP throughput regression", e.MaxThroughputRegression, e.ThroughputBudgetPercent); err != nil {
		return err
	}

	latencyDelta := 0.0
	throughputRegression := 0.0
	for index := range e.BaselineLatencyP99US {
		if delta := e.EnforcedLatencyP99US[index] - e.BaselineLatencyP99US[index]; delta > latencyDelta {
			latencyDelta = delta
		}
		if e.BaselineTCPMbps[index] > 0 {
			regression := (e.BaselineTCPMbps[index] - e.EnforcedTCPMbps[index]) / e.BaselineTCPMbps[index] * 100
			if regression > throughputRegression {
				throughputRegression = regression
			}
		}
	}
	if !nearlyEqual(e.LatencyDeltaP99US, latencyDelta) || !nearlyEqual(e.MaxThroughputRegression, throughputRegression) {
		return fmt.Errorf("packet aggregate mismatch: latency delta %.6f/%.6f, throughput regression %.6f/%.6f", e.LatencyDeltaP99US, latencyDelta, e.MaxThroughputRegression, throughputRegression)
	}
	return nil
}

func validateActivation(e activationEvidence) error {
	if err := validateEnvironment("activation", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("activation", e.KernelRelease, e.Scope, activationScope); err != nil {
		return err
	}
	if e.CgroupRoot != "/sys/fs/cgroup" {
		return fmt.Errorf("activation cgroup root = %q, want /sys/fs/cgroup", e.CgroupRoot)
	}
	if e.BPFFSRoot != "/sys/fs/bpf" {
		return fmt.Errorf("activation bpffs root = %q, want /sys/fs/bpf", e.BPFFSRoot)
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("activation", e.ActivationMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("activation p95", e.ActivationMS, e.ActivationP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("activation budget", e.BudgetMS, activationBudget); err != nil {
		return err
	}
	return validateBudget("activation p95", e.ActivationP95, e.BudgetMS)
}

func validateReconciliation(e reconciliationEvidence) error {
	if err := validateEnvironment("reconciliation", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("reconciliation", e.KernelRelease, e.Scope, reconciliationScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples {
		return fmt.Errorf("samples = %d, want %d", e.Samples, repeatedSamples)
	}
	if err := validatePositiveSamples("reconciliation", e.ReconcileMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("reconciliation p95", e.ReconcileMS, e.ReconcileP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("reconciliation budget", e.BudgetMS, reconcileBudget); err != nil {
		return err
	}
	return validateBudget("reconciliation p95", e.ReconcileP95, e.BudgetMS)
}

func validateEvent(e eventEvidence) error {
	if err := validateEnvironment("event", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("event", e.KernelRelease, e.Scope, eventScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("event", e.EventMS, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("event p95", e.EventMS, e.EventP95); err != nil {
		return err
	}
	if err := validateExpectedBudget("event budget", e.BudgetMS, eventBudget); err != nil {
		return err
	}
	return validateBudget("event p95", e.EventP95, e.BudgetMS)
}

func validatePodStart(e podStartEvidence) error {
	if err := validateEnvironment("Pod-start", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("Pod-start", e.KernelRelease, e.Scope, podStartScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.InitialClassifications != referenceSubjects {
		return fmt.Errorf("pod-start sample shape is %d samples/%d initial classifications, want %d/%d", e.Samples, e.InitialClassifications, repeatedSamples, referenceSubjects)
	}
	if err := validatePositiveSamples("Pod-start", e.PodStart, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("Pod-start p95", e.PodStart, e.PodStartP95)
}

func validateRestart(e restartEvidence) error {
	if err := validateEnvironment("restart", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if e.SchemaVersion == restartproof.EvidenceVersion {
		if len(e.RestartMS) != 0 || e.RestartP95 != 0 {
			return errors.New("continuity evidence contains legacy restart-gap measurements")
		}
		return validateContinuity(e.KernelRelease, e.Scope, e.Subjects, e.Policies, e.Rules, e.Continuity, "SIGTERM")
	}
	if e.SchemaVersion != 0 || len(e.Continuity) != 0 {
		return errors.New("unsupported restart evidence version")
	}

	if err := validateAgentMetadata("restart", e.KernelRelease, e.Scope, restartScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if err := validatePositiveSamples("restart", e.RestartMS, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("restart p95", e.RestartMS, e.RestartP95)
}

func validateCrash(e crashEvidence) error {
	if err := validateEnvironment("crash", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if e.SchemaVersion == restartproof.EvidenceVersion {
		if len(e.CrashGapMS) != 0 || e.CrashGapP95 != 0 || e.Samples != repeatedSamples {
			return errors.New("invalid continuity evidence shape or legacy crash-gap measurements")
		}
		return validateContinuity(e.KernelRelease, e.Scope, e.Subjects, e.Policies, e.Rules, e.Continuity, "SIGKILL")
	}
	if e.SchemaVersion != 0 || len(e.Continuity) != 0 {
		return errors.New("unsupported crash evidence version")
	}

	if err := validateAgentMetadata("crash", e.KernelRelease, e.Scope, crashScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples {
		return fmt.Errorf("samples = %d, want %d", e.Samples, repeatedSamples)
	}
	if err := validatePositiveSamples("crash", e.CrashGapMS, repeatedSamples); err != nil {
		return err
	}
	return validateReportedMaximum("crash p95", e.CrashGapMS, e.CrashGapP95)
}

// Legacy unversioned measurements remain verifiable as historical performance
// data. Version 2 has a different fixture and must meet continuity invariants.
func validateContinuity(kernel, scope string, subjects, policies, rules int, samples []restartproof.Sample, mode string) error {
	if err := validateAgentMetadata("continuity", kernel, scope, restartproof.ContinuityScope); err != nil {
		return err
	}
	if subjects != 1 || policies != 1 || rules != 2 {
		return errors.New("continuity fixture must have one subject, one policy, and two directional rules")
	}
	return restartproof.ValidateSamples(samples, repeatedSamples, mode)
}

func validateResource(e resourceEvidence) error {
	if err := validateEnvironment("resource", e.RunID, e.TimestampUTC, e.GoVersion, e.GOOS, e.GOARCH, e.CPUs); err != nil {
		return err
	}
	if err := validateAgentMetadata("resource", e.KernelRelease, e.Scope, resourceScope); err != nil {
		return err
	}
	if err := validateFixture(e.Subjects, e.Policies, e.Rules); err != nil {
		return err
	}
	if e.Samples != repeatedSamples || e.QuietSeconds != 5 || e.ClockTicks <= 0 {
		return fmt.Errorf("resource sample shape is %d samples/%ds with %d clock ticks, want %d samples/5s and a positive clock rate", e.Samples, e.QuietSeconds, e.ClockTicks, repeatedSamples)
	}
	if err := validateSamples("CPU", e.CPUCoreSamples, repeatedSamples); err != nil {
		return err
	}
	if err := validateSamples("RSS", e.RSSMiBSamples, repeatedSamples); err != nil {
		return err
	}
	if err := validateReportedMaximum("CPU maximum", e.CPUCoreSamples, e.MaxCPUCore); err != nil {
		return err
	}
	if err := validateReportedMaximum("RSS maximum", e.RSSMiBSamples, e.MaxRSSMiB); err != nil {
		return err
	}
	if err := validateExpectedBudget("CPU budget", e.CPUBudgetCores, cpuBudgetCores); err != nil {
		return err
	}
	if err := validateBudget("CPU", e.MaxCPUCore, e.CPUBudgetCores); err != nil {
		return err
	}
	if err := validateExpectedBudget("RSS budget", e.RSSBudgetMiB, rssBudgetMiB); err != nil {
		return err
	}
	return validateBudget("RSS", e.MaxRSSMiB, e.RSSBudgetMiB)
}

func validateEnvironment(name, runID, timestamp, goVersion, goos, goarch string, cpus int) error {
	if strings.TrimSpace(runID) == "" {
		return fmt.Errorf("%s evidence is missing run ID", name)
	}
	if strings.TrimSpace(timestamp) == "" || strings.TrimSpace(goVersion) == "" {
		return fmt.Errorf("%s evidence is missing timestamp or Go version", name)
	}
	if !validGoVersionToken(goVersion) {
		return fmt.Errorf("%s evidence Go version %q is not a dotted version token", name, goVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		return fmt.Errorf("%s evidence timestamp %q is not RFC3339: %v", name, timestamp, err)
	}
	if goos != "linux" {
		return fmt.Errorf("%s evidence GOOS = %q, want linux", name, goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return fmt.Errorf("%s evidence GOARCH = %q, want amd64 or arm64", name, goarch)
	}
	if cpus != referenceCPUs {
		return fmt.Errorf("%s evidence reports %d CPUs, want the documented %d-CPU profile", name, cpus, referenceCPUs)
	}
	return nil
}

func validateAgentMetadata(name, kernelRelease, scope, expectedScope string) error {
	if err := validateNonEmpty(name+" kernel release", kernelRelease); err != nil {
		return err
	}
	return validateExactScope(name+" scope", scope, expectedScope)
}

func validateExactScope(name, actual, expected string) error {
	if actual != expected {
		return fmt.Errorf("%s = %q, want the exact producer scope %q", name, actual, expected)
	}
	return nil
}

func validateNonEmpty(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is missing", name)
	}
	return nil
}

func validateFixture(subjects, policies, rules int) error {
	if subjects != referenceSubjects || policies != referencePolicies || rules != referenceRules {
		return fmt.Errorf("fixture shape is %d subjects/%d policies/%d rules, want %d/%d/%d", subjects, policies, rules, referenceSubjects, referencePolicies, referenceRules)
	}
	return nil
}

func validateSamples(name string, values []float64, want int) error {
	if len(values) != want {
		return fmt.Errorf("%s samples = %d, want %d", name, len(values), want)
	}
	for index, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("%s sample %d is invalid: %v", name, index+1, value)
		}
	}
	return nil
}

func validatePositiveSamples(name string, values []float64, want int) error {
	if err := validateSamples(name, values, want); err != nil {
		return err
	}
	for index, value := range values {
		if value <= 0 {
			return fmt.Errorf("%s sample %d must be positive, got %v", name, index+1, value)
		}
	}
	return nil
}

func validateBudget(name string, value, budget float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.IsNaN(budget) || math.IsInf(budget, 0) || value < 0 || budget <= 0 {
		return fmt.Errorf("%s has invalid value/budget: %v/%v", name, value, budget)
	}
	if value > budget {
		return fmt.Errorf("%s = %.3f exceeds budget %.3f", name, value, budget)
	}
	return nil
}

func validateExpectedBudget(name string, actual, expected float64) error {
	if math.IsNaN(actual) || math.IsInf(actual, 0) || math.Abs(actual-expected) > 1e-9 {
		return fmt.Errorf("%s = %.9f, want documented %.9f", name, actual, expected)
	}
	return nil
}

func validateReportedMaximum(name string, values []float64, reported float64) error {
	if math.IsNaN(reported) || math.IsInf(reported, 0) || reported < 0 {
		return fmt.Errorf("%s is invalid: %v", name, reported)
	}
	maximum := 0.0
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	if !nearlyEqual(reported, maximum) {
		return fmt.Errorf("%s = %.9f, want maximum %.9f", name, reported, maximum)
	}
	return nil
}

func nearlyEqual(left, right float64) bool {
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= 1e-9*scale
}

func nearlyEqualMeasurement(left, right float64) bool {
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= 1e-6*scale
}
