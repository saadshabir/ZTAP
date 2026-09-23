//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/saadshabir/ZTAP/internal/flow"
	"github.com/saadshabir/ZTAP/internal/policy"
)

const (
	phase5ReferenceSubjects = 250
	phase5ReferencePolicies = 25
	phase5ReferenceRules    = 2500
	phase5ApplySamples      = 3
	phase5FlowRate          = 1000
	phase5FlowWarmup        = time.Second
	phase5FlowDuration      = 60 * time.Second
)

func phase5RunID(t *testing.T) string {
	t.Helper()
	runID := strings.TrimSpace(os.Getenv("ZTAP_PHASE5_RUN_ID"))
	if runID == "" {
		t.Fatal("ZTAP_PHASE5_RUN_ID is required for Phase 5 evidence")
	}
	return runID
}

type phase5ReferenceEvidence struct {
	TimestampUTC     string                    `json:"timestamp_utc"`
	RunID            string                    `json:"run_id"`
	GoVersion        string                    `json:"go_version"`
	GOOS             string                    `json:"goos"`
	GOARCH           string                    `json:"goarch"`
	CPUs             int                       `json:"cpus"`
	Subjects         int                       `json:"subjects"`
	Policies         int                       `json:"policies"`
	Rules            int                       `json:"rules"`
	ApplySamplesMS   []float64                 `json:"apply_samples_ms"`
	ApplyP95MS       float64                   `json:"apply_p95_ms"`
	ApplyBudgetMS    float64                   `json:"apply_budget_ms"`
	KernelPathScope  string                    `json:"kernel_path_scope"`
	MapMemory        []phase5MapMemoryEvidence `json:"map_memory"`
	MapMemorySamples int                       `json:"map_memory_samples"`
	MapMemoryHistory []phase5MapMemorySnapshot `json:"map_memory_history"`
	MapMemoryStable  bool                      `json:"map_memory_stable"`
}

type phase5MapMemorySnapshot struct {
	Stage string                    `json:"stage"`
	Maps  []phase5MapMemoryEvidence `json:"maps"`
}

type phase5MapMemoryEvidence struct {
	Name                    string `json:"name"`
	Type                    string `json:"type"`
	MaxEntries              uint32 `json:"max_entries"`
	KeySize                 uint32 `json:"key_size"`
	ValueSize               uint32 `json:"value_size"`
	CapacityBounded         bool   `json:"capacity_bounded"`
	CalculatedCapacityBytes uint64 `json:"calculated_capacity_bytes"`
	ObservedMemlockBytes    uint64 `json:"observed_memlock_bytes"`
	MemlockAvailable        bool   `json:"memlock_available"`
}

type phase5FlowEvidence struct {
	TimestampUTC       string  `json:"timestamp_utc"`
	RunID              string  `json:"run_id"`
	GoVersion          string  `json:"go_version"`
	GOOS               string  `json:"goos"`
	GOARCH             string  `json:"goarch"`
	CPUs               int     `json:"cpus"`
	Subjects           int     `json:"subjects"`
	Policies           int     `json:"policies"`
	Rules              int     `json:"rules"`
	RequestedRate      int     `json:"requested_decisions_per_second"`
	TrafficPattern     string  `json:"traffic_pattern"`
	DurationSeconds    float64 `json:"duration_seconds"`
	Decisions          uint64  `json:"decisions"`
	DeliveredEvents    uint64  `json:"delivered_events"`
	RateLimitedEvents  uint64  `json:"rate_limited_events"`
	RingFullEvents     uint64  `json:"ring_full_events"`
	AccountingTotal    uint64  `json:"accounting_total"`
	AccountingBalanced bool    `json:"accounting_balanced"`
	Scope              string  `json:"scope"`
}

// TestPhase5ReferenceFixtureApply measures the direct instance-owned engine
// apply path for the documented 250-subject/2,500-rule fixture. It is gated
// behind an explicit environment variable because the test creates real
// cgroups and loads eBPF programs. The full Section 14.5 release evidence
// still requires agent activation, packet, resource, fail-open, and flow-loss
// measurements outside this focused harness.
func TestPhase5ReferenceFixtureApply(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup performance harness")
	}
	requireLinuxEBPFRoot(t)

	root := createTestCgroup(t)
	cgroupPaths := make(map[uint64]string, phase5ReferenceSubjects)
	policySet := phase5ReferencePolicySet(t, root, cgroupPaths)
	engine := newLinuxEngineForTest(t, cgroupPaths)
	previousMapMemory := phase5MapMemory(t, engine)
	mapMemorySamples := 1
	mapMemoryHistory := []phase5MapMemorySnapshot{{Stage: "before_warmup", Maps: previousMapMemory}}

	// Populate both policy slots before checking repeated-apply memory. The
	// LPM trie allocates entries lazily, including on the first use of slot 0.
	for warmup := 0; warmup < 2; warmup++ {
		warmupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := engine.Apply(warmupContext, policySet)
		cancel()
		if err != nil {
			t.Fatalf("warm-up reference apply %d: %v", warmup+1, err)
		}
	}
	currentMapMemory := phase5MapMemory(t, engine)
	// LPM trie entries can allocate backing pages on first population. Capacity
	// must stay fixed, but observed memlock is compared only after warm-up.
	if err := requireStablePhase5MapMemory(previousMapMemory, currentMapMemory, false); err != nil {
		t.Fatalf("map memory changed after warm-up apply: %v", err)
	}
	previousMapMemory = currentMapMemory
	mapMemorySamples++
	mapMemoryHistory = append(mapMemoryHistory, phase5MapMemorySnapshot{Stage: "after_warmup", Maps: currentMapMemory})

	samples := make([]time.Duration, 0, phase5ApplySamples)
	for sample := 0; sample < phase5ApplySamples; sample++ {
		applyContext, applyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		started := time.Now()
		err := engine.Apply(applyContext, policySet)
		duration := time.Since(started)
		applyCancel()
		if err != nil {
			t.Fatalf("reference apply sample %d: %v", sample+1, err)
		}
		samples = append(samples, duration)
		currentMapMemory = phase5MapMemory(t, engine)
		if err := requireStablePhase5MapMemory(previousMapMemory, currentMapMemory, true); err != nil {
			t.Fatalf("map memory changed after apply sample %d: %v", sample+1, err)
		}
		previousMapMemory = currentMapMemory
		mapMemorySamples++
		mapMemoryHistory = append(mapMemoryHistory, phase5MapMemorySnapshot{Stage: fmt.Sprintf("after_apply_%d", sample+1), Maps: currentMapMemory})
	}

	sortedSamples := append([]time.Duration(nil), samples...)
	sort.Slice(sortedSamples, func(i, j int) bool { return sortedSamples[i] < sortedSamples[j] })
	p95 := sortedSamples[len(sortedSamples)-1]
	evidence := phase5ReferenceEvidence{
		TimestampUTC:     time.Now().UTC().Format(time.RFC3339Nano),
		RunID:            phase5RunID(t),
		GoVersion:        runtime.Version(),
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
		CPUs:             runtime.NumCPU(),
		Subjects:         len(policySet.Subjects),
		Policies:         phase5ReferencePolicies,
		Rules:            len(policySet.Rules),
		ApplySamplesMS:   durationMilliseconds(samples),
		ApplyP95MS:       float64(p95) / float64(time.Millisecond),
		ApplyBudgetMS:    2000,
		KernelPathScope:  "real cgroup creation, eBPF map population, policy flip, and cgroup link attachment",
		MapMemory:        previousMapMemory,
		MapMemorySamples: mapMemorySamples,
		MapMemoryHistory: mapMemoryHistory,
		MapMemoryStable:  true,
	}
	if len(policySet.Subjects) != phase5ReferenceSubjects {
		t.Fatalf("reference subjects = %d, want %d", len(policySet.Subjects), phase5ReferenceSubjects)
	}
	if len(policySet.Rules) != phase5ReferenceRules {
		t.Fatalf("reference rules = %d, want %d", len(policySet.Rules), phase5ReferenceRules)
	}
	if p95 > 2*time.Second {
		t.Fatalf("direct engine apply p95 = %s, want <= 2s", p95)
	}
	writePhase5ReferenceEvidence(t, evidence)
}

func phase5MapMemory(t *testing.T, engine *LinuxEngine) []phase5MapMemoryEvidence {
	t.Helper()
	names := make([]string, 0, len(engine.store.maps))
	for name := range engine.store.maps {
		names = append(names, name)
	}
	sort.Strings(names)
	evidence := make([]phase5MapMemoryEvidence, 0, len(names))
	for _, name := range names {
		info, err := engine.store.maps[name].Info()
		if err != nil {
			t.Fatalf("read map %q memory metadata: %v", name, err)
		}
		mapType := info.Type.String()
		capacityBounded := mapType != "CGroupStorage"
		calculated, err := phase5MapCapacityBytes(mapType, info.MaxEntries, info.KeySize, info.ValueSize, runtime.NumCPU())
		if err != nil {
			t.Fatalf("calculate map %q capacity: %v", name, err)
		}
		memlock, available := info.Memlock()
		evidence = append(evidence, phase5MapMemoryEvidence{
			Name:                    name,
			Type:                    info.Type.String(),
			MaxEntries:              info.MaxEntries,
			KeySize:                 info.KeySize,
			ValueSize:               info.ValueSize,
			CapacityBounded:         capacityBounded,
			CalculatedCapacityBytes: calculated,
			ObservedMemlockBytes:    memlock,
			MemlockAvailable:        available,
		})
	}
	return evidence
}

func requireStablePhase5MapMemory(previous, current []phase5MapMemoryEvidence, compareMemlock bool) error {
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
		if compareMemlock && before.MemlockAvailable && after.MemlockAvailable && after.ObservedMemlockBytes > before.ObservedMemlockBytes {
			return fmt.Errorf("map %q observed memlock grew from %d to %d bytes", before.Name, before.ObservedMemlockBytes, after.ObservedMemlockBytes)
		}
		if compareMemlock && before.MemlockAvailable != after.MemlockAvailable {
			return fmt.Errorf("map %q memlock availability changed from %t to %t", before.Name, before.MemlockAvailable, after.MemlockAvailable)
		}
	}
	return nil
}

// TestPhase5FlowAccounting verifies that sustained real packet decisions are
// accounted for by either a delivered flow event or an explicit drop counter.
// It does not measure TCP throughput or packet latency; those remain separate
// Section 14.5 gates.
func TestPhase5FlowAccounting(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-cgroup performance harness")
	}
	requireLinuxEBPFRoot(t)

	root := createTestCgroup(t)
	cgroupPaths := make(map[uint64]string, phase5ReferenceSubjects)
	flowPolicy := phase5ReferencePolicySet(t, root, cgroupPaths)
	selectedSubject := flowPolicy.Subjects[0]
	cgroup := cgroupPaths[selectedSubject.CgroupID]
	if cgroup == "" {
		t.Fatalf("flow-accounting cgroup %d was not created", selectedSubject.CgroupID)
	}
	allowed := listenEngineTestUDP(t)
	blocked := listenEngineTestUDP(t)
	allowedAddress := allowed.LocalAddr().String()
	blockedAddress := blocked.LocalAddr().String()
	allowedPort := uint16(allowed.LocalAddr().(*net.UDPAddr).Port)
	blockedPort := uint16(blocked.LocalAddr().(*net.UDPAddr).Port)
	flowRuleUpdated := false
	for index := range flowPolicy.Rules {
		if flowPolicy.Rules[index].CgroupID != selectedSubject.CgroupID {
			continue
		}
		flowPolicy.Rules[index].Peer = netip.MustParsePrefix("127.0.0.0/8")
		flowPolicy.Rules[index].Protocol = policy.ProtocolUDP
		flowPolicy.Rules[index].Port = allowedPort
		flowRuleUpdated = true
		break
	}
	if !flowRuleUpdated {
		t.Fatalf("flow-accounting policy has no rule for selected cgroup %d", selectedSubject.CgroupID)
	}
	if err := policy.ValidatePolicySet(flowPolicy); err != nil {
		t.Fatalf("validate full flow-accounting policy: %v", err)
	}
	engine := newLinuxEngineForTest(t, cgroupPaths)
	if err := engine.Apply(context.Background(), flowPolicy); err != nil {
		t.Fatalf("apply flow-accounting policy: %v", err)
	}

	reader, err := ringbuf.NewReader(engine.FlowEventsMap())
	if err != nil {
		t.Fatalf("create flow-accounting reader: %v", err)
	}
	defer reader.Close()
	var delivered atomic.Uint64
	var measuredEpoch atomic.Uint64
	readerErrors := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			record, readErr := reader.Read()
			if readErr != nil {
				if !errors.Is(readErr, ringbuf.ErrClosed) {
					select {
					case readerErrors <- readErr:
					default:
					}
				}
				return
			}
			if len(record.RawSample) != 72 {
				select {
				case readerErrors <- fmt.Errorf("unexpected flow event size %d", len(record.RawSample)):
				default:
				}
				return
			}
			var event flow.RawFlowEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				select {
				case readerErrors <- fmt.Errorf("decode flow event: %w", err):
				default:
				}
				return
			}
			matched, matchErr := phase5FlowEventMatch(event, measuredEpoch.Load(), selectedSubject.CgroupID, allowedPort, blockedPort)
			if matchErr != nil {
				select {
				case readerErrors <- matchErr:
				default:
				}
				return
			}
			if matched {
				delivered.Add(1)
			}
		}
	}()

	warmupLoop := startUDPLoopHelper(t, cgroup, []string{allowedAddress, blockedAddress}, phase5FlowRate)
	time.Sleep(phase5FlowWarmup)
	if warmupLoop.ProcessState == nil {
		_ = warmupLoop.Process.Kill()
		_ = warmupLoop.Wait()
	}
	time.Sleep(time.Second)
	if err := engine.Apply(context.Background(), flowPolicy); err != nil {
		t.Fatalf("refresh flow-accounting policy after warm-up: %v", err)
	}
	before, err := engine.MetricsSnapshot(context.Background())
	if err != nil {
		t.Fatalf("read flow-accounting baseline: %v", err)
	}
	measuredEpoch.Store(before.ActivePolicyEpoch)
	loop := startUDPLoopHelper(t, cgroup, []string{allowedAddress, blockedAddress}, phase5FlowRate)
	started := time.Now()
	time.Sleep(phase5FlowDuration)
	trafficDuration := time.Since(started)
	if loop.ProcessState == nil {
		_ = loop.Process.Kill()
		_ = loop.Wait()
	}
	if trafficDuration > phase5FlowDuration+5*time.Second {
		t.Fatalf("flow measurement duration = %s, want no more than %s", trafficDuration, phase5FlowDuration+5*time.Second)
	}
	// Give the reader time to consume events already reserved before closing it.
	time.Sleep(time.Second)
	if err := reader.Close(); err != nil {
		t.Fatalf("close flow-accounting reader: %v", err)
	}
	<-readerDone
	select {
	case readerErr := <-readerErrors:
		t.Fatalf("read flow-accounting event: %v", readerErr)
	default:
	}

	after, err := engine.MetricsSnapshot(context.Background())
	if err != nil {
		t.Fatalf("read flow-accounting result: %v", err)
	}
	decisions, err := phase5DecisionDelta(before, after)
	if err != nil {
		t.Fatalf("calculate flow decision delta: %v", err)
	}
	rateLimited, err := phase5DropDelta(before, after, "rate_limited")
	if err != nil {
		t.Fatalf("calculate rate-limited event delta: %v", err)
	}
	ringFull, err := phase5DropDelta(before, after, "ring_full")
	if err != nil {
		t.Fatalf("calculate ring-full event delta: %v", err)
	}
	deliveredEvents := delivered.Load()
	accountingTotal, err := phase5CounterSum(deliveredEvents, rateLimited, ringFull)
	if err != nil {
		t.Fatalf("calculate flow accounting total: %v", err)
	}
	evidence := phase5FlowEvidence{
		TimestampUTC:       time.Now().UTC().Format(time.RFC3339Nano),
		RunID:              phase5RunID(t),
		GoVersion:          runtime.Version(),
		GOOS:               runtime.GOOS,
		GOARCH:             runtime.GOARCH,
		CPUs:               runtime.NumCPU(),
		Subjects:           len(flowPolicy.Subjects),
		Policies:           phase5ReferencePolicies,
		Rules:              len(flowPolicy.Rules),
		RequestedRate:      phase5FlowRate,
		TrafficPattern:     "one alternating allowed/blocked UDP decision per millisecond",
		DurationSeconds:    trafficDuration.Seconds(),
		Decisions:          decisions,
		DeliveredEvents:    deliveredEvents,
		RateLimitedEvents:  rateLimited,
		RingFullEvents:     ringFull,
		AccountingTotal:    accountingTotal,
		AccountingBalanced: decisions == accountingTotal,
		Scope:              "full 250-subject/2,500-rule real-cgroup fixture with one selected subject generating alternating allowed/blocked UDP decisions",
	}
	minimumDecisions := uint64(phase5FlowRate * int(phase5FlowDuration/time.Second))
	if decisions < minimumDecisions {
		t.Fatalf("flow decisions = %d, want at least %d", decisions, minimumDecisions)
	}
	maximumDecisions := uint64((trafficDuration.Seconds() + 1) * float64(phase5FlowRate))
	if decisions > maximumDecisions {
		t.Fatalf("flow decisions = %d, want no more than %d for the one-packet-per-millisecond helper", decisions, maximumDecisions)
	}
	if decisions != accountingTotal {
		t.Fatalf("flow accounting mismatch: decisions=%d delivered=%d rate_limited=%d ring_full=%d",
			decisions, deliveredEvents, rateLimited, ringFull)
	}
	writePhase5FlowEvidence(t, evidence)
}

func phase5ReferencePolicySet(t *testing.T, root string, cgroupPaths map[uint64]string) policy.PolicySet {
	t.Helper()
	subjects := make([]policy.Subject, 0, phase5ReferenceSubjects)
	rules := make([]policy.Rule, 0, phase5ReferenceRules)
	for subjectIndex := 0; subjectIndex < phase5ReferenceSubjects; subjectIndex++ {
		cgroup := createSubCgroup(t, root, fmt.Sprintf("reference-%03d", subjectIndex))
		cgroupID := mustCgroupID(t, cgroup)
		cgroupPaths[cgroupID] = cgroup
		subjects = append(subjects, policy.Subject{
			CgroupID: cgroupID,
			Isolated: policy.DirectionEgress,
			PodIPs: []netip.Addr{netip.AddrFrom4([4]byte{
				10,
				0,
				1,
				byte(subjectIndex + 1),
			})},
		})
		for ruleIndex := 0; ruleIndex < phase5ReferenceRules/phase5ReferenceSubjects; ruleIndex++ {
			ruleNumber := subjectIndex*(phase5ReferenceRules/phase5ReferenceSubjects) + ruleIndex
			rules = append(rules, policy.Rule{
				CgroupID:  cgroupID,
				Direction: policy.DirectionEgress,
				Peer: netip.PrefixFrom(netip.AddrFrom4([4]byte{
					203,
					0,
					113,
					byte(ruleNumber % 256),
				}), 32),
				Protocol: policy.ProtocolTCP,
				Port:     uint16(10000 + ruleIndex),
			})
		}
	}
	result := policy.PolicySet{
		NodeIPs:  []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Subjects: subjects,
		Rules:    rules,
	}
	if err := policy.ValidatePolicySet(result); err != nil {
		t.Fatalf("validate reference policy set: %v", err)
	}
	return result
}

func durationMilliseconds(values []time.Duration) []float64 {
	result := make([]float64, len(values))
	for i, value := range values {
		result[i] = float64(value) / float64(time.Millisecond)
	}
	return result
}

func writePhase5ReferenceEvidence(t *testing.T, evidence phase5ReferenceEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode reference performance evidence: %v", err)
	}
	t.Logf("reference performance evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_PERFORMANCE_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote reference performance evidence to %s", output)
}

func writePhase5FlowEvidence(t *testing.T, evidence phase5FlowEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode flow performance evidence: %v", err)
	}
	t.Logf("flow performance evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_FLOW_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote flow performance evidence to %s", output)
}
