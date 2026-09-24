//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/policy"
)

const (
	phase5PacketSamples = 3
	// Keep roughly 100 observations in the tail used for each p99 estimate.
	phase5PacketRoundTrips = 10_000
	phase5TCPBytes         = 128 << 20
)

type phase5PacketEvidence struct {
	TimestampUTC            string    `json:"timestamp_utc"`
	RunID                   string    `json:"run_id"`
	GoVersion               string    `json:"go_version"`
	GOOS                    string    `json:"goos"`
	GOARCH                  string    `json:"goarch"`
	CPUs                    int       `json:"cpus"`
	Subjects                int       `json:"subjects"`
	Policies                int       `json:"policies"`
	Rules                   int       `json:"rules"`
	Samples                 int       `json:"samples"`
	RoundTripsPerSample     int       `json:"round_trips_per_sample"`
	TCPBytesPerSample       int       `json:"tcp_bytes_per_sample"`
	BaselineLatencyP99US    []float64 `json:"baseline_latency_p99_us"`
	EnforcedLatencyP99US    []float64 `json:"enforced_latency_p99_us"`
	LatencyDeltaP99US       float64   `json:"latency_delta_p99_us"`
	LatencyBudgetUS         float64   `json:"latency_budget_us"`
	BaselineTCPMbps         []float64 `json:"baseline_tcp_mbps"`
	EnforcedTCPMbps         []float64 `json:"enforced_tcp_mbps"`
	MaxThroughputRegression float64   `json:"max_throughput_regression_percent"`
	ThroughputBudgetPercent float64   `json:"throughput_budget_percent"`
	Scope                   string    `json:"scope"`
}

// TestPhase5PacketAndTCPPerformance compares real loopback packets in one
// selected subject of the full reference fixture with the cgroup programs
// detached and attached. It measures the user-visible UDP round-trip p99 and
// TCP transfer regression; it does not substitute synthetic Go benchmarks for
// kernel-path evidence.
func TestPhase5PacketAndTCPPerformance(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("set ZTAP_PHASE5_PERFORMANCE=1 to run the real-packet performance harness")
	}
	requireLinuxEBPFRoot(t)

	baselineLatency := make([]float64, 0, phase5PacketSamples)
	enforcedLatency := make([]float64, 0, phase5PacketSamples)
	baselineTCP := make([]float64, 0, phase5PacketSamples)
	enforcedTCP := make([]float64, 0, phase5PacketSamples)
	// Complete one detached/attached pass without recording it so loopback,
	// cgroup-link, and map paths are warm for the three retained samples.
	for sample := 0; sample < phase5PacketSamples+1; sample++ {
		root := createTestCgroup(t)
		cgroupPaths := make(map[uint64]string, phase5ReferenceSubjects)
		subjectIDs := make([]uint64, 0, phase5ReferenceSubjects)
		var cgroup string
		for subjectIndex := 0; subjectIndex < phase5ReferenceSubjects; subjectIndex++ {
			subjectCgroup := createSubCgroup(t, root, fmt.Sprintf("packet-performance-%03d-%03d", sample, subjectIndex))
			subjectID := mustCgroupID(t, subjectCgroup)
			cgroupPaths[subjectID] = subjectCgroup
			subjectIDs = append(subjectIDs, subjectID)
			if subjectIndex == 0 {
				cgroup = subjectCgroup
			}
		}

		baselineUDP := listenEngineTestUDP(t)
		baselineTCPListener := listenEngineTestTCP(t)
		enforcedUDP := listenEngineTestUDP(t)
		enforcedTCPListener := listenEngineTestTCP(t)

		baselineUDPP99 := runPhase5UDPLatency(t, cgroup, baselineUDP, phase5PacketRoundTrips)
		baselineTCPDuration := runPhase5TCPTransfer(t, cgroup, baselineTCPListener, phase5TCPBytes)

		engine, err := NewLinuxEngine(context.Background(), LinuxEngineOptions{
			CgroupRoot: "/sys/fs/cgroup",
			BPFFSRoot:  "/sys/fs/bpf",
			ResolveCgroupPath: func(_ context.Context, id uint64) (string, error) {
				subjectCgroup, ok := cgroupPaths[id]
				if !ok {
					return "", fmt.Errorf("unknown packet-performance cgroup %d", id)
				}
				return subjectCgroup, nil
			},
			AgentEpoch: uint64(100 + sample),
		})
		if err != nil {
			t.Fatalf("create packet-performance engine sample %d: %v", sample+1, err)
		}
		if err := engine.Apply(context.Background(), phase5PacketPolicySet(t, subjectIDs,
			uint16(enforcedUDP.LocalAddr().(*net.UDPAddr).Port),
			uint16(enforcedTCPListener.Addr().(*net.TCPAddr).Port))); err != nil {
			_ = engine.Close()
			t.Fatalf("apply packet-performance policy sample %d: %v", sample+1, err)
		}

		enforcedUDPP99 := runPhase5UDPLatency(t, cgroup, enforcedUDP, phase5PacketRoundTrips)
		beforeTCP, err := engine.MetricsSnapshot(context.Background())
		if err != nil {
			_ = engine.Close()
			t.Fatalf("read packet-performance pre-transfer counters: %v", err)
		}
		enforcedTCPDuration := runPhase5TCPTransfer(t, cgroup, enforcedTCPListener, phase5TCPBytes)
		afterTCP, err := engine.MetricsSnapshot(context.Background())
		if err != nil {
			_ = engine.Close()
			t.Fatalf("read packet-performance post-transfer counters: %v", err)
		}
		t.Logf("packet sample %d: baseline TCP %.3f ms (%.2f Mbps), enforced TCP %.3f ms (%.2f Mbps), baseline UDP p99 %s, enforced UDP p99 %s",
			sample, float64(baselineTCPDuration)/float64(time.Millisecond), phase5TCPMbps(phase5TCPBytes, baselineTCPDuration),
			float64(enforcedTCPDuration)/float64(time.Millisecond), phase5TCPMbps(phase5TCPBytes, enforcedTCPDuration), baselineUDPP99, enforcedUDPP99)
		if len(beforeTCP.Decisions) != len(afterTCP.Decisions) {
			_ = engine.Close()
			t.Fatalf("packet counter shape changed during sample %d", sample)
		}
		for index, decision := range afterTCP.Decisions {
			if decision.Count < beforeTCP.Decisions[index].Count {
				_ = engine.Close()
				t.Fatalf("packet counter reset during sample %d: %+v", sample, decision)
			}
			if delta := decision.Count - beforeTCP.Decisions[index].Count; delta != 0 {
				t.Logf("packet sample %d: TCP %s/%s/%s decisions=%d", sample, decision.Direction, decision.Action, decision.Reason, delta)
				if decision.Direction == "egress" && decision.Action == "blocked" {
					_ = engine.Close()
					t.Fatalf("allowed TCP transfer blocked %d packets as %s in sample %d", delta, decision.Reason, sample)
				}
			}
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("close packet-performance engine sample %d: %v", sample+1, err)
		}
		if sample == 0 {
			continue
		}
		baselineLatency = append(baselineLatency, float64(baselineUDPP99)/float64(time.Microsecond))
		baselineTCP = append(baselineTCP, phase5TCPMbps(phase5TCPBytes, baselineTCPDuration))
		enforcedLatency = append(enforcedLatency, float64(enforcedUDPP99)/float64(time.Microsecond))
		enforcedTCP = append(enforcedTCP, phase5TCPMbps(phase5TCPBytes, enforcedTCPDuration))
	}

	latencyDelta := 0.0
	maxRegression := 0.0
	for i := range baselineLatency {
		if delta := enforcedLatency[i] - baselineLatency[i]; delta > latencyDelta {
			latencyDelta = delta
		}
		if baselineTCP[i] > 0 {
			regression := (baselineTCP[i] - enforcedTCP[i]) / baselineTCP[i] * 100
			if regression > maxRegression {
				maxRegression = regression
			}
		}
	}
	evidence := phase5PacketEvidence{
		TimestampUTC:            time.Now().UTC().Format(time.RFC3339Nano),
		RunID:                   phase5RunID(t),
		GoVersion:               runtime.Version(),
		GOOS:                    runtime.GOOS,
		GOARCH:                  runtime.GOARCH,
		CPUs:                    runtime.NumCPU(),
		Subjects:                phase5ReferenceSubjects,
		Policies:                phase5ReferencePolicies,
		Rules:                   phase5ReferenceRules,
		Samples:                 phase5PacketSamples,
		RoundTripsPerSample:     phase5PacketRoundTrips,
		TCPBytesPerSample:       phase5TCPBytes,
		BaselineLatencyP99US:    baselineLatency,
		EnforcedLatencyP99US:    enforcedLatency,
		LatencyDeltaP99US:       latencyDelta,
		LatencyBudgetUS:         10,
		BaselineTCPMbps:         baselineTCP,
		EnforcedTCPMbps:         enforcedTCP,
		MaxThroughputRegression: maxRegression,
		ThroughputBudgetPercent: 10,
		Scope:                   "full 250-subject/2,500-rule real-cgroup fixture with loopback UDP round trips and TCP transfers from one selected subject, cgroup eBPF detached versus attached",
	}
	if latencyDelta > evidence.LatencyBudgetUS {
		t.Fatalf("packet latency p99 delta = %.2fµs, want <= %.2fµs", latencyDelta, evidence.LatencyBudgetUS)
	}
	if maxRegression > evidence.ThroughputBudgetPercent {
		t.Fatalf("TCP throughput regression = %.2f%%, want <= %.2f%%", maxRegression, evidence.ThroughputBudgetPercent)
	}
	writePhase5PacketEvidence(t, evidence)
}

func phase5PacketPolicySet(t *testing.T, subjectIDs []uint64, udpPort, tcpPort uint16) policy.PolicySet {
	t.Helper()
	if len(subjectIDs) != phase5ReferenceSubjects {
		t.Fatalf("packet-performance subject IDs = %d, want %d", len(subjectIDs), phase5ReferenceSubjects)
	}
	subjects := make([]policy.Subject, 0, phase5ReferenceSubjects)
	rules := make([]policy.Rule, 0, phase5ReferenceRules)
	for subjectIndex := 0; subjectIndex < phase5ReferenceSubjects; subjectIndex++ {
		subjectID := subjectIDs[subjectIndex]
		subjects = append(subjects, policy.Subject{
			CgroupID: subjectID,
			Isolated: policy.DirectionEgress,
			PodIPs: []netip.Addr{netip.AddrFrom4([4]byte{
				10,
				0,
				2,
				byte(subjectIndex + 1),
			})},
		})
		for ruleIndex := 0; ruleIndex < phase5ReferenceRules/phase5ReferenceSubjects; ruleIndex++ {
			protocol := policy.ProtocolTCP
			port := uint16(20000 + subjectIndex*10 + ruleIndex)
			if subjectIndex == 0 && ruleIndex == 0 {
				protocol = policy.ProtocolUDP
				port = udpPort
			}
			if subjectIndex == 0 && ruleIndex == 1 {
				port = tcpPort
			}
			rules = append(rules, policy.Rule{
				CgroupID:  subjectID,
				Direction: policy.DirectionEgress,
				Peer:      netip.MustParsePrefix("127.0.0.0/8"),
				Protocol:  protocol,
				Port:      port,
			})
		}
	}
	set := policy.PolicySet{
		NodeIPs:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Subjects: subjects,
		Rules:    rules,
	}
	if err := policy.ValidatePolicySet(set); err != nil {
		t.Fatalf("validate packet-performance policy: %v", err)
	}
	if len(set.Subjects) != phase5ReferenceSubjects || len(set.Rules) != phase5ReferenceRules {
		t.Fatalf("packet-performance fixture = %d subjects/%d rules, want %d/%d", len(set.Subjects), len(set.Rules), phase5ReferenceSubjects, phase5ReferenceRules)
	}
	return set
}

func startPhase5UDPEcho(t *testing.T, listener *net.UDPConn, expected int) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		for count := 0; count < expected; count++ {
			if err := listener.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
				done <- err
				return
			}
			n, address, err := listener.ReadFromUDP(buffer)
			if err != nil {
				done <- err
				return
			}
			if _, err := listener.WriteToUDP(buffer[:n], address); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

func waitPhase5UDPEcho(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UDP echo server: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for UDP echo server")
	}
}

func TestCgroupPhase5UDPLatencyHelper(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_UDP_LATENCY_HELPER") != "1" {
		t.Skip("helper")
	}
	start := os.NewFile(uintptr(3), "start")
	status := os.NewFile(uintptr(4), "status")
	if start == nil || status == nil {
		t.Fatal("UDP latency helper pipes are missing")
	}
	defer start.Close()
	defer status.Close()
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatalf("UDP latency helper start: %v", err)
	}
	address := os.Getenv("ZTAP_PHASE5_UDP_ADDR")
	if address == "" {
		t.Fatal("ZTAP_PHASE5_UDP_ADDR is required")
	}
	connection, err := net.DialTimeout("udp4", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial UDP latency target: %v", err)
	}
	defer connection.Close()
	payload := []byte("phase5")
	response := make([]byte, len(payload))
	samples := make([]time.Duration, 0, phase5PacketRoundTrips)
	for i := 0; i < phase5PacketRoundTrips; i++ {
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set UDP latency deadline: %v", err)
		}
		started := time.Now()
		if _, err := connection.Write(payload); err != nil {
			t.Fatalf("write UDP latency packet: %v", err)
		}
		if _, err := io.ReadFull(connection, response); err != nil {
			t.Fatalf("read UDP latency response: %v", err)
		}
		samples = append(samples, time.Since(started))
	}
	p99 := phase5P99Duration(samples)
	if _, err := fmt.Fprintf(status, "%d\n", p99.Nanoseconds()); err != nil {
		t.Fatalf("write UDP latency result: %v", err)
	}
}

func runPhase5UDPLatency(t *testing.T, cgroup string, listener *net.UDPConn, expected int) time.Duration {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create UDP latency start pipe: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("create UDP latency status pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupPhase5UDPLatencyHelper$")
	cmd.Env = append(os.Environ(), "ZTAP_PHASE5_UDP_LATENCY_HELPER=1", "ZTAP_PHASE5_UDP_ADDR="+listener.LocalAddr().String())
	cmd.ExtraFiles = []*os.File{startReader, statusWriter}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		_ = statusReader.Close()
		_ = statusWriter.Close()
		t.Fatalf("start UDP latency helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = statusReader.Close()
	})
	_ = startReader.Close()
	_ = statusWriter.Close()
	moveProcessToCgroup(t, cmd, cgroup)
	echoDone := startPhase5UDPEcho(t, listener, expected)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release UDP latency helper: %v", err)
	}
	_ = startWriter.Close()
	value := readPhase5StatusLine(t, statusReader)
	waitPhase5UDPEcho(t, echoDone)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("UDP latency helper: %v", err)
	}
	nanoseconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || nanoseconds <= 0 {
		t.Fatalf("UDP latency p99 result %q: %v", value, err)
	}
	return time.Duration(nanoseconds)
}

func TestCgroupPhase5TCPThroughputHelper(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_TCP_THROUGHPUT_HELPER") != "1" {
		t.Skip("helper")
	}
	start := os.NewFile(uintptr(3), "start")
	status := os.NewFile(uintptr(4), "status")
	if start == nil || status == nil {
		t.Fatal("TCP throughput helper pipes are missing")
	}
	defer start.Close()
	defer status.Close()
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatalf("TCP throughput helper start: %v", err)
	}
	address := os.Getenv("ZTAP_PHASE5_TCP_ADDR")
	bytesToWrite, err := strconv.Atoi(os.Getenv("ZTAP_PHASE5_TCP_BYTES"))
	if err != nil || bytesToWrite <= 0 {
		t.Fatalf("invalid TCP throughput byte count: %q", os.Getenv("ZTAP_PHASE5_TCP_BYTES"))
	}
	connection, err := net.DialTimeout("tcp4", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial TCP throughput target: %v", err)
	}
	buffer := make([]byte, 32*1024)
	for remaining := bytesToWrite; remaining > 0; {
		chunk := len(buffer)
		if remaining < chunk {
			chunk = remaining
		}
		written, writeErr := connection.Write(buffer[:chunk])
		if writeErr != nil {
			_ = connection.Close()
			t.Fatalf("write TCP throughput payload: %v", writeErr)
		}
		remaining -= written
	}
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = connection.Close()
	if _, err := fmt.Fprintln(status, "done"); err != nil {
		t.Fatalf("write TCP throughput completion: %v", err)
	}
}

func runPhase5TCPTransfer(t *testing.T, cgroup string, listener *net.TCPListener, bytesToRead int) time.Duration {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create TCP throughput start pipe: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("create TCP throughput status pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupPhase5TCPThroughputHelper$")
	cmd.Env = append(os.Environ(),
		"ZTAP_PHASE5_TCP_THROUGHPUT_HELPER=1",
		"ZTAP_PHASE5_TCP_ADDR="+listener.Addr().String(),
		"ZTAP_PHASE5_TCP_BYTES="+strconv.Itoa(bytesToRead),
	)
	cmd.ExtraFiles = []*os.File{startReader, statusWriter}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		_ = statusReader.Close()
		_ = statusWriter.Close()
		t.Fatalf("start TCP throughput helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = statusReader.Close()
	})
	_ = startReader.Close()
	_ = statusWriter.Close()
	moveProcessToCgroup(t, cmd, cgroup)
	if err := listener.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set TCP throughput listener deadline: %v", err)
	}
	started := time.Now()
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release TCP throughput helper: %v", err)
	}
	_ = startWriter.Close()
	connection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept TCP throughput helper: %v", err)
	}
	if _, err := io.CopyN(io.Discard, connection, int64(bytesToRead)); err != nil {
		_ = connection.Close()
		t.Fatalf("read TCP throughput payload: %v", err)
	}
	duration := time.Since(started)
	_ = connection.Close()
	if got := readPhase5StatusLine(t, statusReader); strings.TrimSpace(got) != "done" {
		t.Fatalf("TCP throughput helper status = %q, want done", got)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("TCP throughput helper: %v", err)
	}
	return duration
}

func readPhase5StatusLine(t *testing.T, reader *os.File) string {
	t.Helper()
	result := make(chan struct {
		line string
		err  error
	}, 1)
	go func() {
		line, err := bufio.NewReader(reader).ReadString('\n')
		result <- struct {
			line string
			err  error
		}{line: line, err: err}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatalf("read helper status: %v", value.err)
		}
		return value.line
	case <-time.After(20 * time.Second):
		_ = reader.Close()
		t.Fatal("timed out reading helper status")
		return ""
	}
}

func phase5P99Duration(values []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := (len(sorted)*99+99)/100 - 1
	if index < 0 {
		return 0
	}
	return sorted[index]
}

func phase5TCPMbps(bytes int, duration time.Duration) float64 {
	if duration <= 0 {
		return 0
	}
	return float64(bytes*8) / duration.Seconds() / 1_000_000
}

func writePhase5PacketEvidence(t *testing.T, evidence phase5PacketEvidence) {
	t.Helper()
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode packet performance evidence: %v", err)
	}
	t.Logf("packet performance evidence:\n%s", payload)
	output := os.Getenv("ZTAP_PHASE5_PACKET_OUTPUT")
	if output == "" {
		return
	}
	writePhase5EvidenceFile(t, output, payload)
	t.Logf("wrote packet performance evidence to %s", output)
}
