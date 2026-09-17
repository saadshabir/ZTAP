package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ztap/internal/flow"

	"github.com/spf13/cobra"
)

func newFlowsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "flows",
		Short: "View real-time network flow events",
		Long: `Display real-time network flow events captured by the eBPF enforcer.

	This command requires:
	  - Linux: kernel 5.7+ with eBPF support (best fidelity)
	  - Windows: WFP NetEvents subscription (best effort; requires admin/BFE access)
	  - Active Linux Kubernetes enforcement via 'ztap agent'
	    to see block/allow decisions

Examples:
  ztap flows                    # Show recent flows
  ztap flows --follow           # Stream flows in real-time
  ztap flows --action blocked   # Show only blocked flows
  ztap flows --protocol TCP     # Filter by protocol
  ztap flows --limit 50         # Show last 50 flows`,

		Run: runFlows,
	}
	c.Flags().BoolP("follow", "f", false, "Stream flows in real-time")
	c.Flags().StringP("action", "a", "", "Filter by action (allowed, blocked)")
	c.Flags().StringP("protocol", "p", "", "Filter by protocol (TCP, UDP, ICMP)")
	c.Flags().StringP("direction", "d", "", "Filter by direction (egress, ingress)")
	c.Flags().IntP("limit", "n", 20, "Number of flows to display (0 = unlimited)")
	c.Flags().StringP("output", "o", "table", "Output format (table, json)")
	c.Flags().String("run-dir", "/run/ztap", "Directory containing the flow-reader lock")
	return c
}

func runFlows(cmd *cobra.Command, args []string) {
	follow, _ := cmd.Flags().GetBool("follow")
	action, _ := cmd.Flags().GetString("action")
	protocol, _ := cmd.Flags().GetString("protocol")
	direction, _ := cmd.Flags().GetString("direction")
	limit, _ := cmd.Flags().GetInt("limit")
	output, _ := cmd.Flags().GetString("output")
	runDir, _ := cmd.Flags().GetString("run-dir")

	// Build filter
	filter := flow.FlowFilter{
		Action:    strings.ToLower(action),
		Direction: strings.ToLower(direction),
		Protocol:  strings.ToUpper(protocol),
	}

	// Check platform
	if !isFlowMonitoringAvailable() {
		fmt.Println("Flow monitoring is not available on this platform.")
		fmt.Println("On macOS, flow events are simulated for demonstration.")
		fmt.Println()
	}

	if follow {
		streamFlows(filter, output, runDir)
	} else {
		displayRecentFlows(filter, limit, output)
	}
}

func isFlowMonitoringAvailable() bool {
	// Linux: eBPF ring buffer; Windows: WFP NetEvents subscription.
	return runtime.GOOS == "linux" || runtime.GOOS == "windows" || fileExists("/proc/version")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func streamFlows(filter flow.FlowFilter, output, runDir string) {
	var unlock func() error
	if isFlowMonitoringAvailable() {
		var err error
		unlock, err = acquireFlowReaderLock(runDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting flow monitor: %v\n", err)
			return
		}
		defer func() {
			if err := unlock(); err != nil {
				fmt.Fprintf(os.Stderr, "Error releasing flow reader lock: %v\n", err)
			}
		}()
	}
	fmt.Println("Streaming flow events (Ctrl+C to stop)...")
	fmt.Println()

	// Create context that cancels on interrupt
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping flow monitor...")
		cancel()
	}()

	// Use the pinned engine ring buffer on Linux; the reader itself retains a
	// compatibility fallback when no live agent has published one yet.
	reader := createFlowReader()
	monitor := flow.NewMonitor(reader)

	if err := monitor.Start(ctx); err != nil {
		fmt.Printf("Error starting flow monitor: %v\n", err)
		return
	}
	defer func() { _ = monitor.Stop() }()

	// Subscribe to events
	events := monitor.Subscribe(ctx)

	// Print header for table output
	if output == "table" {
		printFlowHeader()
	}

	// Stream events
	for event := range events {
		if !filter.Matches(event) {
			continue
		}

		switch output {
		case "json":
			printFlowJSON(event)
		default:
			printFlowRow(event)
		}
	}

	// Print final stats
	stats := monitor.GetStats()
	fmt.Println()
	fmt.Printf("Total: %d events (%d allowed, %d blocked) | %.1f events/sec\n",
		stats.TotalEvents, stats.AllowedEvents, stats.BlockedEvents, stats.EventsPerSec)
}

func displayRecentFlows(filter flow.FlowFilter, limit int, output string) {
	// For now, show a message about how to use flow monitoring
	// In a full implementation, this would read from a flow log file
	fmt.Println("Recent flow events:")
	fmt.Println()

	if output == "table" {
		printFlowHeader()
	}

	// Show demo/simulated data when not on Linux
	if !isFlowMonitoringAvailable() {
		demoEvents := generateDemoFlows(limit)
		for _, event := range demoEvents {
			if !filter.Matches(event) {
				continue
			}
			switch output {
			case "json":
				printFlowJSON(event)
			default:
				printFlowRow(event)
			}
		}
		fmt.Println()
		fmt.Println("(Simulated data - run on Linux with eBPF for real flows)")
		return
	}

	fmt.Println("No flow data available. Ensure policies are being enforced with 'ztap agent'.")
	fmt.Println("Use 'ztap flows --follow' to stream real-time events.")
}

func printFlowHeader() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tDIRECTION\tPROTOCOL\tSOURCE\tDESTINATION\tACTION")
	_, _ = fmt.Fprintln(w, "---------\t---------\t--------\t------\t-----------\t------")
	_ = w.Flush()
}

func printFlowRow(event flow.FlowEvent) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	timestamp := event.Timestamp.Format("15:04:05.000")
	src := fmt.Sprintf("%s:%d", event.SourceIP, event.SourcePort)
	dst := fmt.Sprintf("%s:%d", event.DestIP, event.DestPort)

	actionColor := "\033[32m" // green for allowed
	if event.Action == "blocked" {
		actionColor = "\033[31m" // red for blocked
	}
	reset := "\033[0m"

	_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s%s%s\n",
		timestamp, event.Direction, event.Protocol, src, dst,
		actionColor, strings.ToUpper(event.Action), reset)
	_ = w.Flush()
}

func printFlowJSON(event flow.FlowEvent) {
	fmt.Println(formatFlowJSON(event))
}

func formatFlowJSON(event flow.FlowEvent) string {
	return fmt.Sprintf(`{"timestamp":"%s","policy_epoch":%d,"cgroup_id":%d,"direction":"%s","protocol":"%s","src_ip":"%s","src_port":%d,"dst_ip":"%s","dst_port":%d,"action":"%s","reason":"%s","schema_version":%d}`,
		event.Timestamp.Format(time.RFC3339Nano),
		event.PolicyEpoch,
		event.CgroupID,
		event.Direction,
		event.Protocol,
		event.SourceIP,
		event.SourcePort,
		event.DestIP,
		event.DestPort,
		event.Action,
		event.Reason,
		event.SchemaVersion)
}

func generateDemoFlows(limit int) []flow.FlowEvent {
	if limit == 0 {
		limit = 10
	}

	events := []flow.FlowEvent{
		{
			Timestamp:  time.Now().Add(-5 * time.Second),
			SourceIP:   []byte{10, 0, 1, 1},
			DestIP:     []byte{10, 0, 2, 1},
			SourcePort: 45678,
			DestPort:   5432,
			Protocol:   "TCP",
			Direction:  "egress",
			Action:     "allowed",
		},
		{
			Timestamp:  time.Now().Add(-4 * time.Second),
			SourceIP:   []byte{192, 168, 1, 100},
			DestIP:     []byte{10, 0, 1, 1},
			SourcePort: 52341,
			DestPort:   443,
			Protocol:   "TCP",
			Direction:  "ingress",
			Action:     "allowed",
		},
		{
			Timestamp:  time.Now().Add(-3 * time.Second),
			SourceIP:   []byte{10, 0, 1, 1},
			DestIP:     []byte{8, 8, 8, 8},
			SourcePort: 54321,
			DestPort:   53,
			Protocol:   "UDP",
			Direction:  "egress",
			Action:     "blocked",
		},
		{
			Timestamp:  time.Now().Add(-2 * time.Second),
			SourceIP:   []byte{172, 16, 0, 50},
			DestIP:     []byte{10, 0, 1, 1},
			SourcePort: 22345,
			DestPort:   22,
			Protocol:   "TCP",
			Direction:  "ingress",
			Action:     "blocked",
		},
		{
			Timestamp:  time.Now().Add(-1 * time.Second),
			SourceIP:   []byte{10, 0, 1, 1},
			DestIP:     []byte{10, 0, 3, 1},
			SourcePort: 38901,
			DestPort:   6379,
			Protocol:   "TCP",
			Direction:  "egress",
			Action:     "allowed",
		},
	}

	if limit < len(events) {
		return events[:limit]
	}
	return events
}
func generateRawDemoFlows() []flow.RawFlowEvent {
	return []flow.RawFlowEvent{
		{
			TimestampNs: unixNanoUint64(),
			SrcIP:       [4]uint32{0x0A000101}, // 10.0.1.1
			DestIP:      [4]uint32{0x0A000201}, // 10.0.2.1
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    6, // TCP
			Direction:   0, // egress
			Action:      1, // allowed
			Family:      4,
		},
		{
			TimestampNs: unixNanoUint64(),
			SrcIP:       [4]uint32{0xC0A86464}, // 192.168.100.100
			DestIP:      [4]uint32{0x0A000101}, // 10.0.1.1
			SrcPort:     52341,
			DestPort:    443,
			Protocol:    6,
			Direction:   1, // ingress
			Action:      1,
			Family:      4,
		},
		{
			TimestampNs: unixNanoUint64(),
			SrcIP:       [4]uint32{0x0A000101},
			DestIP:      [4]uint32{0x08080808}, // 8.8.8.8
			SrcPort:     54321,
			DestPort:    53,
			Protocol:    17, // UDP
			Direction:   0,
			Action:      0, // blocked
			Family:      4,
		},
	}
}

func unixNanoUint64() uint64 {
	ns := time.Now().UnixNano()
	if ns < 0 {
		return 0
	}
	return uint64(ns)
}
