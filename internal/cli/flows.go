package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"

	"github.com/spf13/cobra"
)

func newFlowsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "flows",
		Short: "Stream live network flow events",
		Long: `Stream live network flow events captured by the node-local eBPF agent.

	This command requires:
	  - Linux with eBPF support
	  - An active Linux Kubernetes agent started with 'ztap agent'
	  - Permission to read the agent's pinned flow map

Examples:
	  ztap flows                    # Stream all live flows
	  ztap flows --action blocked   # Show only blocked flows
	  ztap flows --protocol TCP     # Filter by protocol
	  ztap flows --direction egress # Filter by direction`,

		Args: cobra.NoArgs,
		RunE: runFlows,
	}
	c.Flags().String("action", "", "Filter by action (allowed, blocked)")
	c.Flags().String("protocol", "", "Filter by protocol (TCP, UDP)")
	c.Flags().String("direction", "", "Filter by direction (egress, ingress)")
	c.Flags().String("output", "table", "Output format (table, json)")
	c.Flags().String("run-dir", "/run/ztap", "Directory containing the flow-reader lock")
	c.Flags().String("bpffs-root", "/sys/fs/bpf", "Mounted bpffs root containing the agent's pinned maps")
	return c
}

func runFlows(cmd *cobra.Command, _ []string) error {
	if cmd == nil {
		return errors.New("flows command is nil")
	}
	action, _ := cmd.Flags().GetString("action")
	protocol, _ := cmd.Flags().GetString("protocol")
	direction, _ := cmd.Flags().GetString("direction")
	output, _ := cmd.Flags().GetString("output")
	runDir, _ := cmd.Flags().GetString("run-dir")
	bpffsRoot, _ := cmd.Flags().GetString("bpffs-root")

	action = strings.ToLower(strings.TrimSpace(action))
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	direction = strings.ToLower(strings.TrimSpace(direction))
	output = strings.ToLower(strings.TrimSpace(output))
	if action != "" && action != "allowed" && action != "blocked" {
		return fmt.Errorf("invalid --action %q: want allowed or blocked", action)
	}
	if protocol != "" && protocol != "TCP" && protocol != "UDP" {
		return fmt.Errorf("invalid --protocol %q: want TCP or UDP", protocol)
	}
	if direction != "" && direction != "egress" && direction != "ingress" {
		return fmt.Errorf("invalid --direction %q: want egress or ingress", direction)
	}
	if output != "table" && output != "json" {
		return fmt.Errorf("invalid --output %q: want table or json", output)
	}

	filter := flow.FlowFilter{
		Action:    action,
		Direction: direction,
		Protocol:  protocol,
	}
	return streamFlows(cmd.Context(), filter, output, runDir, bpffsRoot)
}

func streamFlows(parent context.Context, filter flow.FlowFilter, output, runDir, bpffsRoot string) (returnErr error) {
	if parent == nil {
		return errors.New("flow stream context is nil")
	}
	if runtime.GOOS != "linux" {
		return errors.New("real flow streaming is supported only on Linux")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	unlock, err := acquireFlowReaderLock(runDir)
	if err != nil {
		return fmt.Errorf("acquire flow reader lock: %w", err)
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("release flow reader lock: %w", unlockErr)
		}
	}()

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	reader, err := openStreamingFlowReader(bpffsRoot)
	if err != nil {
		return fmt.Errorf("open live flow stream: %w", err)
	}
	monitor, events, err := startStreamingFlowMonitor(ctx, reader)
	if err != nil {
		return err
	}
	defer func() {
		if stopErr := monitor.Stop(); stopErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("stop live flow stream: %w", stopErr)
		}
	}()

	if output == "table" {
		printFlowHeader()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-events:
			if !ok {
				if streamErr := monitor.Err(); streamErr != nil {
					return fmt.Errorf("live flow stream stopped: %w", streamErr)
				}
				return nil
			}
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
	}
}

// startStreamingFlowMonitor transfers the opened reader into the monitor only
// after startup succeeds. A cancellation or availability failure during the
// monitor handoff must still release the reader-owned pinned map handles.
func startStreamingFlowMonitor(ctx context.Context, reader flow.FlowReader) (*flow.Monitor, <-chan flow.FlowEvent, error) {
	if reader == nil {
		return nil, nil, errors.New("live flow reader is nil")
	}
	monitor := flow.NewMonitor(reader)
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		startErr := fmt.Errorf("start live flow stream: %w", err)
		// Start can fail before the monitor owns a running reader. Close the
		// monitor's pre-start subscriber and release the already-opened reader
		// explicitly so a canceled startup cannot leak pinned map handles.
		cleanupErr := errors.Join(monitor.Stop(), reader.Stop())
		if cleanupErr != nil {
			return nil, nil, errors.Join(startErr, fmt.Errorf("close live flow reader: %w", cleanupErr))
		}
		return nil, nil, startErr
	}
	return monitor, events, nil
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
	payload := struct {
		Timestamp     string `json:"timestamp"`
		PolicyEpoch   uint64 `json:"policy_epoch"`
		CgroupID      uint64 `json:"cgroup_id"`
		Direction     string `json:"direction"`
		Protocol      string `json:"protocol"`
		SourceIP      string `json:"src_ip"`
		SourcePort    uint16 `json:"src_port"`
		DestIP        string `json:"dst_ip"`
		DestPort      uint16 `json:"dst_port"`
		Action        string `json:"action"`
		Reason        string `json:"reason"`
		SchemaVersion uint8  `json:"schema_version"`
	}{
		Timestamp:     event.Timestamp.Format(time.RFC3339Nano),
		PolicyEpoch:   event.PolicyEpoch,
		CgroupID:      event.CgroupID,
		Direction:     event.Direction,
		Protocol:      event.Protocol,
		SourceIP:      event.SourceIP.String(),
		SourcePort:    event.SourcePort,
		DestIP:        event.DestIP.String(),
		DestPort:      event.DestPort,
		Action:        event.Action,
		Reason:        event.Reason,
		SchemaVersion: event.SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		// The payload contains only JSON-supported scalar values. Keep the
		// existing no-error formatter contract while making any future schema
		// change fail loudly instead of emitting an invalid transcript.
		panic(fmt.Sprintf("encode flow event JSON: %v", err))
	}
	return string(encoded)
}
