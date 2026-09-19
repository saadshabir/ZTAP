package cli

import (
	"context"
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
	return streamFlows(cmd.Context(), filter, output, runDir)
}

func streamFlows(parent context.Context, filter flow.FlowFilter, output, runDir string) (returnErr error) {
	if parent == nil {
		return errors.New("flow stream context is nil")
	}
	if runtime.GOOS != "linux" {
		return errors.New("real flow streaming is supported only on Linux")
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
	reader, err := openStreamingFlowReader()
	if err != nil {
		return fmt.Errorf("open live flow stream: %w", err)
	}
	monitor := flow.NewMonitor(reader)
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		_ = monitor.Stop()
		return fmt.Errorf("start live flow stream: %w", err)
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
