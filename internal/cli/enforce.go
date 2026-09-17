package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ztap/internal/enforcer"
	"ztap/internal/logging"
	"ztap/internal/policy"

	"github.com/spf13/cobra"
)

func newEnforceCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "enforce -f policy.yaml",
		Short: "Enforce zero-trust network policies",
		Run: func(cmd *cobra.Command, args []string) {
			if enforcer.IsLinux() {
				logging.Fatalf("%v", enforcer.ErrLegacyLinuxEnforcementRetired)
				return
			}
			central, err := app.Config()
			if err != nil {
				logging.Fatalf("Failed to load config: %v", err)
			}
			policyFile, _ := cmd.Flags().GetString("file")

			// Flags take precedence over config (flag > env > config > default).
			dryRun := central.Enforcement.DryRun
			if cmd.Flags().Changed("dry-run") {
				dryRun, _ = cmd.Flags().GetBool("dry-run")
			}
			resolveLabels := central.Policy.ResolveLabels
			if cmd.Flags().Changed("resolve-labels") {
				resolveLabels, _ = cmd.Flags().GetBool("resolve-labels")
			}
			resolveLabelsInterval, _ := cmd.Flags().GetDuration("resolve-labels-interval")

			defaultAction := strings.ToLower(strings.TrimSpace(string(central.Enforcement.DefaultAction)))
			if cmd.Flags().Changed("default-action") {
				defaultAction, _ = cmd.Flags().GetString("default-action")
				defaultAction = strings.ToLower(strings.TrimSpace(defaultAction))
			}
			if defaultAction == "" {
				defaultAction = "block"
			}
			if defaultAction != "block" && defaultAction != "allow" {
				logging.Fatalf("invalid --default-action %q (expected block or allow)", defaultAction)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			basePolicies, err := policy.LoadFromFile(policyFile)
			if err != nil {
				logging.Fatalf("Failed to load policy: %v", err)
			}

			needsResolution := policiesNeedTargetResolution(basePolicies)
			if needsResolution {
				resolveLabels = true
			}

			var disc policy.ServiceDiscovery
			if resolveLabels {
				disc, err = getDiscoveryBackend(central)
				if err != nil {
					logging.Fatalf("Failed to load discovery backend for label resolution: %v", err)
				}
				if starter, ok := disc.(interface{ Start(context.Context) error }); ok {
					if err := starter.Start(ctx); err != nil {
						logging.Fatalf("Failed to start discovery backend: %v", err)
					}
				}
				defer func() {
					if disc == nil {
						return
					}
					if err := disc.Stop(); err != nil {
						logging.Warnf("failed to stop discovery backend: %v", err)
					}
				}()
			}

			policies := basePolicies
			if resolveLabels {
				resolver := policy.NewPolicyResolver(disc)
				enforcer.WarnNoMatchPolicyTargets(disc, enforcer.SelectorRefreshOptions{}, basePolicies)
				resolved, err := resolver.ResolvePodSelectorsToIPBlocks(basePolicies)
				if err != nil {
					logging.Fatalf("Failed to resolve pod selectors: %v", err)
				}
				policies = resolved
				if needsResolution {
					switch {
					case dryRun:
						fmt.Printf("Resolved label selectors (dry-run; no ongoing re-resolution)\n")
					case resolveLabelsInterval <= 0:
						fmt.Printf("Resolved label selectors (refresh disabled; set --resolve-labels-interval to enable)\n")
					default:
						fmt.Printf("Resolved label selectors and will keep them updated while enforcement is active\n")
					}
				}
			}
			normalized, err := policy.NormalizePolicies(policies)
			if err != nil {
				logging.Fatalf("Failed to normalize ipBlocks: %v", err)
			}
			policies = normalized

			policyName := filepath.Base(policyFile)
			named := make([]policy.NamedPolicy, 0, len(basePolicies))
			for _, p := range basePolicies {
				if err := p.ValidateWithOptions(policy.ValidateOptions{AllowEmptyEgress: central.Policy.AllowEmptyEgress}); err != nil {
					logging.Fatalf("Invalid policy: %v", err)
				}
				named = append(named, policy.NamedPolicy{PolicyName: policyName, Policy: p})
			}
			for i, np := range named {
				if err := policy.CheckConflicts(named[:i], np); err != nil {
					logging.Fatalf("Policy conflict: %v", err)
				}
			}

			fmt.Printf("Loaded %d policy(ies) from %s\n", len(policies), policyFile)

			if enforcer.IsWindows() {
				fmt.Println("Enforcing via WFP (Windows)...")
				opts := enforcer.EnforcementOptions{Policies: policies, DryRun: dryRun, DefaultAction: defaultAction, Context: ctx}
				if err := enforcer.EnforceWithWFP(opts); err != nil {
					logging.Fatalf("Failed to enforce via WFP: %v", err)
				}

				if dryRun {
					fmt.Println("Dry-run complete. No changes were applied.")
					return
				}

				// Anomaly detection (Phase E): advisory, batched pipeline over
				// flow events while enforcement is active.
				var anomalyR *anomalyRunner
				if central.Anomaly.Enabled {
					anomalyR, err = startAnomalyRunner(ctx, central, nil)
					if err != nil {
						logging.Warnf("anomaly detection disabled: %v", err)
					}
				}

				var wg sync.WaitGroup
				if needsResolution && resolveLabelsInterval > 0 {
					wg.Go(func() {
						enforcer.RunSelectorRefresh(ctx, disc, basePolicies, enforcer.SelectorRefreshOptions{PollInterval: resolveLabelsInterval}, func(next []policy.NetworkPolicy) error {
							nextOpts := opts
							nextOpts.Policies = next
							return enforcer.EnforceWithWFP(nextOpts)
						})
					})
				}

				fmt.Println("Enforcement active. Press Ctrl+C to stop.")
				sigCh := make(chan os.Signal, 1)
				notifyStopSignals(sigCh)
				<-sigCh
				stopStopSignals(sigCh)
				cancel()
				wg.Wait()
				if anomalyR != nil {
					anomalyR.Stop()
				}
				if err := enforcer.StopWFPEnforcement(); err != nil {
					logging.Warnf("failed to stop WFP enforcement cleanly: %v", err)
				}
				fmt.Println("Enforcement stopped.")
				return
			}

			fmt.Println("Enforcing via pf (macOS)...")
			opts := enforcer.EnforcementOptions{Policies: policies, DryRun: dryRun, DefaultAction: defaultAction, Context: ctx}
			if err := enforcer.EnforceWithPF(opts); err != nil {
				logging.Fatalf("Failed to enforce via pf: %v", err)
			}
			if dryRun {
				fmt.Println("Dry-run complete. No rules were loaded into pf.")
			}
			fmt.Println("Enforcement complete.")
		},
	}
	c.Flags().StringP("file", "f", "policy.yaml", "Path to policy YAML file")
	c.Flags().String("cgroup", "", "Cgroup v2 path for eBPF attachment (Linux only)")
	c.Flags().StringSlice("self-ip", nil, "IPv4 workload address allowed as explicit self traffic (Linux only)")
	c.Flags().String("bpf-object", "", "Optional path to compiled eBPF object file (overrides embedded bytecode; Linux only)")
	c.Flags().Bool("debug-ebpf", false, "Enable debug logging for eBPF object loading (Linux only)")
	c.Flags().Bool("resolve-labels", false, "Resolve pod selectors to IP blocks using configured discovery backend (auto-enabled when policies use podSelector targets)")
	c.Flags().Duration("resolve-labels-interval", 5*time.Second, "Re-resolve label selectors at this interval while enforcement is active (0 disables refresh)")
	c.Flags().Bool("dry-run", false, "Simulate enforcement without making system changes")
	c.Flags().String("default-action", "", "Default action for traffic not matching any policy (block or allow; enforcement.default_action)")
	return c
}

func policiesNeedTargetResolution(policies []policy.NetworkPolicy) bool {
	return policy.NeedsTargetResolution(policies)
}
