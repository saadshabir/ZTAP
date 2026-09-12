package cli

import (
	"fmt"

	"ztap/internal/config"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

// App carries per-invocation state (currently the single parsed config).
// NewRootCmd owns one App; PersistentPreRunE parses the config once and the
// subcommands read it via app.Config(). Precedence is flag > env > file > default.
// Commands invoked directly (e.g. in unit tests) without the root
// PersistentPreRunE get a lazy load on first use and must handle the error.
type App struct {
	cfg *config.Config
}

// Config returns the parsed configuration, or an error when loading it fails.
// In the normal CLI path PersistentPreRunE has already loaded and cached the
// config, so this returns the cached value; the lazy path exists for direct
// invocations and surfaces the error to the caller instead of exiting.
func (a *App) Config() (*config.Config, error) {
	if a.cfg == nil {
		cfg, err := config.Load("")
		if err != nil {
			return nil, err
		}
		a.cfg = cfg
	}
	return a.cfg, nil
}

// NewRootCmd builds the ztap root command with every subcommand registered.
// Command construction is explicit (no init() side effects); main calls this
// once and executes the returned command.
func NewRootCmd(version string) *cobra.Command {
	app := &App{}
	Version = version
	clusterStarted := false

	root := &cobra.Command{
		Use:           "ztap",
		Short:         "Zero Trust Access Platform - Microsegmentation for hybrid environments",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `ZTAP enforces zero-trust network policies across on-premises and cloud workloads.
It uses eBPF on Linux and pf on macOS to enforce fine-grained traffic rules.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if commandSkipsConfig(cmd) {
				return nil
			}
			cfg, err := config.Load("")
			if err != nil {
				return err
			}
			app.cfg = cfg

			lcfg := logging.Config{
				Level:  string(cfg.Logging.Level),
				File:   cfg.Logging.File,
				Format: string(cfg.Logging.Format),
			}
			if level, _ := cmd.Flags().GetString("log-level"); level != "" {
				lcfg.Level = level
			}
			if format, _ := cmd.Flags().GetString("log-format"); format != "" {
				lcfg.Format = format
			}
			if file, _ := cmd.Flags().GetString("log-file"); file != "" {
				lcfg.File = file
			}

			if _, err := logging.Configure(lcfg); err != nil {
				return fmt.Errorf("configure logging: %w", err)
			}
			if commandUsesClusterBackend(cmd) {
				if err := startClusterBackendWithConfig(cmd.Context(), cfg, "127.0.0.1:9090"); err != nil {
					return err
				}
				clusterStarted = true
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if clusterStarted {
				stopClusterBackend()
				clusterStarted = false
			}
		},
	}

	root.PersistentFlags().String("log-level", "", "Log level (debug, info, warn, error)")
	root.PersistentFlags().String("log-format", "", "Log format (json, text)")
	root.PersistentFlags().String("log-file", "", "Log output file")

	root.AddCommand(
		newValidateCmd(),
		newAgentCmd(app),
		newAlertCmd(app),
		newApiCmd(app),
		newAuditCmd(app),
		newAwsCmd(app),
		newAzureCmd(app),
		newClusterCmdWithApp(app),
		newComplianceCmd(),
		newDiscoveryCmd(app),
		newEnforceCmd(app),
		newFlowsCmd(),
		newGcpCmd(app),
		newGrpcCmd(app),
		newLogsCmd(app),
		newMetricsCmd(app),
		newPolicyCmd(app),
		newStatusCmd(app),
		newUserCmd(app),
		newVersionCmd(),
	)

	initClusterBackend()

	return root
}
