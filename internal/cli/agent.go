package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ztap/internal/logging"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// newAgentCmd starts the node-local Kubernetes reconciler. The reconciler is
// deliberately the only production path from Kubernetes objects to the
// instance-owned enforcement engine; legacy ConfigMap/discovery enforcement
// is kept available to older commands but is not used by `ztap agent`.
func newAgentCmd(_ *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "agent",
		Short: "Run ZTAP node agent for Kubernetes enforcement",
		RunE: func(cmd *cobra.Command, _ []string) error {
			nodeName, err := cmd.Flags().GetString("node-name")
			if err != nil {
				return err
			}
			nodeName = strings.TrimSpace(nodeName)
			if nodeName == "" {
				return errors.New("--node-name is required")
			}
			if _, err := configureNativeAgentLogging(cmd); err != nil {
				return err
			}
			kubeconfig, err := cmd.Flags().GetString("kubeconfig")
			if err != nil {
				return err
			}
			cgroupRoot, err := cmd.Flags().GetString("cgroup-root")
			if err != nil {
				return err
			}
			legacyCgroup, err := cmd.Flags().GetString("cgroup")
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cgroup") && !cmd.Flags().Changed("cgroup-root") {
				cgroupRoot = legacyCgroup
			}
			bpffsRoot, err := cmd.Flags().GetString("bpffs-root")
			if err != nil {
				return err
			}
			runDir, err := cmd.Flags().GetString("run-dir")
			if err != nil {
				return err
			}
			listen, err := cmd.Flags().GetString("listen")
			if err != nil {
				return err
			}
			dryRun, err := cmd.Flags().GetBool("dry-run")
			if err != nil {
				return err
			}

			config, err := loadAgentConfig(kubeconfig)
			if err != nil {
				return fmt.Errorf("load kubernetes config: %w", err)
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return fmt.Errorf("create kubernetes client: %w", err)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runNativeKubernetesAgent(ctx, clientset, NativeAgentOptions{
				NodeName:   nodeName,
				Kubeconfig: kubeconfig,
				CgroupRoot: cgroupRoot,
				BPFFSRoot:  bpffsRoot,
				RunDir:     runDir,
				Listen:     listen,
				DryRun:     dryRun,
			})
		},
	}
	c.Flags().String("node-name", "", "Kubernetes node name to reconcile (required)")
	c.Flags().String("kubeconfig", "", "Path to kubeconfig; empty uses in-cluster credentials")
	c.Flags().String("cgroup-root", "/sys/fs/cgroup", "Mounted cgroup v2 root used for subject attachment")
	c.Flags().String("cgroup", "", "Deprecated alias for --cgroup-root")
	c.Flags().String("bpffs-root", "/sys/fs/bpf", "Mounted bpffs root used for stable engine maps")
	c.Flags().String("run-dir", "/run/ztap", "Directory containing the node-agent lock")
	c.Flags().String("listen", ":9090", "Local health, readiness, and metrics listen address")
	c.Flags().Bool("dry-run", false, "Compile snapshots without loading or attaching eBPF")
	return c
}

func loadAgentConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig = strings.TrimSpace(kubeconfig); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// The root command skips the retired file-based configuration path for agent.
// Keep its process logging independent while honoring the inherited log flags.
func configureNativeAgentLogging(cmd *cobra.Command) (*logging.Logger, error) {
	if cmd == nil {
		return nil, errors.New("agent command is nil")
	}
	config := logging.DefaultConfig()
	if level, _ := cmd.Flags().GetString("log-level"); level != "" {
		config.Level = level
	}
	if format, _ := cmd.Flags().GetString("log-format"); format != "" {
		config.Format = format
	}
	if file, _ := cmd.Flags().GetString("log-file"); file != "" {
		config.File = file
	}
	logger, err := logging.Configure(config)
	if err != nil {
		return nil, fmt.Errorf("configure native agent logging: %w", err)
	}
	if strings.TrimSpace(config.File) == "" {
		logger.SetOutput(os.Stderr)
	}
	return logger, nil
}
