package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// newAgentCmd starts the node-local Kubernetes reconciler. The reconciler is
// deliberately the only production path from Kubernetes objects to the
// instance-owned enforcement engine.
func newAgentCmd() *cobra.Command {
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
			kubeconfig, err := cmd.Flags().GetString("kubeconfig")
			if err != nil {
				return err
			}
			cgroupRoot, err := cmd.Flags().GetString("cgroup-root")
			if err != nil {
				return err
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
