package cli

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
)

func newNodeInitCmd() *cobra.Command {
	var node, root, runDir, kubeconfig string
	var stay bool
	c := &cobra.Command{Use: "node-init", Short: "Prepare authenticated node bootstrap for the workload guard", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if node == "" {
				return errors.New("--node-name is required")
			}
			config, err := loadAgentConfig(kubeconfig)
			if err != nil {
				return err
			}
			client, err := coreclient.NewForConfig(config)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := initializeNodeBootstrap(ctx, &nativeClients{core: client}, config, node, root, runDir); err != nil {
				return err
			}
			if stay {
				<-ctx.Done()
			}
			return nil
		},
	}
	c.Flags().StringVar(&node, "node-name", "", "Kubernetes node name (required)")
	c.Flags().StringVar(&root, "cgroup-root", "/sys/fs/cgroup", "Mounted cgroup v2 root")
	c.Flags().StringVar(&runDir, "run-dir", "/run/ztap", "Protected node bootstrap directory")
	c.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Kubeconfig; empty uses in-cluster credentials")
	c.Flags().BoolVar(&stay, "stay", false, "Remain running after publishing bootstrap state")
	return c
}
