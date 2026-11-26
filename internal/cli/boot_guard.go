package cli

import "github.com/spf13/cobra"

func newBootGuardCmd() *cobra.Command {
	var cgroupRoot, bpffsRoot, runDir, kubeletUnit string
	var checkKubelet bool
	cmd := &cobra.Command{
		Use:   "boot-guard",
		Short: "Install the node guard before Kubernetes workload startup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := verifyBootGuardKubelet(cmd.Context(), kubeletUnit); err != nil {
				return err
			}
			if checkKubelet {
				return nil
			}
			return installNodeBootGuard(cmd.Context(), cgroupRoot, bpffsRoot, runDir)
		},
	}
	cmd.Flags().StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "Mounted cgroup v2 root")
	cmd.Flags().StringVar(&bpffsRoot, "bpffs-root", "/sys/fs/bpf", "Mounted bpffs root")
	cmd.Flags().StringVar(&runDir, "run-dir", "/run/ztap", "Protected node lock directory")
	cmd.Flags().StringVar(&kubeletUnit, "kubelet-unit", "kubelet.service", "Host systemd unit that starts kubelet")
	cmd.Flags().BoolVar(&checkKubelet, "check-kubelet", false, "Verify kubelet's startup arguments without installing a guard")
	return cmd
}
