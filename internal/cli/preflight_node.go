package cli

import "github.com/spf13/cobra"

func newNodePreflightCmd() *cobra.Command {
	var cgroupRoot, bpffsRoot string
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Probe Linux kernel, cgroup layout, and eBPF permissions on this node",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := preflightReport{out: cmd.OutOrStdout()}
			checkNodePreflight(&r, cgroupRoot, bpffsRoot)
			return r.result()
		},
	}
	cmd.Flags().StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "Mounted host cgroup v2 root")
	cmd.Flags().StringVar(&bpffsRoot, "bpffs-root", "/sys/fs/bpf", "Mounted host bpffs root")
	return cmd
}
