package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// BuildVersion and buildCommit are set by the build's linker flags.
var (
	BuildVersion = "dev"
	buildCommit  = "unknown"
)

func newVersionCmd(version string) *cobra.Command {
	if version == "" {
		version = "dev"
	}
	c := &cobra.Command{
		Use:   "version",
		Short: "Print ZTAP version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "version=%s go=%s os=%s arch=%s commit=%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH, versionCommit())
			return err
		},
	}
	return c
}

func versionCommit() string {
	if buildCommit != "unknown" {
		return buildCommit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return buildCommit
}
