package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version is the human-readable build version.
//
// It is set by main at startup. Release builds also inject main.Version via ldflags.
var Version = "dev"

var (
	Commit    = "unknown"
	BuildDate = "unknown"
)

// SetBuildInfo installs values supplied by release-build linker flags.
func SetBuildInfo(version, commit, buildDate string) {
	Version = version
	Commit = commit
	BuildDate = buildDate
}

func newVersionCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "Print ZTAP version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			v := Version
			if v == "" {
				v = "dev"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "version=%s commit=%s build_date=%s go=%s os=%s arch=%s\n", v, Commit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
	return c
}
