package main

import (
	"fmt"
	"os"

	"github.com/saadshabir/ZTAP/internal/cli"
)

// Build metadata is set at build time via linker flags.
var Version = "dev"
var Commit = "unknown"
var BuildDate = "unknown"

func main() {
	cli.SetBuildInfo(Version, Commit, BuildDate)
	if err := cli.NewRootCmd(Version).Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
