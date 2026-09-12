package main

import (
	"fmt"
	"os"

	"ztap/internal/cli"
)

// Version is set at build time via -ldflags "-X main.Version=<value>".
var Version = "dev"

func main() {
	if err := cli.NewRootCmd(Version).Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
