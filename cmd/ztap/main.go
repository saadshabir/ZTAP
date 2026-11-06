package main

import (
	"fmt"
	"os"

	"github.com/saadshabir/ZTAP/internal/cli"
)

func main() {
	if err := cli.NewRootCmd(cli.BuildVersion).Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
