//go:build !linux

package cli

import "errors"

func checkNodePreflight(r *preflightReport, _, _ string) {
	r.check("Linux node", errors.New("run this check on each target Linux node"))
}
