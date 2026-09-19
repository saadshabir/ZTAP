package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/saadshabir/ZTAP/internal/policy"

	"github.com/spf13/cobra"
)

// newValidateCmd implements the standalone offline validation command from
// the streamlined product contract. It deliberately does not load runtime
// configuration or initialize cluster services.
func newValidateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate native Kubernetes NetworkPolicy documents",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return &ExitError{Status: 2, Err: err}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := cmd.Flags().GetString("file")
			if err != nil {
				return &ExitError{Status: 2, Err: err}
			}
			if path == "" {
				return &ExitError{Status: 2, Err: errors.New("required flag --file is missing")}
			}

			var data []byte
			if path == "-" {
				data, err = io.ReadAll(cmd.InOrStdin())
			} else {
				data, err = os.ReadFile(path) // #nosec G304 -- --file intentionally selects the user-provided validation input.
			}
			if err != nil {
				return &ExitError{Status: 2, Err: fmt.Errorf("read policy input: %w", err)}
			}

			policies, err := policy.LoadNativePoliciesFromBytes(data)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "valid: %d NetworkPolicy object(s)\n", len(policies)); err != nil {
				return fmt.Errorf("write validation result: %w", err)
			}
			for _, item := range policies {
				namespace := "default"
				name := ""
				if item.Metadata != nil {
					name = item.Metadata.Name
					if item.Metadata.Namespace != "" {
						namespace = item.Metadata.Namespace
					}
				}
				if _, err := fmt.Fprintf(out, "- %s/%s\n", namespace, name); err != nil {
					return fmt.Errorf("write validation result: %w", err)
				}
			}
			return nil
		},
	}
	c.Flags().StringP("file", "f", "", "Path to a YAML file, or - for stdin")
	c.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &ExitError{Status: 2, Err: err}
	})
	return c
}
