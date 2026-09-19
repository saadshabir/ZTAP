package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// primaryUsageTemplate keeps Cobra's support commands callable without
// presenting them as part of ZTAP's four-command product surface. Cobra's
// default template special-cases a command named "help" and lists it even
// when Hidden is true.
const primaryUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) .IsAvailableCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") .IsAvailableCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

// NewRootCmd builds the focused ZTAP command surface. Command construction is
// explicit (no init side effects); main calls this once and executes it.
func NewRootCmd(version string) *cobra.Command {
	Version = version

	root := &cobra.Command{
		Use:           "ztap",
		Short:         "Linux eBPF enforcement for Kubernetes NetworkPolicy",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `ZTAP watches native Kubernetes NetworkPolicy resources on a Linux node,
compiles the supported subset, and enforces it with per-container eBPF programs.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return configureLogging(cmd)
		},
	}
	root.CompletionOptions.HiddenDefaultCmd = true
	root.SetUsageTemplate(primaryUsageTemplate)

	root.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	root.PersistentFlags().String("log-format", "json", "Log format (json, text)")
	root.AddCommand(
		newAgentCmd(),
		newValidateCmd(),
		newFlowsCmd(),
		newVersionCmd(),
	)
	root.InitDefaultHelpCmd()
	for _, command := range root.Commands() {
		if command.Name() == "help" {
			// Keep Cobra's built-in help behavior and familiar command name, but
			// omit it from the product command list via primaryUsageTemplate.
			command.Hidden = true
			break
		}
	}
	return root
}

func configureLogging(cmd *cobra.Command) error {
	if cmd == nil {
		return errors.New("logging command is nil")
	}
	levelName, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return err
	}
	format, err := cmd.Flags().GetString("log-format")
	if err != nil {
		return err
	}
	level, err := parseLogLevel(levelName)
	if err != nil {
		return err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "json" && format != "text" {
		return fmt.Errorf("invalid log format %q: want json or text", format)
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: want debug, info, warn, or error", value)
	}
}
