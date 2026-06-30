// aspex-doctor - fast local health check for your AI agent setup.
// This command is now available as: aspex-scan doctor
package main

import (
	"fmt"
	"os"

	"github.com/aspex-security/aspex/internal/doctor"
	"github.com/aspex-security/aspex/internal/version"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var jsonMode bool
	var noColor bool

	cmd := &cobra.Command{
		Use:     "aspex-doctor",
		Short:   "Fast local health check for your AI agent setup",
		Version: version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("NO_COLOR") != "" {
				noColor = true
			}
			if !jsonMode {
				fmt.Fprintf(os.Stderr, "\033[2mNote: aspex-doctor is now aspex-scan doctor\033[0m\n\n")
			}
			return doctor.Run(jsonMode, noColor)
		},
	}

	cmd.Flags().BoolVar(&jsonMode, "json", false, "Output results as JSON")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")

	return cmd
}
