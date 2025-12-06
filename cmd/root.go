package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Preflight CLI - Launch readiness checker for your codebase",
	Long: `Preflight CLI scans your codebase and configuration for launch readiness.
It identifies missing configuration, integration issues, security concerns,
SEO metadata gaps, and other common mistakes that affect production deploys.`,
	Version: version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetVersionTemplate("preflight version {{.Version}}\n")
}

func exitWithError(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
