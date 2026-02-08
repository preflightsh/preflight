package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Show help and examples",
	Long:  "Display detailed help information with examples for all commands.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(`
Preflight CLI - Launch readiness checker for your codebase

USAGE:
  preflight <command> [flags]

COMMANDS:
  init          Initialize preflight configuration for your project
  scan          Run all enabled checks and report results
  ignore        Add a check to the ignore list
  unignore      Remove a check from the ignore list
  checks        List all available check IDs
  version       Show version information
  help          Show this help message

EXAMPLES:

  Initialize a new project:
    $ preflight init

  Run all checks:
    $ preflight scan

  Run in CI mode with JSON output:
    $ preflight scan --ci --format json

  Silence a specific check:
    $ preflight ignore sitemap
    $ preflight ignore llmsTxt
    $ preflight ignore debug_statements

  Re-enable a silenced check:
    $ preflight unignore sitemap

  List all check IDs:
    $ preflight checks

EXIT CODES:
  0  All checks passed
  1  Warnings only
  2  Errors found

CONFIGURATION:
  Preflight uses a preflight.yml file in your project root.
  Run 'preflight init' to generate one automatically.

  To silence checks via config, add an ignore list:
    ignore:
      - sitemap
      - llmsTxt

DOCUMENTATION:
  https://github.com/preflightsh/preflight
`)
	},
}

func init() {
	rootCmd.AddCommand(helpCmd)
}
