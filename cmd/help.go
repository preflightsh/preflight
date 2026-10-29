package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// helpCmd replaces cobra's help command (SetHelpCommand, not AddCommand,
// which listed help twice). With no argument it prints the overview below;
// `preflight help scan` prints that command's own help, as cobra's does.
var helpCmd = &cobra.Command{
	Use:   "help [command]",
	Short: "Show help and examples",
	Long:  "Display detailed help information with examples for all commands.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			target, _, err := cmd.Root().Find(args)
			if err != nil || target == nil || target == cmd.Root() {
				return &ExitError{Code: ExitUsage, Err: fmt.Errorf("unknown help topic %q (run 'preflight help' to list commands)", args[0])}
			}
			return target.Help()
		}
		fmt.Fprint(cmd.OutOrStdout(), helpPage)
		return nil
	},
}

const helpPage = `
Preflight CLI - Launch readiness checker for your codebase

USAGE:
  preflight <command> [flags]

COMMANDS:
  init          Initialize preflight configuration for your project
  scan          Run all enabled checks and report results
  ignore        Add a check to the ignore list
  unignore      Remove a check from the ignore list
  checks        List all available check IDs
  auth          Log in to, log out of, or check your Preflight dashboard account
  history       View previous scan results from your Preflight dashboard
  completion    Generate a shell completion script
  version       Show version information
  help          Show this help message, or 'help <command>' for one command

EXAMPLES:

  Initialize a new project:
    $ preflight init

  Run all checks:
    $ preflight scan

  Run in CI mode with JSON output:
    $ preflight scan --ci --format json

  Silence a specific check:
    $ preflight ignore sitemap
    $ preflight ignore llms_txt
    $ preflight ignore debug_statements

  Re-enable a silenced check:
    $ preflight unignore sitemap

  List all check IDs:
    $ preflight checks

  Publish a scan to your dashboard and list past runs:
    $ preflight auth login
    $ preflight scan --publish
    $ preflight history

  Enable shell completion (bash, zsh, fish, or powershell):
    $ preflight completion zsh --help

EXIT CODES:
  0    All checks passed
  1    Warnings only
  2    Errors found
  64   Preflight could not run (bad path, unreadable config, unknown ID)
  130  Scan cancelled (Ctrl-C)

CONFIGURATION:
  Preflight uses a preflight.yml file in your project root.
  Run 'preflight init' to generate one automatically.

  To silence checks via config, add an ignore list:
    ignore:
      - sitemap
      - llms_txt

DOCUMENTATION:
  https://github.com/preflightsh/preflight
`

func init() {
	rootCmd.SetHelpCommand(helpCmd)
}
