package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/spf13/cobra"
)

var (
	historyLimit  int
	historyFormat string
	historyHere   bool
)

var historyCmd = &cobra.Command{
	Use:   "history [run-id]",
	Short: "View previous scan results from your Preflight dashboard",
	Long: `View previous Preflight scans published to your dashboard with --publish.

Without an argument it lists recent runs. Pass a run id to see that run's full
check results. Use --format json for agent-readable output, and --here to limit
the list to the project in the current directory.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runHistory,
}

func init() {
	historyCmd.Flags().IntVar(&historyLimit, "limit", 20, "Maximum number of runs to list")
	historyCmd.Flags().StringVar(&historyFormat, "format", "human", "Output format: human or json")
	historyCmd.Flags().BoolVar(&historyHere, "here", false, "Only list runs for the project in the current directory")
	rootCmd.AddCommand(historyCmd)
}

func runHistory(cmd *cobra.Command, args []string) error {
	if historyFormat != "human" && historyFormat != "json" {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("invalid --format %q (want human or json)", historyFormat)}
	}

	creds, err := dashboard.LoadCredentials()
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	if creds == nil || creds.Token == "" {
		return &ExitError{Code: 1, Err: fmt.Errorf("not logged in; run 'preflight auth login' to view your dashboard history")}
	}
	client, warning := dashboard.ClientForCredentials(creds)
	if warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}

	if len(args) == 1 {
		return showRun(client, creds.Token, args[0])
	}
	return listHistory(client, creds.Token)
}

// listHistory prints recent runs, optionally scoped to the current project.
func listHistory(client *dashboard.Client, token string) error {
	projectKey := ""
	if historyHere {
		projectKey = currentProjectKey()
		if projectKey == "" {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("could not determine the current project; run from a project directory or omit --here")}
		}
	}

	runs, err := client.ListRuns(token, projectKey, historyLimit)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	if historyFormat == "json" {
		return printJSON(map[string]any{"runs": runs})
	}

	if len(runs) == 0 {
		fmt.Println("No runs found. Publish one with 'preflight scan --publish'.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN ID\tPROJECT\tWHEN\tOK\tWARN\tFAIL")
	for _, r := range runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\n",
			r.ID, truncate(r.ProjectName, 28), relTime(r.CreatedAt), r.OK, r.Warn, r.Fail)
	}
	_ = tw.Flush()
	fmt.Printf("\nView a run:  preflight history <run-id>\n")
	return nil
}

// showRun prints one run's check results.
func showRun(client *dashboard.Client, token, runID string) error {
	run, err := client.GetRun(token, runID)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	if historyFormat == "json" {
		return printJSON(run)
	}

	fmt.Printf("%s  (%s)\n", run.ProjectName, time.Unix(run.CreatedAt, 0).Format("Jan 2, 2006 3:04 PM"))
	fmt.Printf("%d passed, %d warnings, %d failed\n\n", run.OK, run.Warn, run.Fail)
	for _, c := range run.Checks {
		mark := "✓"
		if !c.Passed {
			mark = "✗"
			// The wire value is "warn" (checks.SeverityWarn), not "warning".
			if c.Severity == "warn" {
				mark = "!"
			}
		}
		fmt.Printf("  %s  %s\n", mark, c.Title)
		if !c.Passed && c.Message != "" {
			fmt.Printf("       %s\n", c.Message)
		}
	}
	return nil
}

// currentProjectKey computes the dashboard project key for the current
// directory, matching how `preflight scan --publish` groups runs.
func currentProjectKey() string {
	name := ""
	if cfg, err := config.Load("."); err == nil {
		name = cfg.ProjectName
	}
	return projectKey(".", name)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// relTime renders a unix timestamp as a short absolute date.
func relTime(unix int64) string {
	return time.Unix(unix, 0).Format("Jan 2 3:04 PM")
}

// truncate shortens s to n runes. Project names are user text, so count
// runes rather than bytes to avoid slicing a multi-byte character.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
