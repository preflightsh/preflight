package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/preflightsh/preflight/internal/output"
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
		return &ExitError{Code: ExitFail, Err: err}
	}
	if creds == nil || creds.Token == "" {
		return &ExitError{Code: ExitFail, Err: fmt.Errorf("not logged in; run 'preflight auth login' to view your dashboard history")}
	}
	client, warning := dashboard.ClientForCredentials(creds)
	client.Ctx = cmd.Context()
	if warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}

	if len(args) == 1 {
		run, err := client.GetRun(creds.Token, args[0])
		if err != nil {
			return &ExitError{Code: ExitFail, Err: err}
		}
		if historyFormat == "json" {
			return printJSON(run)
		}
		writeRun(os.Stdout, run)
		return nil
	}
	return listHistory(client, creds.Token)
}

// listHistory prints recent runs, optionally scoped to the current project.
func listHistory(client *dashboard.Client, token string) error {
	projectKey := ""
	if historyHere {
		projectKey = currentProjectKey(".")
		if projectKey == "" {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("could not determine the current project; run from a project directory or omit --here")}
		}
	}

	runs, err := client.ListRuns(token, projectKey, historyLimit)
	if err != nil {
		return &ExitError{Code: ExitFail, Err: err}
	}

	if historyFormat == "json" {
		return printJSON(map[string]any{"runs": runs})
	}

	if len(runs) == 0 {
		fmt.Println("No runs found. Publish one with 'preflight scan --publish'.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN ID\tPROJECT\tWHEN\tOK\tWARN\tFAIL\tSKIPPED")
	for _, r := range runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			output.Sanitize(r.ID), truncate(output.Sanitize(r.ProjectName), 28), shortDate(r.CreatedAt), r.OK, r.Warn, r.Fail, r.Skipped)
	}
	_ = tw.Flush()
	fmt.Printf("\nView a run:  preflight history <run-id>\n")
	return nil
}

// writeRun prints one run's check results. Every string here came from the
// dashboard, so each is sanitized before it reaches the terminal.
func writeRun(w io.Writer, run *dashboard.RunDetail) {
	fmt.Fprintf(w, "%s  (%s)\n", output.Sanitize(run.ProjectName), time.Unix(run.CreatedAt, 0).Format("Jan 2, 2006 3:04 PM"))
	fmt.Fprintf(w, "%d passed, %d warnings, %d failed\n", run.OK, run.Warn, run.Fail)
	// Inconclusive checks are among the warnings; skipped ones are in
	// none of the three counts.
	if run.Skipped > 0 || run.Inconclusive > 0 {
		fmt.Fprintf(w, "Not verified: %d skipped, %d inconclusive\n", run.Skipped, run.Inconclusive)
	}
	fmt.Fprintln(w)
	for _, c := range run.Checks {
		fmt.Fprintf(w, "  %s  %s\n", runCheckMark(c), output.Sanitize(c.Title))
		// A skipped or inconclusive check passes or fails on paper, but
		// its message is the only thing that says it was not verified.
		if (!c.Passed || c.Skipped || c.Inconclusive) && c.Message != "" {
			fmt.Fprintf(w, "       %s\n", output.Sanitize(c.Message))
		}
	}
}

// runCheckMark is the one-character status of a published check. Skipped
// and inconclusive come first: a skipped check is stored as passed: false
// with info severity and used to print as a failure, and an inconclusive
// one could print as a pass.
func runCheckMark(c dashboard.PublishCheck) string {
	switch {
	case c.Skipped:
		return "-"
	case c.Inconclusive:
		return "?"
	case c.Passed:
		return "✓"
	case c.Severity == "warn": // the wire value (checks.SeverityWarn), not "warning"
		return "!"
	default:
		return "✗"
	}
}

// currentProjectKey computes the dashboard project key for dir, matching
// how `preflight scan --publish` groups runs. It is "" when dir is not a
// project: no repository remote and no preflight.yml. projectKey always
// returns at least "name:", so without this check `history --here`
// outside a project asked the dashboard for a project with no name and
// reported "No runs found" instead of the usage error.
func currentProjectKey(dir string) string {
	cfg, err := config.Load(dir)
	name := ""
	if err == nil {
		name = cfg.ProjectName
	}
	key := projectKey(dir, name)
	if err != nil && strings.HasPrefix(key, "name:") {
		return ""
	}
	return key
}

func printJSON(v any) error {
	return writeHistoryJSON(os.Stdout, v)
}

// writeHistoryJSON writes v, a JSON object, with schema_version and
// cli_version added beside its own keys, so agents can tell which contract
// the output follows the same way they do for scan JSON.
func writeHistoryJSON(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc["schema_version"] = output.SchemaVersion
	doc["cli_version"] = version
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// shortDate renders a unix timestamp as a short absolute date.
func shortDate(unix int64) string {
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
