package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/preflightsh/preflight/internal/checks"
)

// SchemaVersion identifies the shape of JSONOutput and of the payload
// published to the dashboard. Consumers can branch on it instead of
// guessing from the fields present. It is bumped only when an existing
// field changes meaning or goes away; adding a field does not count.
//
//	1: the 1.0 contract. Check IDs are snake_case (see catalog.Aliases).
//	   Output without a schema_version is from a pre-1.0 CLI, with the old
//	   camelCase IDs.
const SchemaVersion = 1

// JSONOutputter renders the machine-readable report. CLIVersion is the
// version of the binary producing it, stamped into the output.
type JSONOutputter struct {
	CLIVersion string
}

type JSONOutput struct {
	SchemaVersion int               `json:"schema_version"`
	CLIVersion    string            `json:"cli_version,omitempty"`
	Project       string            `json:"project"`
	Summary       Summary           `json:"summary"`
	Checks        []JSONCheckResult `json:"checks"`
}

type JSONCheckResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Passed      bool     `json:"passed"`
	Severity    string   `json:"severity"`
	Message     string   `json:"message,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

func (j JSONOutputter) Output(w io.Writer, projectName string, results []checks.CheckResult) {
	output := BuildJSONOutput(projectName, results)
	output.CLIVersion = j.CLIVersion

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
	}
}

// BuildJSONOutput maps check results onto the wire format. Kept separate
// from the encoding so the contract can be asserted without doing I/O.
func BuildJSONOutput(projectName string, results []checks.CheckResult) JSONOutput {
	output := JSONOutput{
		SchemaVersion: SchemaVersion,
		Project:       projectName,
		Summary:       CalculateSummary(results),
		Checks:        make([]JSONCheckResult, len(results)),
	}

	for i, r := range results {
		output.Checks[i] = JSONCheckResult{
			ID:          r.ID,
			Title:       r.Title,
			Passed:      r.Passed,
			Severity:    string(r.Severity),
			Message:     r.Message,
			Suggestions: r.Suggestions,
		}
	}

	return output
}
