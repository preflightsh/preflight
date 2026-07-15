package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/preflightsh/preflight/internal/checks"
)

type JSONOutputter struct{}

type JSONOutput struct {
	Project string            `json:"project"`
	Summary Summary           `json:"summary"`
	Checks  []JSONCheckResult `json:"checks"`
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
		Project: projectName,
		Summary: CalculateSummary(results),
		Checks:  make([]JSONCheckResult, len(results)),
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
