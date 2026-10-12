package output

import (
	"io"

	"github.com/preflightsh/preflight/internal/checks"
)

// Outputter renders scan results to w. Taking the writer as a parameter
// rather than reaching for os.Stdout is what makes the rendering
// testable: JSONOutput in particular is the run-data contract the
// dashboard ingests, so it needs to be assertable byte for byte.
type Outputter interface {
	Output(w io.Writer, projectName string, results []checks.CheckResult) error
}

type Summary struct {
	OK           int `json:"ok"`
	Warn         int `json:"warn"`
	Fail         int `json:"fail"`
	Skipped      int `json:"skipped,omitempty"`
	Inconclusive int `json:"inconclusive,omitempty"`
}

func CalculateSummary(results []checks.CheckResult) Summary {
	var summary Summary

	for _, r := range results {
		if r.Skipped {
			summary.Skipped++
			continue
		}
		if r.Inconclusive {
			summary.Inconclusive++
			if !r.Passed && r.Severity == checks.SeverityError {
				summary.Fail++
			} else {
				summary.Warn++
			}
			continue
		}
		if r.Passed {
			summary.OK++
		} else {
			switch r.Severity {
			case checks.SeverityError:
				summary.Fail++
			case checks.SeverityWarn:
				summary.Warn++
			default:
				summary.Warn++
			}
		}
	}

	return summary
}
