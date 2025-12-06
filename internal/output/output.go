package output

import "github.com/phillips-jon/preflight/internal/checks"

type Outputter interface {
	Output(projectName string, results []checks.CheckResult)
}

type Summary struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

func CalculateSummary(results []checks.CheckResult) Summary {
	var summary Summary

	for _, r := range results {
		if r.Passed {
			summary.OK++
		} else {
			switch r.Severity {
			case checks.SeverityError:
				summary.Fail++
			case checks.SeverityWarn:
				summary.Warn++
			default:
				summary.OK++
			}
		}
	}

	return summary
}
