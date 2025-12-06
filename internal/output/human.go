package output

import (
	"fmt"
	"strings"

	"github.com/phillips-jon/preflight/internal/checks"
)

type HumanOutputter struct{}

func (h HumanOutputter) Output(projectName string, results []checks.CheckResult) {
	fmt.Println()

	// Map check IDs to display categories
	categoryMap := map[string]string{
		"envParity":       "ENV",
		"healthEndpoint":  "HEALTH",
		"stripeWebhook":   "WEBHOOK",
		"sentry":          "ERRORS",
		"plausible":       "ANALYTICS",
		"seoMeta":         "SEO",
		"securityHeaders": "SECURITY",
		"secrets":         "SECRETS",
	}

	for _, r := range results {
		category := categoryMap[r.ID]
		if category == "" {
			category = strings.ToUpper(r.ID)
		}

		status := formatStatus(r)
		fmt.Printf("[%s] %-40s %s\n", category, r.Title, status)

		if !r.Passed && r.Message != "" {
			fmt.Printf("      %s\n", r.Message)
		}
	}

	// Print summary
	summary := CalculateSummary(results)
	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  OK:   %d\n", summary.OK)
	fmt.Printf("  WARN: %d\n", summary.Warn)
	fmt.Printf("  FAIL: %d\n", summary.Fail)
	fmt.Println()
}

func formatStatus(r checks.CheckResult) string {
	if r.Passed {
		return "\033[32mOK\033[0m" // Green
	}

	switch r.Severity {
	case checks.SeverityError:
		return "\033[31mFAIL\033[0m" // Red
	case checks.SeverityWarn:
		return "\033[33mWARN\033[0m" // Yellow
	default:
		return "\033[33mWARN\033[0m"
	}
}
