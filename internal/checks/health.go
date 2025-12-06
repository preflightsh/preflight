package checks

import (
	"fmt"
	"net/http"
)

type HealthCheck struct{}

func (c HealthCheck) ID() string {
	return "healthEndpoint"
}

func (c HealthCheck) Title() string {
	return "Health endpoint is reachable"
}

func (c HealthCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.HealthEndpoint
	if cfg == nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Check not configured",
		}, nil
	}

	// Try staging first, then production
	urls := []string{}
	if ctx.Config.URLs.Staging != "" {
		urls = append(urls, ctx.Config.URLs.Staging+cfg.Path)
	}
	if ctx.Config.URLs.Production != "" {
		urls = append(urls, ctx.Config.URLs.Production+cfg.Path)
	}

	if len(urls) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "No staging or production URL configured",
			Suggestions: []string{
				"Add staging or production URL to preflight.yml",
			},
		}, nil
	}

	var lastErr error
	for _, url := range urls {
		resp, err := ctx.Client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Health endpoint at %s returned 200 OK", url),
			}, nil
		}
		lastErr = fmt.Errorf("returned status %d", resp.StatusCode)
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  fmt.Sprintf("Health endpoint unreachable: %v", lastErr),
		Suggestions: []string{
			"Ensure your health endpoint is accessible",
			"Check that the path is correct in preflight.yml",
		},
	}, nil
}
