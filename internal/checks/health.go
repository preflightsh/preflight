package checks

import (
	"fmt"
	"net/http"
	"strings"
)

type HealthCheck struct{}

func (c HealthCheck) ID() string {
	return "healthEndpoint"
}

func (c HealthCheck) Title() string {
	return "Health endpoint"
}

func (c HealthCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.HealthEndpoint

	// Get base URL to check - prefer staging/local for health checks
	var baseURL string
	if ctx.Config.URLs.Staging != "" {
		baseURL = ctx.Config.URLs.Staging
	} else if ctx.Config.URLs.Production != "" {
		baseURL = ctx.Config.URLs.Production
	}

	if baseURL == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No URLs configured to check",
		}, nil
	}

	baseURLs := []string{baseURL}

	// Determine which health paths to probe. If the user explicitly enabled
	// the check with a specific path, only try that one. Otherwise try the
	// common defaults.
	var pathsToTry []string
	strict := false
	if cfg != nil && cfg.Enabled && cfg.Path != "" {
		pathsToTry = []string{cfg.Path}
		strict = true
	} else {
		pathsToTry = []string{"/health", "/healthz", "/api/health", "/_health", "/status"}
	}

	for _, path := range pathsToTry {
		if result, ok := c.probePath(ctx, baseURLs, path); ok {
			return result, nil
		}
	}

	// Fallback: the configured/expected health path didn't return 200, so
	// just check whether the site itself is up. Many sites don't expose a
	// health endpoint at all, and a reachable homepage is good enough to
	// confirm the site is live.
	if result, ok := c.probeRoot(ctx, baseURLs); ok {
		if strict {
			result.Message = "Site reachable, but no health endpoint at " +
				strings.TrimSuffix(baseURL, "/") + cfg.Path
			result.Suggestions = []string{
				"Check that the health path is correct in preflight.yml",
				"Or remove the healthEndpoint block to rely on root URL reachability",
			}
		}
		return result, nil
	}

	// Site itself isn't reachable.
	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  fmt.Sprintf("Site unreachable: %s", strings.TrimSuffix(baseURL, "/")),
		Suggestions: []string{
			"Ensure your site is accessible",
		},
	}, nil
}

// probePath tries a path and returns (result, true) on a 200 response.
// Returns (_, false) on any error or non-200 so the caller can keep trying.
func (c HealthCheck) probePath(ctx Context, baseURLs []string, path string) (CheckResult, bool) {
	for _, baseURL := range baseURLs {
		baseURL = strings.TrimSuffix(baseURL, "/")
		resp, actualURL, err := tryURL(ctx.Client, baseURL+path)
		if err != nil {
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()
		if status == http.StatusOK {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Health endpoint at %s returned %d", actualURL, status),
			}, true
		}
	}
	return CheckResult{}, false
}

// probeRoot returns (result, true) if the root URL responds with any 2xx or
// 3xx, treating that as a sign the site is up.
func (c HealthCheck) probeRoot(ctx Context, baseURLs []string) (CheckResult, bool) {
	for _, baseURL := range baseURLs {
		baseURL = strings.TrimSuffix(baseURL, "/")
		resp, actualURL, err := tryURL(ctx.Client, baseURL+"/")
		if err != nil {
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()
		if status >= 200 && status < 400 {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Site reachable at %s (%d)", actualURL, status),
			}, true
		}
	}
	return CheckResult{}, false
}
