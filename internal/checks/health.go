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

	// Get base URLs to check
	var baseURLs []string
	if ctx.Config.URLs.Staging != "" {
		baseURLs = append(baseURLs, ctx.Config.URLs.Staging)
	}
	if ctx.Config.URLs.Production != "" {
		baseURLs = append(baseURLs, ctx.Config.URLs.Production)
	}

	if len(baseURLs) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No URLs configured to check",
		}, nil
	}

	// If a specific path is configured, use it
	if cfg != nil && cfg.Path != "" {
		return c.checkPath(ctx, baseURLs, cfg.Path, true)
	}

	// Try common health endpoint paths first
	commonPaths := []string{"/health", "/healthz", "/api/health", "/_health", "/status"}
	for _, path := range commonPaths {
		result, _ := c.checkPath(ctx, baseURLs, path, false)
		if result.Passed {
			return result, nil
		}
	}

	// Fallback: check if the root URL returns 200 OK
	return c.checkPath(ctx, baseURLs, "/", false)
}

// checkPath tries a specific path on all base URLs
func (c HealthCheck) checkPath(ctx Context, baseURLs []string, path string, configured bool) (CheckResult, error) {
	var lastErr error
	for _, baseURL := range baseURLs {
		// Handle trailing slash in base URL to avoid double slashes
		baseURL = strings.TrimSuffix(baseURL, "/")
		url := baseURL + path
		resp, actualURL, err := tryURL(ctx.Client, url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			msg := fmt.Sprintf("Site reachable at %s (200 OK)", actualURL)
			if path != "/" {
				msg = fmt.Sprintf("Health endpoint at %s returned 200 OK", actualURL)
			}
			var details []string
			if ctx.Verbose && !configured && path != "/" {
				details = append(details, "Auto-detected health endpoint")
			}
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  msg,
				Details:  details,
			}, nil
		}
		lastErr = fmt.Errorf("returned status %d", resp.StatusCode)
	}

	// Only return failure for configured paths or root fallback
	if configured || path == "/" {
		suggestions := []string{
			"Ensure your site is accessible",
		}
		if configured {
			suggestions = append(suggestions, "Check that the health path is correct in preflight.yml")
		} else {
			suggestions = append(suggestions, "Consider adding a /health endpoint for better monitoring")
		}
		return CheckResult{
			ID:          c.ID(),
			Title:       c.Title(),
			Severity:    SeverityWarn,
			Passed:      false,
			Message:     fmt.Sprintf("Site unreachable: %v", lastErr),
			Suggestions: suggestions,
		}, nil
	}

	// Return non-passed for auto-detection probes (will continue to next path)
	return CheckResult{
		Passed: false,
	}, nil
}
