package checks

import (
	"fmt"
	"strings"
)

type SecurityHeadersCheck struct{}

func (c SecurityHeadersCheck) ID() string {
	return "securityHeaders"
}

func (c SecurityHeadersCheck) Title() string {
	return "Security headers"
}

func (c SecurityHeadersCheck) Run(ctx Context) (CheckResult, error) {
	prodURL := ctx.Config.URLs.Production
	stagingURL := ctx.Config.URLs.Staging

	if prodURL == "" && stagingURL == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No staging or production URL configured, skipping",
		}, nil
	}

	// Check both environments
	var results []string
	var allMissing []string
	var suggestions []string
	hasFailure := false

	// Check production if configured
	if prodURL != "" {
		missing, status, err := c.checkURL(ctx, prodURL, ctx.PageFetchProduction)
		if err != nil {
			results = append(results, "prod: unreachable")
			hasFailure = true
		} else if blockedStatus(status) {
			// The headers on a bot-protection or auth-wall response are the
			// edge's, not the site's. Reporting them would invent missing
			// headers for a site we never actually reached.
			results = append(results, fmt.Sprintf("prod: %s", fetchFailure(status)))
			hasFailure = true
		} else if len(missing) > 0 {
			results = append(results, fmt.Sprintf("prod missing: %s", strings.Join(missing, ", ")))
			allMissing = append(allMissing, missing...)
			hasFailure = true
		} else {
			results = append(results, "prod: ✓")
		}
	}

	// Check staging if configured
	if stagingURL != "" {
		missing, status, err := c.checkURL(ctx, stagingURL, ctx.PageFetchStaging)
		if err != nil {
			results = append(results, "staging: unreachable")
			hasFailure = true
		} else if blockedStatus(status) {
			results = append(results, fmt.Sprintf("staging: %s", fetchFailure(status)))
			hasFailure = true
		} else if len(missing) > 0 {
			results = append(results, fmt.Sprintf("staging missing: %s", strings.Join(missing, ", ")))
			allMissing = append(allMissing, missing...)
			hasFailure = true
		} else {
			results = append(results, "staging: ✓")
		}
	}

	if !hasFailure {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			// Stack per-env results one per line, matching how every other
			// per-env check (SEO, OG, viewport, lang) renders its breakdown.
			Message: strings.Join(results, "\n                    └─ "),
		}, nil
	}

	// Build suggestions based on missing headers
	suggestions = append(suggestions, "Add missing security headers to your server configuration")
	seen := make(map[string]bool)
	for _, header := range allMissing {
		if seen[header] {
			continue
		}
		seen[header] = true
		switch header {
		case "Strict-Transport-Security":
			suggestions = append(suggestions, "HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains")
		case "X-Content-Type-Options":
			suggestions = append(suggestions, "X-Content-Type-Options: nosniff")
		case "Referrer-Policy":
			suggestions = append(suggestions, "Referrer-Policy: strict-origin-when-cross-origin")
		case "Content-Security-Policy":
			suggestions = append(suggestions, "Consider adding a Content-Security-Policy header")
		}
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     strings.Join(results, "\n                    └─ "),
		Suggestions: suggestions,
	}, nil
}

// checkURL checks security headers for a single URL and returns the missing
// headers alongside the status the host answered with, so the caller can
// discard the results of a response that never came from the app.
//
// The scan already fetched each environment's homepage, so prefetched is
// reused when it holds a response: one request per environment means this
// row can't disagree with the SEO and metadata rows about whether the host
// answered, which it otherwise would whenever a slow host beat the timeout
// on one request but not the other. Only a check invoked outside a scan
// (no prefetch) makes its own request.
func (c SecurityHeadersCheck) checkURL(ctx Context, url string, prefetched PageFetch) ([]string, int, error) {
	headers, status, actualURL := prefetched.Headers, prefetched.Status, prefetched.URL
	if !prefetched.Attempted() {
		resp, requested, err := tryURL(ctx.reqContext(), ctx.Client, url)
		if err != nil {
			return nil, 0, fmt.Errorf("fetch %s: %w", url, err)
		}
		defer resp.Body.Close()
		headers, status, actualURL = resp.Header, resp.StatusCode, requested
	}
	if headers == nil {
		// The scan tried this environment and nothing answered.
		return nil, 0, fmt.Errorf("fetch %s: no response", url)
	}

	// Check if we're using HTTPS (HSTS only makes sense over HTTPS)
	isHTTPS := strings.HasPrefix(actualURL, "https://")

	// Required security headers
	requiredHeaders := []string{
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	}

	// Only check HSTS over HTTPS connections
	if isHTTPS {
		requiredHeaders = append([]string{"Strict-Transport-Security"}, requiredHeaders...)
	}

	var missing []string
	for _, header := range requiredHeaders {
		if headers.Get(header) == "" {
			missing = append(missing, header)
		}
	}

	return missing, status, nil
}
