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
	return "Security headers are present"
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
		missing, err := c.checkURL(ctx, prodURL, true)
		if err != nil {
			results = append(results, fmt.Sprintf("prod: unreachable"))
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
		missing, err := c.checkURL(ctx, stagingURL, false)
		if err != nil {
			results = append(results, fmt.Sprintf("staging: unreachable"))
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
			Message:  strings.Join(results, " | "),
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
		Message:     strings.Join(results, " | "),
		Suggestions: suggestions,
	}, nil
}

// checkURL checks security headers for a single URL and returns missing headers
func (c SecurityHeadersCheck) checkURL(ctx Context, url string, isProd bool) ([]string, error) {
	resp, actualURL, err := tryURL(ctx.Client, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
		if resp.Header.Get(header) == "" {
			missing = append(missing, header)
		}
	}

	return missing, nil
}
