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
	// Need a production URL to check
	if ctx.Config.URLs.Production == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No production URL configured, skipping",
		}, nil
	}

	resp, err := ctx.Client.Get(ctx.Config.URLs.Production)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("Could not reach production URL: %v", err),
			Suggestions: []string{
				"Ensure production URL is accessible",
			},
		}, nil
	}
	defer resp.Body.Close()

	// Required security headers
	requiredHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	}

	var missing []string
	var present []string

	for _, header := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			missing = append(missing, header)
		} else {
			present = append(present, header)
		}
	}

	if len(missing) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "All recommended security headers present",
		}, nil
	}

	suggestions := []string{
		"Add missing security headers to your server configuration",
	}

	// Add specific suggestions for common missing headers
	for _, header := range missing {
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
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  fmt.Sprintf("Missing security headers: %s (present: %s)", strings.Join(missing, ", "), strings.Join(present, ", ")),
		Suggestions: suggestions,
	}, nil
}
