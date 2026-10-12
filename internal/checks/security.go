package checks

import (
	"fmt"
	"strconv"
	"strings"
)

type SecurityHeadersCheck struct{}

func (c SecurityHeadersCheck) ID() string {
	return "security_headers"
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
	// Production is authoritative once it answered, the same rule RunPerEnv
	// applies: a staging host that is down (a local dev server not running
	// during the scan) is noted in the message but is not a header failure.
	prodAnswered := false

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
		prodAnswered = err == nil && !blockedStatus(status)
	}

	// Check staging if configured
	if stagingURL != "" {
		missing, status, err := c.checkURL(ctx, stagingURL, ctx.PageFetchStaging)
		if err != nil {
			results = append(results, "staging: unreachable")
			hasFailure = hasFailure || !prodAnswered
		} else if blockedStatus(status) {
			results = append(results, fmt.Sprintf("staging: %s", fetchFailure(status)))
			hasFailure = hasFailure || !prodAnswered
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
			// One line, like every other per-env check: Message is rendered
			// on a single line by the terminal and the dashboard.
			Message: strings.Join(results, "; "),
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
		Message:     strings.Join(results, "; "),
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
	if (status < 200 || status >= 400) && !blockedStatus(status) {
		return nil, status, fmt.Errorf("fetch %s: HTTP %d", url, status)
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
		} else if !validSecurityHeader(header, headers.Get(header)) {
			missing = append(missing, header+" (invalid or ineffective)")
		}
	}

	return missing, status, nil
}

func validSecurityHeader(name, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch name {
	case "X-Content-Type-Options":
		return value == "nosniff"
	case "Strict-Transport-Security":
		for _, part := range strings.Split(value, ";") {
			key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
			if key == "max-age" && ok {
				n, e := strconv.ParseInt(strings.Trim(val, "\""), 10, 64)
				return e == nil && n > 0
			}
		}
		return false
	case "Referrer-Policy":
		valid := map[string]bool{"no-referrer": true, "same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true, "no-referrer-when-downgrade": true, "origin": true, "origin-when-cross-origin": true}
		parts := strings.Split(value, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if valid[strings.TrimSpace(parts[i])] {
				return true
			}
		}
		return false
	case "Content-Security-Policy":
		directives := map[string][]string{}
		for _, part := range strings.Split(value, ";") {
			fields := strings.Fields(part)
			if len(fields) > 0 {
				if _, seen := directives[fields[0]]; !seen {
					directives[fields[0]] = fields[1:]
				}
			}
		}
		sources, ok := directives["script-src"]
		if !ok {
			sources, ok = directives["default-src"]
		}
		if !ok || len(sources) == 0 {
			return false
		}
		nonce := false
		for _, v := range sources {
			if strings.HasPrefix(v, "'nonce-") || strings.HasPrefix(v, "'sha256-") || strings.HasPrefix(v, "'sha384-") || strings.HasPrefix(v, "'sha512-") {
				nonce = true
			}
		}
		for _, v := range sources {
			if v == "*" || v == "http:" || v == "https:" || v == "'unsafe-eval'" || (v == "'unsafe-inline'" && !nonce) {
				return false
			}
		}
		return true
	}
	return false
}
