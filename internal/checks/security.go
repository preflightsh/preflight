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
	var weakNotes []string
	var suggestions []string
	hasFailure := false
	// Production is authoritative once it answered, the same rule RunPerEnv
	// applies: a staging host that is down (a local dev server not running
	// during the scan) is noted in the message but is not a header failure.
	prodAnswered := false

	// Check production if configured
	if prodURL != "" {
		missing, weak, status, err := c.checkURL(ctx, prodURL, ctx.PageFetchProduction)
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
			results = append(results, fmt.Sprintf("prod missing: %s", strings.Join(missing, ", "))+weakSuffix(weak))
			allMissing = append(allMissing, missing...)
			hasFailure = true
		} else {
			results = append(results, "prod: ✓"+weakSuffix(weak))
		}
		weakNotes = append(weakNotes, weak...)
		prodAnswered = err == nil && !blockedStatus(status)
	}

	// Check staging if configured
	if stagingURL != "" {
		missing, weak, status, err := c.checkURL(ctx, stagingURL, ctx.PageFetchStaging)
		if err != nil {
			results = append(results, "staging: unreachable")
			hasFailure = hasFailure || !prodAnswered
		} else if blockedStatus(status) {
			results = append(results, fmt.Sprintf("staging: %s", fetchFailure(status)))
			hasFailure = hasFailure || !prodAnswered
		} else if len(missing) > 0 {
			results = append(results, fmt.Sprintf("staging missing: %s", strings.Join(missing, ", "))+weakSuffix(weak))
			allMissing = append(allMissing, missing...)
			hasFailure = true
		} else {
			results = append(results, "staging: ✓"+weakSuffix(weak))
		}
		weakNotes = append(weakNotes, weak...)
	}

	// A weak CSP is still a CSP: it is worth tightening, but it doesn't fail
	// the check on its own.
	var cspSuggestions []string
	if len(weakNotes) > 0 {
		cspSuggestions = append(cspSuggestions, "Tighten script-src: replace 'unsafe-inline' with nonces or hashes, drop 'unsafe-eval' and wildcard sources")
	}

	if !hasFailure {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			// One line, like every other per-env check: Message is rendered
			// on a single line by the terminal and the dashboard.
			Message:     strings.Join(results, "; "),
			Suggestions: cspSuggestions,
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

	suggestions = append(suggestions, cspSuggestions...)

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     strings.Join(results, "; "),
		Suggestions: suggestions,
	}, nil
}

// weakSuffix renders an environment's weak-header notes after its verdict.
func weakSuffix(weak []string) string {
	if len(weak) == 0 {
		return ""
	}
	return " (" + strings.Join(weak, ", ") + ")"
}

// checkURL checks security headers for a single URL and returns the missing
// headers, notes on headers that are present but weak (a CSP that allows
// 'unsafe-inline'), and the status the host answered with, so the caller can
// discard the results of a response that never came from the app.
//
// The scan already fetched each environment's homepage, so prefetched is
// reused when it holds a response: one request per environment means this
// row can't disagree with the SEO and metadata rows about whether the host
// answered, which it otherwise would whenever a slow host beat the timeout
// on one request but not the other. Only a check invoked outside a scan
// (no prefetch) makes its own request.
func (c SecurityHeadersCheck) checkURL(ctx Context, url string, prefetched PageFetch) ([]string, []string, int, error) {
	headers, status, actualURL := prefetched.Headers, prefetched.Status, prefetched.URL
	if !prefetched.Attempted() {
		resp, requested, err := tryURL(ctx.reqContext(), ctx.Client, url)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("fetch %s: %w", url, err)
		}
		defer resp.Body.Close()
		headers, status, actualURL = resp.Header, resp.StatusCode, requested
	}
	if headers == nil {
		// The scan tried this environment and nothing answered.
		return nil, nil, 0, fmt.Errorf("fetch %s: no response", url)
	}
	if (status < 200 || status >= 400) && !blockedStatus(status) {
		return nil, nil, status, fmt.Errorf("fetch %s: HTTP %d", url, status)
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

	var missing, weak []string
	for _, header := range requiredHeaders {
		value := headers.Get(header)
		switch {
		case strings.TrimSpace(value) == "":
			missing = append(missing, header)
		case header == "Content-Security-Policy":
			if w := cspWeakness(value); w != "" {
				weak = append(weak, "weak Content-Security-Policy: "+w)
			}
		case !validSecurityHeader(header, value):
			missing = append(missing, header+" (invalid or ineffective)")
		}
	}

	return missing, weak, status, nil
}

// cspWeakness describes why a Content-Security-Policy does little against
// script injection ("script-src allows 'unsafe-inline'"), or returns "" for a
// policy that restricts scripts.
func cspWeakness(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	directives := map[string][]string{}
	for _, part := range strings.Split(value, ";") {
		fields := strings.Fields(part)
		if len(fields) > 0 {
			if _, seen := directives[fields[0]]; !seen {
				directives[fields[0]] = fields[1:]
			}
		}
	}
	name := "script-src"
	sources, ok := directives[name]
	if !ok {
		name = "default-src"
		sources, ok = directives[name]
	}
	if !ok || len(sources) == 0 {
		return "no script-src or default-src"
	}
	// A nonce or hash makes browsers ignore 'unsafe-inline' (it is only
	// there as a fallback for old ones).
	nonce := false
	for _, v := range sources {
		if strings.HasPrefix(v, "'nonce-") || strings.HasPrefix(v, "'sha256-") || strings.HasPrefix(v, "'sha384-") || strings.HasPrefix(v, "'sha512-") {
			nonce = true
		}
	}
	for _, v := range sources {
		if v == "*" || v == "http:" || v == "https:" || v == "'unsafe-eval'" || (v == "'unsafe-inline'" && !nonce) {
			return name + " allows " + v
		}
	}
	return ""
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
		return cspWeakness(value) == ""
	}
	return false
}
