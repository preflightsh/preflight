package checks

import (
	"fmt"
	"strings"
)

type HealthCheck struct{}

func (c HealthCheck) ID() string {
	return "health_endpoint"
}

func (c HealthCheck) Title() string {
	return "Health endpoint"
}

func (c HealthCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.HealthEndpoint

	// Prefer staging/local for health checks, but fall through to
	// production: a local server that is not running says nothing about
	// whether the site has a health endpoint.
	configured := ctx.Config.URLs.Staging
	if configured == "" {
		configured = ctx.Config.URLs.Production
	}
	if configured == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "No URLs configured to check",
		}, nil
	}

	// The scan already tried every configured host once. If none answered,
	// report that now rather than waiting out the timeout on each health
	// path and then the root.
	baseURLs := ctx.probeBaseURLs()
	if len(baseURLs) == 0 || ctx.Client == nil {
		return c.unreachable(configured), nil
	}
	baseURL := baseURLs[0]

	// Determine which health paths to probe. If the user explicitly enabled
	// the check with a specific path, only try that one. A path with no
	// enabled key is tried first, ahead of the common defaults.
	var pathsToTry []string
	strict := false
	configuredPath := ""
	if cfg != nil {
		configuredPath = healthPath(cfg.Path)
	}
	defaults := []string{"/health", "/healthz", "/api/health", "/_health", "/status"}
	switch {
	case cfg != nil && cfg.Enabled && configuredPath != "":
		pathsToTry = []string{configuredPath}
		strict = true
	case configuredPath != "":
		pathsToTry = []string{configuredPath}
		for _, p := range defaults {
			if p != configuredPath {
				pathsToTry = append(pathsToTry, p)
			}
		}
	default:
		pathsToTry = defaults
	}

	// refusals collects the answers that could not say whether the site is
	// up: a WAF's 403, a 5xx, a login redirect.
	var refusals []string
	for _, path := range pathsToTry {
		if result, ok := c.probePath(ctx, baseURLs, path, strict); ok {
			return result, nil
		}
	}

	// Fallback: the configured/expected health path didn't answer, so just
	// check whether the site itself is up. Many sites don't expose a health
	// endpoint at all, and a reachable homepage is good enough to confirm
	// the site is live.
	if result, ok := c.probeRoot(ctx, baseURLs, &refusals); ok {
		if strict {
			// The user named a health path and it isn't there: that is a
			// finding, not a pass. A reachable homepage only stands in when
			// no path was configured.
			result.Passed = false
			result.Severity = SeverityWarn
			result.Message = "Site reachable, but no health endpoint at " +
				strings.TrimSuffix(baseURL, "/") + configuredPath
			result.Suggestions = []string{
				"Check that the health path is correct in preflight.yml",
				"Or remove the healthEndpoint block to rely on root URL reachability",
			}
		}
		return result, nil
	}

	// The site answered, but not in a way that says whether it is up.
	if len(refusals) > 0 {
		return inconclusiveResult(c, "the site is up", strings.Join(refusals, "; ")), nil
	}

	// Site itself isn't reachable.
	return c.unreachable(baseURL), nil
}

// healthPath normalizes a configured path so "healthz" and "/healthz" name
// the same endpoint. Joining a path without its slash onto the base URL
// requested http://host:3000healthz.
func healthPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

// unreachable is the result when nothing answered at all. That is not proof
// the site is down (a local dev server that is not running during the scan
// looks the same), so it is flagged inconclusive.
func (c HealthCheck) unreachable(baseURL string) CheckResult {
	return CheckResult{
		ID:           c.ID(),
		Title:        c.Title(),
		Severity:     SeverityWarn,
		Passed:       false,
		Inconclusive: true,
		Message:      fmt.Sprintf("Site unreachable: %s", strings.TrimSuffix(baseURL, "/")),
		Suggestions: []string{
			"Ensure your site is accessible",
		},
	}
}

// probePath tries a path on each base and returns (result, true) when one
// answers 2xx with something other than the host's catch-all page. For a
// path the user configured (strict), an answer that demands credentials is
// also the endpoint existing. Returns (_, false) otherwise so the caller
// can keep trying.
func (c HealthCheck) probePath(ctx Context, baseURLs []string, path string, strict bool) (CheckResult, bool) {
	for _, base := range baseURLs {
		baseURL := strings.TrimSuffix(base, "/")
		answer := fetchOnSite(ctx, baseURL+path)
		if answer.err != nil {
			continue
		}
		if strict && !answer.redirected && (answer.status == 401 || answer.status == 403) {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Health endpoint at %s exists but requires authentication (HTTP %d)", answer.url, answer.status),
			}, true
		}
		if !answer.ok() {
			continue
		}
		// A catch-all host (SPA rewrite) answers 200 with its shell for
		// every path, which is not a health endpoint. Where the shell
		// differs between requests the digest cannot rule it out, so only
		// a non-HTML answer (JSON, plain "ok") counts there.
		if shell := ctx.catchAllFor(base); shell.answers {
			if shell.unstable && answer.isHTML() {
				continue
			}
			if !shell.unstable && shell.serves(answer.digest(path)) {
				continue
			}
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  fmt.Sprintf("Health endpoint at %s returned %d", answer.url, answer.status),
		}, true
	}
	return CheckResult{}, false
}

// probeRoot returns (result, true) if the root URL responds with any 2xx or
// 3xx, treating that as a sign the site is up. The scan's own homepage
// request is reused when there is one. Answers that are neither (blocked,
// a server error) are added to refusals.
func (c HealthCheck) probeRoot(ctx Context, baseURLs []string, refusals *[]string) (CheckResult, bool) {
	for _, base := range baseURLs {
		baseURL := strings.TrimSuffix(base, "/")
		status, actualURL := 0, ""
		if fetch, ok := ctx.prefetched(baseURL); ok {
			status, actualURL = fetch.Status, fetch.URL
		} else {
			resp, requested, err := tryURL(ctx.reqContext(), ctx.Client, baseURL+"/")
			if err != nil {
				continue
			}
			status, actualURL = resp.StatusCode, requested
			resp.Body.Close()
		}
		if status >= 200 && status < 400 {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Site reachable at %s (%d)", actualURL, status),
			}, true
		}
		if status != 0 {
			*refusals = append(*refusals, ctx.envName(baseURL)+": "+fetchFailure(status))
		}
	}
	return CheckResult{}, false
}
