package checks

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WWWRedirectCheck struct{}

func (c WWWRedirectCheck) ID() string {
	return "www_redirect"
}

func (c WWWRedirectCheck) Title() string {
	return "WWW redirect"
}

func (c WWWRedirectCheck) Run(ctx Context) (CheckResult, error) {
	if ctx.Config.URLs.Production == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No production URL configured",
		}, nil
	}

	parsedURL, err := url.Parse(ctx.Config.URLs.Production)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Invalid production URL",
		}, nil
	}

	host := parsedURL.Hostname()

	// Skip localhost and IP addresses
	if host == "localhost" || host == "127.0.0.1" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".test") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Skipped for local URL",
		}, nil
	}

	// Determine www and non-www versions
	var wwwHost, nonWwwHost string
	if strings.HasPrefix(host, "www.") {
		wwwHost = host
		nonWwwHost = strings.TrimPrefix(host, "www.")
	} else {
		nonWwwHost = host
		wwwHost = "www." + host
	}

	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	wwwURL := scheme + "://" + wwwHost
	nonWwwURL := scheme + "://" + nonWwwHost

	// Check both URLs
	wwwFinal, wwwErr := getFinalURL(wwwURL)
	nonWwwFinal, nonWwwErr := getFinalURL(nonWwwURL)

	// Both fail to resolve
	if wwwErr != nil && nonWwwErr != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Neither www nor non-www resolves",
			Suggestions: []string{
				"Check your DNS configuration",
				"Ensure both www and non-www have DNS records",
			},
		}, nil
	}

	// Only one resolves - that's fine, but warn
	if wwwErr != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("www.%s does not resolve", nonWwwHost),
			Suggestions: []string{
				"Add a CNAME or A record for www subdomain",
				"Or redirect www to non-www in your DNS/CDN",
			},
		}, nil
	}

	if nonWwwErr != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("%s (non-www) does not resolve", nonWwwHost),
			Suggestions: []string{
				"Add an A record for the apex domain",
				"Or redirect non-www to www in your DNS/CDN",
			},
		}, nil
	}

	// Both resolve - check if they end up at the same domain
	wwwFinalHost := extractHost(wwwFinal)
	nonWwwFinalHost := extractHost(nonWwwFinal)

	// Normalize: strip www. prefix for comparison
	wwwNormalized := strings.TrimPrefix(wwwFinalHost, "www.")
	nonWwwNormalized := strings.TrimPrefix(nonWwwFinalHost, "www.")

	if wwwNormalized == nonWwwNormalized {
		// Both end up at the same domain (with or without www)
		if wwwFinalHost == nonWwwFinalHost {
			canonical := "non-www"
			if strings.HasPrefix(wwwFinalHost, "www.") {
				canonical = "www"
			}
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("Both redirect to %s (%s)", canonical, wwwFinalHost),
			}, nil
		}
		// Both work but serve on their respective domains (no redirect)
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Both www and non-www resolve correctly",
		}, nil
	}

	// Both resolve but to completely different domains
	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "www and non-www resolve to different domains",
		Suggestions: []string{
			"Configure redirects so both point to your canonical URL",
			fmt.Sprintf("www → %s, non-www → %s", wwwFinalHost, nonWwwFinalHost),
		},
	}, nil
}

func getFinalURL(urlStr string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Preflight/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Request.URL.String(), nil
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsed.Hostname()
}
