package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/preflightsh/preflight/internal/netutil"
	"golang.org/x/net/publicsuffix"
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
			Skipped:  true,
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

	// Skip local dev URLs. Reuse IsLocalURL so the list stays in sync
	// with the SSRF-bypass allowlist (localhost, *.localhost, *.test,
	// *.ddev.site, *.lndo.site, etc.).
	if IsLocalURL(ctx.Config.URLs.Production) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Skipped for local URL",
		}, nil
	}

	// A www counterpart only exists for the registrable domain. For a
	// subdomain production URL (app.example.com) there is no www question:
	// www.app.example.com is not a name anyone types or expects to work.
	if apex, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && host != apex && host != "www."+apex {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Skipped for subdomain " + host,
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
	wwwFinal, wwwErr := getFinalURL(ctx.reqContext(), wwwURL)
	nonWwwFinal, nonWwwErr := getFinalURL(ctx.reqContext(), nonWwwURL)

	// Both fail to resolve
	if wwwErr != nil && nonWwwErr != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("Neither www nor non-www is reachable (www %s, non-www %s)", describeFetchError(wwwErr), describeFetchError(nonWwwErr)),
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
			Message:  fmt.Sprintf("www.%s %s", nonWwwHost, describeFetchError(wwwErr)),
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
			Message:  fmt.Sprintf("%s (non-www) %s", nonWwwHost, describeFetchError(nonWwwErr)),
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

func getFinalURL(ctx context.Context, urlStr string) (string, error) {
	// This call starts with a user-configured URL and follows redirects;
	// SafeHTTPClient guards both the initial dial AND each redirect hop
	// against private / loopback / link-local addresses.
	client := netutil.SafeHTTPClient(10 * time.Second)

	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		return "", fmt.Errorf("build request for %s: %w", urlStr, err)
	}
	req.Header.Set("User-Agent", "Preflight/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD %s: %w", urlStr, err)
	}
	defer resp.Body.Close()

	return resp.Request.URL.String(), nil
}

// describeFetchError names the class of a failed request, so a certificate
// problem or a refused connection isn't reported as missing DNS.
func describeFetchError(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	switch {
	case errors.As(err, &dnsErr):
		return "does not resolve"
	case errors.As(err, &certErr), errors.As(err, &hostErr), errors.As(err, &authErr), errors.As(err, &invalidErr):
		return "has a TLS certificate error"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "timed out"
	default:
		return "is unreachable"
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsed.Hostname()
}
