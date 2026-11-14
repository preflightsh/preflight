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
	"sync"
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

	// A name directly under a hosting platform's shared suffix
	// (myapp.vercel.app, user.github.io) is the whole site. The public
	// suffix list counts it as a registrable domain, so the test above lets
	// it through, but www.myapp.vercel.app is not a name the owner can
	// create a record for.
	if platformHost(host) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Skipped for platform subdomain " + host,
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
	// Keep a port from the production URL: without it the check asked a
	// different server than the one configured.
	port := ""
	if p := parsedURL.Port(); p != "" {
		port = ":" + p
	}

	wwwURL := scheme + "://" + wwwHost + port
	nonWwwURL := scheme + "://" + nonWwwHost + port

	// Check both URLs at once: in series a slow pair cost two timeouts.
	var wwwAnswer, nonWwwAnswer finalAnswer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); wwwAnswer = wwwFinalURL(ctx.reqContext(), wwwURL) }()
	go func() { defer wg.Done(); nonWwwAnswer = wwwFinalURL(ctx.reqContext(), nonWwwURL) }()
	wg.Wait()
	wwwFinal, wwwErr := wwwAnswer.url, wwwAnswer.err
	nonWwwFinal, nonWwwErr := nonWwwAnswer.url, nonWwwAnswer.err

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
		// Each name answers on its own host, with no redirect between
		// them. Resolving is not the same as serving: an unconfigured
		// vhost answers 404 or 5xx on a name that resolves fine.
		for _, side := range []struct {
			host   string
			answer finalAnswer
		}{{wwwHost, wwwAnswer}, {nonWwwHost, nonWwwAnswer}} {
			if blockedStatus(side.answer.status) {
				return inconclusiveResult(c, "the www redirect", fmt.Sprintf("%s %s", side.host, fetchFailure(side.answer.status))), nil
			}
		}
		for _, side := range []struct {
			host   string
			answer finalAnswer
		}{{wwwHost, wwwAnswer}, {nonWwwHost, nonWwwAnswer}} {
			if side.answer.status >= 400 {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityWarn,
					Passed:   false,
					Message:  fmt.Sprintf("%s resolves but answers HTTP %d instead of serving or redirecting", side.host, side.answer.status),
					Suggestions: []string{
						"Configure the web server or CDN to redirect this name to your canonical URL",
					},
				}, nil
			}
		}
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

// finalAnswer is where a request ended up after redirects, and the status
// of that last response.
type finalAnswer struct {
	url    string
	status int
	err    error
}

// wwwFinalURL is a variable so tests can stand in for the network; the safe
// client refuses the loopback addresses a test server listens on.
var wwwFinalURL = getFinalURL

func getFinalURL(ctx context.Context, urlStr string) finalAnswer {
	// This call starts with a user-configured URL and follows redirects;
	// SafeHTTPClient guards both the initial dial AND each redirect hop
	// against private / loopback / link-local addresses.
	client := netutil.SafeHTTPClient(10 * time.Second)

	answer := requestFinalURL(ctx, client, http.MethodHead, urlStr)
	// Some servers reject HEAD (405, 501) or answer it differently from
	// GET. Ask again with GET before believing an error status.
	if answer.err == nil && answer.status >= 400 {
		if retry := requestFinalURL(ctx, client, http.MethodGet, urlStr); retry.err == nil {
			return retry
		}
	}
	return answer
}

func requestFinalURL(ctx context.Context, client *http.Client, method, urlStr string) finalAnswer {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return finalAnswer{err: fmt.Errorf("build request for %s: %w", urlStr, err)}
	}
	req.Header.Set("User-Agent", "Preflight/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return finalAnswer{err: fmt.Errorf("%s %s: %w", method, urlStr, err)}
	}
	defer resp.Body.Close()

	return finalAnswer{url: resp.Request.URL.String(), status: resp.StatusCode}
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
