package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/preflightsh/preflight/internal/netutil"
)

type SSLCheck struct{}

func (c SSLCheck) ID() string {
	return "ssl"
}

func (c SSLCheck) Title() string {
	return "SSL certificate"
}

func (c SSLCheck) Run(ctx Context) (CheckResult, error) {
	if ctx.Config.URLs.Production == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "No production URL configured",
		}, nil
	}

	// A local dev URL has no public certificate to check. Skip it the same
	// way www_redirect does, using IsLocalURL so both agree on what is local.
	if IsLocalURL(ctx.Config.URLs.Production) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Skipped for local URL",
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

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		// "example.com" parses as a bare path. Saying the site doesn't use
		// HTTPS would be wrong; the config is missing the scheme.
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Production URL has no scheme: " + ctx.Config.URLs.Production,
			Suggestions: []string{
				"Write the production URL in preflight.yml with its scheme, e.g. https://" + strings.TrimPrefix(ctx.Config.URLs.Production, "//"),
			},
		}, nil
	}

	if parsedURL.Scheme != "https" {
		// A production URL written with http:// usually belongs to a site
		// that redirects to HTTPS. Failing it without a request told those
		// users to go and get a certificate they already had.
		if upgraded := sslHTTPSUpgrade(ctx, parsedURL); upgraded != nil {
			return c.plainHTTPResult(ctx, upgraded), nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityError,
			Passed:   false,
			Message:  "Production URL does not use HTTPS",
			Suggestions: []string{
				"Use HTTPS for your production site",
				"Get a free SSL certificate from Let's Encrypt",
			},
		}, nil
	}

	return sslGradeHost(c, ctx, parsedURL), nil
}

// sslGradeHost and sslHTTPSUpgrade are variables so tests can stand in for
// the network: SafeTLSDial refuses loopback, so no test listener can serve
// either of them.
var (
	sslGradeHost    = SSLCheck.gradeHost
	sslHTTPSUpgrade = httpsUpgradeTarget
)

// gradeHost handshakes with the host of an https URL and grades the
// certificate it presents.
func (c SSLCheck) gradeHost(ctx Context, u *url.URL) CheckResult {
	host := u.Host
	if u.Port() == "" {
		host += ":443"
	}

	conn, err := netutil.SafeTLSDialContext(ctx.reqContext(), "tcp", host, &tls.Config{
		MinVersion: tls.VersionTLS12,
	}, 10*time.Second)
	if err != nil {
		return c.classifyDialErrorContext(ctx.reqContext(), host, err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityError,
			Passed:   false,
			Message:  "No SSL certificate found",
		}
	}

	return c.expiryResult(certs[0])
}

// httpsUpgradeTarget requests an http:// production URL and returns where it
// ended up when that is an https URL on the same site. It returns nil when
// the site does not redirect to HTTPS, redirects somewhere else, or could
// not be reached.
func httpsUpgradeTarget(ctx Context, u *url.URL) *url.URL {
	if ctx.Client == nil {
		return nil
	}
	resp, err := doGet(ctx.reqContext(), ctx.Client, u.String())
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	final := resp.Request.URL
	if final == nil || final.Scheme != "https" || !sameSite(u.Hostname(), final.Hostname()) {
		return nil
	}
	return final
}

// plainHTTPResult grades the certificate behind an http:// production URL
// that redirects to HTTPS. A good certificate is still a warning, because
// the configured URL is the one every other check requests.
func (c SSLCheck) plainHTTPResult(ctx Context, upgraded *url.URL) CheckResult {
	res := sslGradeHost(c, ctx, upgraded)
	fix := "Write the production URL in preflight.yml with https://"
	if !res.Passed {
		res.Message += " (production URL is written with http:// and redirects to HTTPS)"
		res.Suggestions = append(res.Suggestions, fix)
		return res
	}
	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     "Production URL is written with http:// but redirects to HTTPS (" + lowerFirst(res.Message) + ")",
		Suggestions: []string{fix},
	}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// Certificates used to live for a year or more, so "a week left" and "a
// month left" meant renewal had failed. Lifetimes are now as short as six
// days, and a certificate that is renewed on schedule spends its whole life
// inside those windows. The thresholds scale with the lifetime instead, and
// the old absolute windows stay as the ceiling for long-lived certificates.
const (
	sslErrorWindow = 7 * 24 * time.Hour
	sslWarnWindow  = 30 * 24 * time.Hour
)

// expiryThresholds returns how much remaining validity is an error and how
// much is a warning for a certificate with the given lifetime: under a tenth
// of the lifetime is an error and under a third is a warning.
func expiryThresholds(lifetime time.Duration) (errorBelow, warnBelow time.Duration) {
	errorBelow, warnBelow = sslErrorWindow, sslWarnWindow
	if lifetime <= 0 {
		return errorBelow, warnBelow
	}
	if scaled := lifetime / 10; scaled < errorBelow {
		errorBelow = scaled
	}
	if scaled := lifetime / 3; scaled < warnBelow {
		warnBelow = scaled
	}
	return errorBelow, warnBelow
}

// expiresIn words the time left, in hours once it is under two days so a
// short-lived certificate does not read as "expires in 0 days".
func expiresIn(remaining time.Duration) string {
	if remaining < 48*time.Hour {
		return fmt.Sprintf("%d hours", int(remaining.Hours()))
	}
	return fmt.Sprintf("%d days", int(math.Round(remaining.Hours()/24)))
}

// expiryResult grades a certificate that verified: an error when it is
// close enough to expiry that renewal has clearly failed, a warning when
// renewal is overdue.
func (c SSLCheck) expiryResult(cert *x509.Certificate) CheckResult {
	remaining := time.Until(cert.NotAfter)
	errorBelow, warnBelow := expiryThresholds(cert.NotAfter.Sub(cert.NotBefore))

	if remaining <= errorBelow {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityError,
			Passed:   false,
			Message:  "SSL certificate expires in " + expiresIn(remaining),
			Suggestions: []string{
				"Renew your SSL certificate soon",
				"Consider enabling auto-renewal",
			},
		}
	}

	if remaining <= warnBelow {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "SSL certificate expires in " + expiresIn(remaining),
			Suggestions: []string{
				"Plan to renew your SSL certificate",
			},
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityInfo,
		Passed:   true,
		Message:  "Valid, expires in " + expiresIn(remaining),
	}
}

// classifyDialError turns a failed handshake into a result. A certificate
// the handshake rejected is an error, not a warning: an expired or
// self-signed cert on the production URL means browsers show an
// interstitial, which is as launch-blocking as it gets.
//
// The handshake fails before the certificate can be inspected, so the
// expired/mismatch/untrusted distinction comes from a second dial with
// verification disabled. That dial still goes through SafeTLSDial (so it
// can't be pointed at a private address) and nothing is sent over it; the
// leaf is read and the connection closed.
func (c SSLCheck) classifyDialError(host string, err error) CheckResult {
	return c.classifyDialErrorContext(context.Background(), host, err)
}

func (c SSLCheck) classifyDialErrorContext(ctx context.Context, host string, err error) CheckResult {
	if errors.Is(err, netutil.ErrPrivateAddress) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Refused to connect: production URL resolved to a private/loopback address",
		}
	}
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(err, &verifyErr) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("Could not connect: %v", err),
		}
	}

	message, suggestions := "Certificate verification failed", []string{"Check the certificate installed on your production host"}
	if leaf := peekLeafCertificateContext(ctx, host); leaf != nil {
		now := time.Now()
		hostname, _, _ := net.SplitHostPort(host)
		switch {
		case now.After(leaf.NotAfter):
			message = fmt.Sprintf("SSL certificate expired %d days ago", int(now.Sub(leaf.NotAfter).Hours()/24))
			suggestions = []string{"Renew your SSL certificate immediately"}
		case now.Before(leaf.NotBefore):
			message = "SSL certificate is not valid yet"
			suggestions = []string{"Check the clock on the host that issued the certificate"}
		case leaf.VerifyHostname(hostname) != nil:
			// Deliberately not naming the SANs on the cert, which can
			// reveal internal hostnames.
			message = "Certificate hostname mismatch"
			suggestions = []string{"Issue a certificate that covers " + hostname}
		default:
			message = "Certificate is not trusted (self-signed or unknown issuer)"
			suggestions = []string{"Use a certificate from a trusted CA such as Let's Encrypt"}
		}
	}
	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityError,
		Passed:      false,
		Message:     message,
		Suggestions: suggestions,
	}
}

// peekLeafCertificate fetches the leaf certificate a host presents without
// verifying it. Returns nil when the host cannot be reached at all.
func peekLeafCertificateContext(ctx context.Context, host string) *x509.Certificate {
	conn, err := netutil.SafeTLSDialContext(ctx, "tcp", host, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // read-only peek to classify a cert the verified dial already rejected
	}, 10*time.Second)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}
