package checks

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
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

	if parsedURL.Scheme != "https" {
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

	host := parsedURL.Host
	if parsedURL.Port() == "" {
		host += ":443"
	}

	conn, err := netutil.SafeTLSDial("tcp", host, &tls.Config{
		MinVersion: tls.VersionTLS12,
	}, 10*time.Second)
	if err != nil {
		return c.classifyDialError(ctx, host, err), nil
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
		}, nil
	}

	return c.expiryResult(certs[0]), nil
}

// expiryResult grades a certificate that verified: failing hard inside a
// week of expiry, warning inside a month.
func (c SSLCheck) expiryResult(cert *x509.Certificate) CheckResult {
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	if daysUntilExpiry <= 7 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityError,
			Passed:   false,
			Message:  fmt.Sprintf("SSL certificate expires in %d days", daysUntilExpiry),
			Suggestions: []string{
				"Renew your SSL certificate soon",
				"Consider enabling auto-renewal",
			},
		}
	}

	if daysUntilExpiry <= 30 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("SSL certificate expires in %d days", daysUntilExpiry),
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
		Message:  fmt.Sprintf("Valid, expires in %d days", daysUntilExpiry),
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
func (c SSLCheck) classifyDialError(ctx Context, host string, err error) CheckResult {
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
	if leaf := peekLeafCertificate(host); leaf != nil {
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
func peekLeafCertificate(host string) *x509.Certificate {
	conn, err := netutil.SafeTLSDial("tcp", host, &tls.Config{
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
