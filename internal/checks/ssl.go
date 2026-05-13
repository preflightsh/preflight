package checks

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  sanitizeTLSDialError(err),
		}, nil
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

	cert := certs[0]
	now := time.Now()

	// Check expiration
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	if now.After(cert.NotAfter) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityError,
			Passed:   false,
			Message:  "SSL certificate has expired",
			Suggestions: []string{
				"Renew your SSL certificate immediately",
			},
		}, nil
	}

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
		}, nil
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
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityInfo,
		Passed:   true,
		Message:  fmt.Sprintf("Valid, expires in %d days", daysUntilExpiry),
	}, nil
}

// sanitizeTLSDialError formats a dial/TLS error for the user-visible
// Message field without leaking internal hostnames learned from cert
// subjects back to the caller. Both x509.HostnameError and Go 1.20+'s
// tls.CertificateVerificationError can embed SANs in their string form.
func sanitizeTLSDialError(err error) string {
	if errors.Is(err, netutil.ErrPrivateAddress) {
		return "Refused to connect: production URL resolved to a private/loopback address"
	}
	var hostErr *x509.HostnameError
	if errors.As(err, &hostErr) {
		return "Certificate hostname mismatch"
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return "Certificate verification failed"
	}
	return fmt.Sprintf("Could not connect: %v", err)
}
