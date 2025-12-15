package checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
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

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{})
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("Could not connect: %v", err),
		}, nil
	}
	defer conn.Close()

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
