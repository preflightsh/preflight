package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type EmailAuthCheck struct{}

func (c EmailAuthCheck) ID() string {
	return "email_auth"
}

func (c EmailAuthCheck) Title() string {
	return "Email authentication (SPF/DMARC)"
}

func (c EmailAuthCheck) Run(ctx Context) (CheckResult, error) {
	if ctx.Config.URLs.Production == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Skipped (no production URL)",
		}, nil
	}

	host, err := extractDomain(ctx.Config.URLs.Production)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Skipped (could not parse domain)",
		}, nil
	}

	// Mail authentication lives on the organizational domain: www.example.com
	// is usually a CNAME with no TXT records of its own while example.com
	// carries the SPF and DMARC records. DMARC mandates this fallback (RFC
	// 7489 section 6.6.3), so checking only the host would report a domain
	// with p=reject as unprotected.
	domains := mailDomainCandidates(host)
	// The domain to name in advice is the organizational one, since that's
	// where a missing record belongs.
	domain := domains[len(domains)-1]

	hasSPF, spfRecord, spfDomain, spfErr := lookupFirst(domains, checkSPF)
	hasDMARC, dmarcRecord, dmarcDomain, dmarcErr := lookupFirst(domains, checkDMARC)

	// If DNS lookups failed, report the error instead of claiming records are missing
	if spfErr != nil || dmarcErr != nil {
		var errParts []string
		if spfErr != nil {
			errParts = append(errParts, fmt.Sprintf("SPF lookup failed: %v", spfErr))
		}
		if dmarcErr != nil {
			errParts = append(errParts, fmt.Sprintf("DMARC lookup failed: %v", dmarcErr))
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("DNS lookup error for %s: %s", domain, strings.Join(errParts, "; ")),
			Suggestions: []string{
				"Check your network connection and DNS resolver",
				"Verify the domain is correct in your production URL",
			},
		}, nil
	}

	var missing []string
	if !hasSPF {
		missing = append(missing, "SPF")
	}
	if !hasDMARC {
		missing = append(missing, "DMARC")
	}

	if len(missing) == 0 {
		if spfDomain != dmarcDomain {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  fmt.Sprintf("SPF configured for %s, DMARC for %s", spfDomain, dmarcDomain),
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  fmt.Sprintf("SPF and DMARC configured for %s", spfDomain),
		}, nil
	}

	var suggestions []string
	if !hasSPF {
		suggestions = append(suggestions, "Add SPF record: v=spf1 include:... ~all")
	} else {
		suggestions = append(suggestions, fmt.Sprintf("SPF: %s", truncate(spfRecord, 60)))
	}
	if !hasDMARC {
		suggestions = append(suggestions, "Add DMARC record at _dmarc."+domain)
	} else {
		suggestions = append(suggestions, fmt.Sprintf("DMARC: %s", truncate(dmarcRecord, 60)))
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")),
		Suggestions: suggestions,
	}, nil
}

// mailDomainCandidates lists the domains to try for a host, most specific
// first: the host itself, then its organizational domain when that differs.
// Always returns at least one entry.
func mailDomainCandidates(host string) []string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return []string{host}
	}
	candidates := []string{host}
	// EffectiveTLDPlusOne fails on hosts with no registrable domain (bare
	// TLDs, "localhost", IP literals); the host is all we have then.
	if org, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && org != host {
		candidates = append(candidates, org)
	}
	return candidates
}

// lookupFirst runs a record lookup down the candidate domains and returns
// the first hit along with the domain it was found on. An error is only
// reported when no candidate produced a record, so a resolver hiccup on a
// subdomain can't mask a record that exists on the parent.
func lookupFirst(domains []string, lookup func(string) (bool, string, error)) (found bool, record, domain string, err error) {
	var lastErr error
	for _, d := range domains {
		ok, rec, lookupErr := lookup(d)
		if lookupErr != nil {
			lastErr = lookupErr
			continue
		}
		if ok {
			return true, rec, d, nil
		}
	}
	return false, "", "", lastErr
}

func extractDomain(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", rawURL, err)
	}
	return parsed.Hostname(), nil
}

const fallbackDNSServer = "1.1.1.1:53"

func dnsLookupTXT(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err == nil {
		return records, nil
	}
	// Domain or record does not exist. Return nil so callers can't
	// accidentally consume a partial slice alongside the non-nil error.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil, err
	}

	// System resolver failed (timeout, refused, server error). Retry against
	// a public resolver so a flaky local resolver doesn't produce false WARNs.
	fallback := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, fallbackDNSServer)
		},
	}
	fbCtx, fbCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fbCancel()
	return fallback.LookupTXT(fbCtx, name)
}

func checkSPF(domain string) (bool, string, error) {
	records, err := dnsLookupTXT(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", nil
		}
		return false, "", err
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			return true, record, nil
		}
	}
	return false, "", nil
}

func checkDMARC(domain string) (bool, string, error) {
	records, err := dnsLookupTXT("_dmarc." + domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", nil
		}
		return false, "", err
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			return true, record, nil
		}
	}
	return false, "", nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
