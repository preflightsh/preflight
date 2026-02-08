package checks

import (
	"fmt"
	"net"
	"net/url"
	"strings"
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

	domain, err := extractDomain(ctx.Config.URLs.Production)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Skipped (could not parse domain)",
		}, nil
	}

	hasSPF, spfRecord, spfErr := checkSPF(domain)
	hasDMARC, dmarcRecord, dmarcErr := checkDMARC(domain)

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
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  fmt.Sprintf("SPF and DMARC configured for %s", domain),
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

func extractDomain(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

func checkSPF(domain string) (bool, string, error) {
	records, err := net.LookupTXT(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
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
	records, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
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
