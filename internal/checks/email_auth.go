package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	cfg := ctx.Config.Checks.EmailAuth
	if cfg == nil || !cfg.Enabled {
		return CheckResult{ID: c.ID(), Title: c.Title(), Skipped: true, Severity: SeverityInfo, Message: "Email authentication not enabled"}, nil
	}
	domain := cfg.Domain
	if domain == "" {
		return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityWarn, Inconclusive: true, Message: "Set emailAuth.domain to the email sending domain; website URLs are not mail identities"}, nil
	}
	hasSPF, spfRecord, spfErr := checkSPFContext(ctx.reqContext(), domain)
	spfDomain := domain
	hasDMARC, dmarcRecord, dmarcDomain, dmarcErr := lookupFirst(mailDomainCandidates(domain), func(d string) (bool, string, error) { return checkDMARCContext(ctx.reqContext(), d) })

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
			Inconclusive: true,
			ID:           c.ID(),
			Title:        c.Title(),
			Severity:     SeverityWarn,
			Passed:       false,
			Message:      fmt.Sprintf("DNS lookup error for %s: %s", domain, strings.Join(errParts, "; ")),
			Suggestions: []string{
				"Check your network connection and DNS resolver",
				"Verify checks.emailAuth.domain is the email sending domain",
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
// the first hit along with the domain it was found on. Only an absent record
// permits organizational-domain fallback; errors or malformed child records
// must not be hidden by a valid parent record.
func lookupFirst(domains []string, lookup func(string) (bool, string, error)) (found bool, record, domain string, err error) {
	for _, d := range domains {
		ok, rec, lookupErr := lookup(d)
		if lookupErr != nil {
			return false, "", d, lookupErr
		}
		if ok {
			return true, rec, d, nil
		}
	}
	return false, "", "", nil
}

const fallbackDNSServer = "1.1.1.1:53"

func lookupTXT(parent context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
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
	fbCtx, fbCancel := context.WithTimeout(parent, 5*time.Second)
	defer fbCancel()
	return fallback.LookupTXT(fbCtx, name)
}

func checkSPFContext(ctx context.Context, domain string) (bool, string, error) {
	records, err := lookupTXT(ctx, domain)
	return evaluateSPF(records, err)
}
func evaluateSPF(records []string, err error) (bool, string, error) {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", nil
		}
		return false, "", err
	}
	found := ""
	for _, record := range records {
		fields := strings.Fields(record)
		if len(fields) == 0 || strings.ToLower(fields[0]) != "v=spf1" {
			continue
		}
		if found != "" {
			return false, "", fmt.Errorf("multiple SPF records")
		}
		found = record
	}
	if found == "" {
		return false, "", nil
	}
	fields := strings.Fields(found)
	if len(fields) < 2 {
		return false, "", fmt.Errorf("SPF record has no mechanisms")
	}
	for _, field := range fields[1:] {
		field = strings.TrimLeft(strings.ToLower(field), "+-~?")
		name, argument, hasArg := strings.Cut(field, ":")
		if strings.Contains(name, "=") {
			k, v, _ := strings.Cut(name, "=")
			if v == "" || k == "" {
				return false, "", fmt.Errorf("invalid SPF modifier")
			}
			continue
		}
		switch name {
		case "all":
			if hasArg {
				return false, "", fmt.Errorf("invalid SPF all mechanism")
			}
		case "include", "exists", "ip4", "ip6":
			if !hasArg || argument == "" {
				return false, "", fmt.Errorf("SPF mechanism missing argument")
			}
		case "a", "mx", "ptr":
		default:
			if !strings.HasPrefix(name, "a/") && !strings.HasPrefix(name, "mx/") {
				return false, "", fmt.Errorf("unknown SPF mechanism")
			}
		}
	}
	return true, found, nil
}
func checkDMARCContext(ctx context.Context, domain string) (bool, string, error) {
	records, err := lookupTXT(ctx, "_dmarc."+domain)
	return evaluateDMARC(records, err)
}
func evaluateDMARC(records []string, err error) (bool, string, error) {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", nil
		}
		return false, "", err
	}
	found := ""
	for _, record := range records {
		tags := strings.Split(record, ";")
		if len(tags) == 0 || !strings.EqualFold(strings.TrimSpace(tags[0]), "v=DMARC1") {
			continue
		}
		if found != "" {
			return false, "", fmt.Errorf("multiple DMARC records")
		}
		policy := ""
		seen := map[string]bool{}
		for _, tag := range tags[1:] {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			k, v, ok := strings.Cut(tag, "=")
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if !ok || seen[k] {
				return false, "", fmt.Errorf("invalid or duplicate DMARC tag")
			}
			seen[k] = true
			if k == "p" {
				policy = v
			}
		}
		if policy != "none" && policy != "quarantine" && policy != "reject" {
			return false, "", fmt.Errorf("DMARC record missing valid p policy")
		}
		found = record
	}
	return found != "", found, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
