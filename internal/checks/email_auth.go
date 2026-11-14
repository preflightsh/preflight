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
	cfg := ctx.Config.Checks.EmailAuth
	if cfg == nil || !cfg.Enabled {
		return CheckResult{ID: c.ID(), Title: c.Title(), Skipped: true, Severity: SeverityInfo, Message: "Email authentication not enabled"}, nil
	}
	domain := cfg.Domain
	spfDomains := []string{domain}
	dmarcDomains := mailDomainCandidates(domain)
	note := ""
	if domain == "" {
		// Configs written before 0.24 have no domain key. v0.23 checked the
		// production URL's host and its organizational domain, and that is
		// still the best guess: most sites send mail from the domain they
		// serve. Say where the domain came from so a site that sends from
		// elsewhere knows how to point the check at it.
		host := productionHost(ctx.Config.URLs.Production)
		if host == "" {
			return CheckResult{ID: c.ID(), Title: c.Title(), Skipped: true, Severity: SeverityInfo, Message: "Skipped: set checks.emailAuth.domain to the email sending domain (there is no production URL to take it from)"}, nil
		}
		// A name on a hosting platform's shared suffix (myapp.vercel.app)
		// cannot hold the site's mail records, and its "organizational
		// domain" is the platform's, not the user's.
		if platformHost(host) {
			return CheckResult{ID: c.ID(), Title: c.Title(), Skipped: true, Severity: SeverityInfo, Message: "Skipped: " + host + " is a hosting platform subdomain; set checks.emailAuth.domain to the email sending domain"}, nil
		}
		spfDomains = mailDomainCandidates(host)
		dmarcDomains = spfDomains
		// The domain to name in advice is the organizational one, since
		// that's where a missing record belongs.
		domain = spfDomains[len(spfDomains)-1]
		note = " (domain from production URL; set checks.emailAuth.domain to choose it)"
	}
	hasSPF, spfRecord, spfDomain, spfErr := lookupFirst(spfDomains, func(d string) (bool, string, error) { return checkSPFContext(ctx.reqContext(), d) })
	hasDMARC, dmarcRecord, dmarcDomain, dmarcErr := lookupFirst(dmarcDomains, func(d string) (bool, string, error) { return checkDMARCContext(ctx.reqContext(), d) })

	// A record that exists but is malformed is a definite finding, not a
	// lookup problem: mail receivers treat two SPF records or a DMARC record
	// with no policy as no record at all. Reporting it as a DNS error told
	// the user to check their network connection.
	var spfBad, dmarcBad *invalidRecordError
	errors.As(spfErr, &spfBad)
	errors.As(dmarcErr, &dmarcBad)
	if spfBad != nil || dmarcBad != nil {
		var problems, suggestions []string
		switch {
		case spfBad != nil:
			problems = append(problems, fmt.Sprintf("SPF for %s: %s", spfDomain, spfBad.describe()))
			suggestions = append(suggestions, "Publish exactly one SPF record, for example: v=spf1 include:... ~all")
		case spfErr == nil && !hasSPF:
			problems = append(problems, "SPF missing")
			suggestions = append(suggestions, "Add SPF record: v=spf1 include:... ~all")
		}
		switch {
		case dmarcBad != nil:
			problems = append(problems, fmt.Sprintf("DMARC for %s: %s", dmarcDomain, dmarcBad.describe()))
			suggestions = append(suggestions, "Publish exactly one DMARC record at _dmarc."+domain+" with a p= policy of none, quarantine, or reject")
		case dmarcErr == nil && !hasDMARC:
			problems = append(problems, "DMARC missing")
			suggestions = append(suggestions, "Add DMARC record at _dmarc."+domain)
		}
		return CheckResult{
			ID:          c.ID(),
			Title:       c.Title(),
			Severity:    SeverityWarn,
			Passed:      false,
			Message:     "Invalid record: " + strings.Join(problems, "; ") + note,
			Suggestions: suggestions,
		}, nil
	}

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
			Message:      fmt.Sprintf("DNS lookup error for %s: %s", domain, strings.Join(errParts, "; ")) + note,
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
				Message:  fmt.Sprintf("SPF configured for %s, DMARC for %s", spfDomain, dmarcDomain) + note,
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  fmt.Sprintf("SPF and DMARC configured for %s", spfDomain) + note,
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
		Message:     fmt.Sprintf("Missing: %s for %s", strings.Join(missing, ", "), domain) + note,
		Suggestions: suggestions,
	}, nil
}

// productionHost returns the host of a production URL for the mail-domain
// fallback, or "" when there is none worth looking up (no URL, an IP
// literal, or a single-label host such as localhost).
func productionHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	return host
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

// txtLookup is the TXT resolver the SPF and DMARC checks use; tests swap it.
var txtLookup = lookupTXT

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
	records, err := txtLookup(ctx, domain)
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
			return false, "", &invalidRecordError{problem: "multiple SPF records", record: found}
		}
		found = record
	}
	if found == "" {
		return false, "", nil
	}
	invalid := func(problem string) (bool, string, error) {
		return false, "", &invalidRecordError{problem: problem, record: found}
	}
	fields := strings.Fields(found)
	if len(fields) < 2 {
		return invalid("SPF record has no mechanisms")
	}
	for _, field := range fields[1:] {
		qualified := strings.ToLower(field)
		field = strings.TrimLeft(qualified, "+-~?")
		name, argument, hasArg := strings.Cut(field, ":")
		if strings.Contains(name, "=") {
			k, v, _ := strings.Cut(name, "=")
			if v == "" || k == "" {
				return invalid("invalid SPF modifier " + field)
			}
			continue
		}
		switch name {
		case "all":
			if hasArg {
				return invalid("invalid SPF all mechanism")
			}
			// A bare "all" has the default "+" qualifier. Either way the
			// record authorizes every server on the internet to send as
			// this domain, which is the opposite of having SPF.
			if qualified == "all" || qualified == "+all" {
				return invalid("SPF record ends in " + qualified + ", which lets any server send as this domain")
			}
		case "include", "exists", "ip4", "ip6":
			if !hasArg || argument == "" {
				return invalid("SPF mechanism " + name + " is missing its argument")
			}
		case "a", "mx", "ptr":
		default:
			if !strings.HasPrefix(name, "a/") && !strings.HasPrefix(name, "mx/") {
				return invalid("unknown SPF mechanism " + name)
			}
		}
	}
	return true, found, nil
}

// invalidRecordError is a record that exists and is wrong, as opposed to a
// lookup that failed. The two need different results: this one is a finding.
type invalidRecordError struct {
	problem string
	record  string
}

func (e *invalidRecordError) Error() string { return e.problem }

// describe is the problem followed by the record, shortened and kept to one
// line for the result message.
func (e *invalidRecordError) describe() string {
	record := strings.Join(strings.Fields(e.record), " ")
	if record == "" {
		return e.problem
	}
	return fmt.Sprintf("%s (%s)", e.problem, truncate(record, 80))
}
func checkDMARCContext(ctx context.Context, domain string) (bool, string, error) {
	records, err := txtLookup(ctx, "_dmarc."+domain)
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
		// The version tag may be written with spaces around "=", and tag
		// names and policy values are case-insensitive (RFC 7489).
		if len(tags) == 0 || !strings.EqualFold(strings.Join(strings.Fields(tags[0]), ""), "v=DMARC1") {
			continue
		}
		if found != "" {
			return false, "", &invalidRecordError{problem: "multiple DMARC records", record: found}
		}
		policy := ""
		seen := map[string]bool{}
		for _, tag := range tags[1:] {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			k, v, ok := strings.Cut(tag, "=")
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			if !ok || seen[k] {
				return false, "", &invalidRecordError{problem: "invalid or duplicate DMARC tag " + k, record: record}
			}
			seen[k] = true
			if k == "p" {
				policy = strings.ToLower(v)
			}
		}
		if policy != "none" && policy != "quarantine" && policy != "reject" {
			return false, "", &invalidRecordError{problem: "DMARC record has no valid p= policy", record: record}
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
