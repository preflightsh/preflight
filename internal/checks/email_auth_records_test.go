package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func emailAuthRun(t *testing.T, records map[string][]string) CheckResult {
	t.Helper()
	fakeTXT(t, records)
	cfg := &config.PreflightConfig{Checks: config.ChecksConfig{EmailAuth: &config.EmailAuthConfig{Enabled: true, Domain: "example.com"}}}
	res, err := EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A record that exists and is wrong is a finding. These all used to read
// "DNS lookup error ... Check your network connection", flagged
// inconclusive.
func TestEmailAuthMalformedRecordsAreFindings(t *testing.T) {
	goodDMARC := []string{"v=DMARC1; p=reject"}
	goodSPF := []string{"v=spf1 include:_spf.example.net ~all"}
	cases := []struct {
		name    string
		records map[string][]string
		want    string
	}{
		{"two SPF records", map[string][]string{"example.com": {"v=spf1 -all", "v=spf1 include:a.example ~all"}, "_dmarc.example.com": goodDMARC}, "multiple SPF records"},
		{"misspelled mechanism", map[string][]string{"example.com": {"v=spf1 inlcude:_spf.example.net ~all"}, "_dmarc.example.com": goodDMARC}, "unknown SPF mechanism inlcude"},
		{"bare SPF version", map[string][]string{"example.com": {"v=spf1"}, "_dmarc.example.com": goodDMARC}, "no mechanisms"},
		{"SPF that allows everyone", map[string][]string{"example.com": {"v=spf1 +all"}, "_dmarc.example.com": goodDMARC}, "lets any server send"},
		{"DMARC without a policy", map[string][]string{"example.com": goodSPF, "_dmarc.example.com": {"v=DMARC1; rua=mailto:d@example.com"}}, "no valid p= policy"},
		{"two DMARC records", map[string][]string{"example.com": goodSPF, "_dmarc.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"}}, "multiple DMARC records"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := emailAuthRun(t, tc.records)
			if res.Passed || res.Inconclusive || res.Severity != SeverityWarn {
				t.Fatalf("passed=%v inconclusive=%v severity=%s msg=%q", res.Passed, res.Inconclusive, res.Severity, res.Message)
			}
			if !strings.Contains(res.Message, tc.want) || strings.Contains(res.Message, "DNS lookup error") {
				t.Errorf("message = %q, want it to say %q", res.Message, tc.want)
			}
			if strings.Contains(res.Message, "\n") {
				t.Errorf("message must stay on one line: %q", res.Message)
			}
			for _, s := range res.Suggestions {
				if strings.Contains(s, "network connection") {
					t.Errorf("a malformed record is not a network problem: %q", s)
				}
			}
		})
	}
}

// Tag names and policy values are case-insensitive, and the version tag may
// have spaces around the equals sign.
func TestEmailAuthDMARCSpelling(t *testing.T) {
	for _, record := range []string{"v=DMARC1; p=Reject", "v = DMARC1; p=quarantine", "v=DMARC1; P=NONE", "v=dmarc1;p=reject"} {
		res := emailAuthRun(t, map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {record}})
		if !res.Passed {
			t.Errorf("%q: %q", record, res.Message)
		}
	}
}

// One malformed record must not hide that the other one is missing.
func TestEmailAuthInvalidAndMissing(t *testing.T) {
	res := emailAuthRun(t, map[string][]string{"example.com": {"v=spf1 +all"}})
	if !strings.Contains(res.Message, "DMARC missing") || !strings.Contains(res.Message, "lets any server send") {
		t.Errorf("message = %q", res.Message)
	}
}

// A hosting platform subdomain cannot carry the site's mail records.
func TestEmailAuthSkipsPlatformSubdomainFallback(t *testing.T) {
	asked := fakeTXT(t, nil)
	cfg := &config.PreflightConfig{
		URLs:   config.URLConfig{Production: "https://myapp.vercel.app"},
		Checks: config.ChecksConfig{EmailAuth: &config.EmailAuthConfig{Enabled: true}},
	}
	res, _ := EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if !res.Skipped || res.Passed || !strings.Contains(res.Message, "checks.emailAuth.domain") {
		t.Errorf("got %+v", res)
	}
	if len(*asked) != 0 {
		t.Errorf("no lookups expected, got %q", *asked)
	}
}
