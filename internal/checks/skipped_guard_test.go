package checks

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/config"
)

// allChecksForGuard is every check the scan can run, core and service.
func allChecksForGuard() []Check {
	all := []Check{
		SEOMetadataCheck{}, CanonicalURLCheck{}, OGTwitterCheck{}, ViewportCheck{},
		LangAttributeCheck{}, StructuredDataCheck{}, IndexNowCheck{},
		SecurityHeadersCheck{}, SSLCheck{}, WWWRedirectCheck{}, EmailAuthCheck{},
		SecretScanCheck{}, EnvParityCheck{}, HealthCheck{}, StripeWebhookCheck{},
		VulnerabilityCheck{}, DebugStatementsCheck{}, ErrorPagesCheck{},
		ImageOptimizationCheck{}, LegalPagesCheck{}, FaviconCheck{},
		RobotsTxtCheck{}, SitemapCheck{}, LLMsTxtCheck{}, AdsTxtCheck{},
		HumansTxtCheck{}, LicenseCheck{},
	}
	ids := make([]string, 0, len(ServiceChecks))
	for id := range ServiceChecks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		all = append(all, ServiceChecks[id])
	}
	return all
}

// skipContractViolation is the rule the JSON contract relies on now that
// the scan no longer guesses Skipped from message text: a check that did
// not apply says so with Skipped, never with a passing result whose message
// happens to mention skipping, and a skipped check never also passes. It
// returns "" when r keeps the rule.
func skipContractViolation(r CheckResult) string {
	if r.Skipped && r.Passed {
		return "both skipped and passed"
	}
	msg := strings.ToLower(r.Message)
	for _, w := range []string{"skipping", "skipped", "not declared", "not enabled", "not configured"} {
		if r.Passed && !r.Skipped && strings.Contains(msg, w) {
			return "passed with a skip message (" + w + ") but Skipped is unset"
		}
	}
	return ""
}

func assertSkipContract(t *testing.T, label string, r CheckResult) {
	t.Helper()
	if v := skipContractViolation(r); v != "" {
		t.Errorf("%s: %s %s: %q", label, r.ID, v, r.Message)
	}
}

// TestSkippedResultsAreExplicit runs every check against projects where
// most of them have nothing to do (nothing declared, no layout, no URLs,
// local and unreachable URLs, a subdomain) and holds each result to the
// skip contract. It also pins the skips the old message heuristic used to
// produce, so none of them quietly turns back into a pass.
func TestSkippedResultsAreExplicit(t *testing.T) {
	unreachable := "http://127.0.0.1:1"
	client := &http.Client{Timeout: 2 * time.Second}
	cases := []struct {
		name        string
		cfg         *config.PreflightConfig
		fetch       bool
		only        []Check
		wantSkipped []string
	}{
		{
			name: "empty project, empty config",
			cfg:  &config.PreflightConfig{},
			wantSkipped: []string{
				"seo_meta", "canonical", "og_twitter", "viewport", "lang",
				"security_headers", "ssl", "www_redirect", "email_auth",
				"env_parity", "health_endpoint", "stripe", "vulnerability",
				"index_now", "ads_txt", "humans_txt",
				"sentry", "plausible", "fathom", "google_analytics", "redis",
				"sidekiq", "postmark", "sendgrid", "mailgun", "resend",
				"aws_ses", "cookiebot", "onetrust", "termly", "cookieyes",
				"iubenda", "openai", "algolia",
			},
		},
		{
			name: "opt-ins enabled, local unreachable URL",
			cfg: &config.PreflightConfig{
				URLs: config.URLConfig{Production: unreachable},
				Checks: config.ChecksConfig{
					EnvParity:      &config.EnvParityConfig{Enabled: true, EnvFile: ".env", ExampleFile: ".env.example"},
					HealthEndpoint: &config.HealthEndpointConfig{Enabled: true, Path: "/health"},
					StripeWebhook:  &config.StripeWebhookConfig{Enabled: true},
					Security:       &config.SecurityConfig{Enabled: true},
					Secrets:        &config.SecretsConfig{Enabled: true},
					AdsTxt:         &config.AdsTxtConfig{Enabled: true},
					HumansTxt:      &config.HumansTxtConfig{Enabled: true},
					License:        &config.LicenseConfig{Enabled: true},
				},
			},
			fetch:       true,
			wantSkipped: []string{"ssl", "www_redirect", "env_parity", "vulnerability", "stripe"},
		},
		{
			name:        "subdomain production URL",
			cfg:         &config.PreflightConfig{URLs: config.URLConfig{Production: "https://app.example.com"}},
			only:        []Check{WWWRedirectCheck{}},
			wantSkipped: []string{"www_redirect"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := Context{RootDir: t.TempDir(), Config: tc.cfg, Client: client}
			if tc.fetch {
				ctx.PageFetchProduction = PageFetch{URL: tc.cfg.URLs.Production}
			}
			list := tc.only
			if list == nil {
				list = allChecksForGuard()
			}
			got := map[string]CheckResult{}
			for _, c := range list {
				r, err := c.Run(ctx)
				if err != nil {
					t.Fatalf("%s: %v", c.ID(), err)
				}
				assertSkipContract(t, tc.name, r)
				got[c.ID()] = r
			}
			for _, id := range tc.wantSkipped {
				r, ok := got[id]
				if !ok {
					t.Errorf("%s did not run", id)
					continue
				}
				if !r.Skipped {
					t.Errorf("%s: want Skipped, got passed=%v %q", id, r.Passed, r.Message)
				}
			}
		})
	}
}

// TestSkipContractFlagsTextOnlySkips keeps the guard honest: it must
// reject a pass that only says it skipped and a result that is both.
func TestSkipContractFlagsTextOnlySkips(t *testing.T) {
	for _, r := range []CheckResult{
		{ID: "x", Passed: true, Message: "Acme not declared, skipping"},
		{ID: "x", Passed: true, Message: "2 files skipped"},
		{ID: "x", Passed: true, Skipped: true, Message: "Skipped for local URL"},
	} {
		if skipContractViolation(r) == "" {
			t.Errorf("guard accepted %+v", r)
		}
	}
	if v := skipContractViolation(CheckResult{ID: "x", Skipped: true, Message: "Skipped for local URL"}); v != "" {
		t.Errorf("guard rejected a proper skip: %s", v)
	}
}
