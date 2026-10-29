package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"gopkg.in/yaml.v3"
)

func TestPublishPrivacyBoundary(t *testing.T) {
	cfg := &config.PreflightConfig{ProjectName: "demo", Stack: "go", URLs: config.URLConfig{Staging: "https://user:password@example.com/private-token?token=query-token#fragment-token"}, Checks: config.ChecksConfig{
		IndexNow: &config.IndexNowConfig{Key: "private-key"}, StripeWebhook: &config.StripeWebhookConfig{URL: "https://example.com/webhook-secret"}, Secrets: &config.SecretsConfig{Allowlist: []config.SecretAllowlistEntry{{Path: "secret-path", Fingerprint: "secret-fingerprint"}}}, EnvParity: &config.EnvParityConfig{EnvFile: "env-secret-path"}, SEOMeta: &config.SEOMetaConfig{MainLayout: "layout-secret-path"},
	}}
	before, _ := json.Marshal(cfg)
	published := redactedConfigYAML(cfg)
	for _, secret := range []string{"password", "private-token", "query-token", "fragment-token", "private-key", "webhook-secret", "secret-path", "secret-fingerprint"} {
		if strings.Contains(published, secret) {
			t.Errorf("published config contains %q", secret)
		}
	}
	var out config.PreflightConfig
	if err := yaml.Unmarshal([]byte(published), &out); err != nil {
		t.Fatal(err)
	}
	if out.URLs.Staging != "https://example.com" {
		t.Fatalf("URL = %q", out.URLs.Staging)
	}
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(before, after) {
		t.Fatal("redaction mutated source config")
	}
	results := []checks.CheckResult{{ID: "health_endpoint", Message: "https://user:password@example.com/?token=query-token"}, {ID: "vulnerability", Message: "tool output secret-value"}, {ID: "secrets", Message: "secret-value"}}
	encoded, _ := json.Marshal(redactChecks(results))
	for _, secret := range []string{"password", "query-token", "secret-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("published results contain %q", secret)
		}
	}
}

func TestExplicitCheckDisableAndMailEnablement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html/>"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.PreflightConfig{Stack: "static", URLs: config.URLConfig{Production: "https://example.com"}, Checks: config.ChecksConfig{SEOMeta: &config.SEOMetaConfig{EnabledSet: true}, HealthEndpoint: &config.HealthEndpointConfig{EnabledSet: true}}}
	for _, c := range buildEnabledChecks(cfg, dir) {
		if c.ID() == "seo_meta" || c.ID() == "health_endpoint" {
			t.Fatalf("disabled %s ran", c.ID())
		}
	}
	cfg.URLs.Production = ""
	cfg.Checks.EmailAuth = &config.EmailAuthConfig{Enabled: true, Domain: "mail.example.com"}
	found := false
	for _, c := range buildEnabledChecks(cfg, dir) {
		if c.ID() == "email_auth" {
			found = true
		}
	}
	if !found {
		t.Fatal("mail authentication depends on a website URL")
	}
}

type failingReportWriter struct{}

func (failingReportWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestScanOutputFailure(t *testing.T) {
	dir := scanProject(t, "projectName: test\nchecks:\n  license:\n    enabled: true\n")
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("MIT license"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"human", "json"} {
		t.Run(format, func(t *testing.T) {
			code, err := executeScan(context.Background(), scanOptions{ProjectDir: dir, CI: true, Format: format, Quiet: true, Only: []string{"license"}}, failingReportWriter{}, io.Discard)
			if code != ExitFail || err == nil {
				t.Fatalf("code=%d err=%v", code, err)
			}
		})
	}
}

func TestUnverifiedResultsDoNotExitSuccessfully(t *testing.T) {
	cases := []struct {
		name   string
		result checks.CheckResult
	}{{"skipped", checks.CheckResult{Skipped: true, Severity: checks.SeverityInfo}}, {"inconclusive", checks.CheckResult{Inconclusive: true, Severity: checks.SeverityWarn}}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if determineExitCode([]checks.CheckResult{tc.result}) != ExitWarn {
				t.Fatal("unverified-only scan succeeded")
			}
		})
	}
}

func TestIncompleteScanPreservesDetectedError(t *testing.T) {
	r := checks.CheckResult{Severity: checks.SeverityError, Inconclusive: true, Message: "Secret found, another file unreadable"}
	if determineExitCode([]checks.CheckResult{r}) != ExitFail {
		t.Fatal("incomplete scanning downgraded a detected error")
	}
}
