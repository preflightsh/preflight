package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "preflight.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadAppliesDefaults(t *testing.T) {
	dir := writeConfig(t, "projectName: demo\nchecks:\n  healthEndpoint:\n    enabled: true\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Stack != "unknown" {
		t.Errorf("Stack = %q, want unknown default", cfg.Stack)
	}
	if cfg.Checks.HealthEndpoint.Path != "/health" {
		t.Errorf("HealthEndpoint.Path = %q, want /health default", cfg.Checks.HealthEndpoint.Path)
	}
}

// A misspelled key used to be silently dropped, which turned "I enabled the
// health check" into "the health check never ran" with no message anywhere.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := writeConfig(t, "projectName: demo\nchecks:\n  healthEndpont:\n    enabled: true\n")
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted an unknown key, want an error")
	}
	if !strings.Contains(err.Error(), "healthEndpont") {
		t.Errorf("error should name the bad key, got: %v", err)
	}
}

// yaml.v3 names Go types ("field sentry not found in type
// config.ChecksConfig"). The error names the key, where it sits, and the
// line, in the file's own terms.
func TestUnknownKeyErrorUsesConfigTerms(t *testing.T) {
	cases := []struct{ body, want string }{
		{"projectName: demo\nchecks:\n  secrets:\n    enabled: true\n  sentry:\n    enabled: true\n", `unknown key "sentry" under checks: at line 5`},
		{"projectName: demo\nprojctName: x\n", `unknown top-level key "projctName" at line 2`},
		{"checks:\n  healthEndpoint:\n    enabeld: true\n", `unknown key "enabeld" under checks.healthEndpoint: at line 3`},
		{"services:\n  stripe:\n    declard: true\n", `unknown key "declard" under services.stripe: at line 3`},
	}
	for _, tc := range cases {
		_, err := Load(writeConfig(t, tc.body))
		if err == nil {
			t.Fatalf("%q loaded", tc.body)
		}
		msg := err.Error()
		if !strings.Contains(msg, tc.want) {
			t.Errorf("got %q, want it to contain %q", msg, tc.want)
		}
		if strings.Contains(msg, "config.") || strings.Contains(msg, "not found in type") {
			t.Errorf("error still names Go types: %q", msg)
		}
		if !strings.Contains(msg, "newer Preflight") {
			t.Errorf("error should hint at a newer Preflight: %q", msg)
		}
	}
	// A service listed under checks: is the likely mistake behind "sentry".
	_, err := Load(writeConfig(t, "checks:\n  sentry:\n    enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "services:") {
		t.Errorf("want a pointer to services:, got %v", err)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	dir := writeConfig(t, "")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("an empty preflight.yml should load with defaults, got: %v", err)
	}
	if cfg.Stack != "unknown" {
		t.Errorf("Stack = %q, want unknown", cfg.Stack)
	}
}

// A hand-edited URL without a scheme used to reach every check as-is, so SSL
// reported "does not use HTTPS" and every page probe failed.
func TestLoadNormalizesSchemelessURLs(t *testing.T) {
	dir := t.TempDir()
	yml := "projectName: p\nurls:\n  staging: localhost:3000\n  production: example.com\n"
	if err := os.WriteFile(filepath.Join(dir, "preflight.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URLs.Production != "https://example.com" || cfg.URLs.Staging != "http://localhost:3000" {
		t.Errorf("urls = %+v", cfg.URLs)
	}
}
