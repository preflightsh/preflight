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
