package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func enabledIDs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range buildEnabledChecks(cfg, dir) {
		ids[c.ID()] = true
	}
	return ids
}

// A checks block without an enabled key is not an opt-out. Since 0.24 a
// healthEndpoint block holding only a path, or a seoMeta block holding
// only a layout, silently dropped the checks it configures.
func TestChecksBlockWithoutEnabledKeepsDefaults(t *testing.T) {
	dir := scanProject(t, "projectName: h\nstack: static\nurls:\n  staging: http://127.0.0.1:8765\nchecks:\n  healthEndpoint:\n    path: /api/health\n")
	if !enabledIDs(t, dir)["health_endpoint"] {
		t.Error("healthEndpoint with only a path and a URL set: health_endpoint did not run")
	}

	dir = scanProject(t, "projectName: s\nstack: unknown\nchecks:\n  seoMeta:\n    mainLayout: partials/header.php\n")
	ids := enabledIDs(t, dir)
	for _, id := range []string{"seo_meta", "canonical", "og_twitter", "viewport", "lang"} {
		if !ids[id] {
			t.Errorf("seoMeta with only mainLayout: %s did not run", id)
		}
	}
}

// An explicit enabled: false is still an opt-out.
func TestExplicitEnabledFalseDisables(t *testing.T) {
	dir := scanProject(t, "projectName: h\nstack: next\nurls:\n  production: https://example.com\nchecks:\n  healthEndpoint:\n    enabled: false\n    path: /api/health\n  seoMeta:\n    enabled: false\n    mainLayout: app/layout.tsx\n")
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app", "layout.tsx"), []byte("export default 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ids := enabledIDs(t, dir)
	if ids["health_endpoint"] || ids["seo_meta"] {
		t.Errorf("explicit enabled: false ignored: %v", ids)
	}
}

// preflight init wrote healthEndpoint {enabled: false, path: /health} for
// CMS and static stacks without asking, and v0.23 still ran the check when
// a URL was set. That exact block keeps the v0.23 behavior.
func TestInitWrittenHealthOptOutKeepsV023Behavior(t *testing.T) {
	dir := scanProject(t, "projectName: h\nstack: craft\nurls:\n  production: https://example.com\nchecks:\n  healthEndpoint:\n    enabled: false\n    path: /health\n")
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notes) == 0 {
		t.Error("want a note explaining how to turn health_endpoint off")
	}
	if !enabledIDs(t, dir)["health_endpoint"] {
		t.Error("init-written healthEndpoint block with a URL: health_endpoint did not run")
	}
}

// A block that holds settings but no enabled key turns its check on. It
// used to read as enabled: false, so a config with only a secrets
// allowlist never ran the secrets scan and printed nothing about it.
func TestSettingsOnlyBlockEnablesEveryCheck(t *testing.T) {
	cases := []struct {
		block string
		id    string
	}{
		{"  secrets:\n    allowlist:\n      - path: foo.js\n", "secrets"},
		{"  envParity:\n    envFile: .env.production\n", "env_parity"},
		{"  emailAuth:\n    domain: mail.example.com\n", "email_auth"},
		{"  security: {}\n", "security_headers"},
		{"  indexNow:\n    key: 0123456789abcdef0123456789abcdef\n", "index_now"},
		{"  stripeWebhook:\n    url: https://example.com/hook\n", "stripe"},
		{"  adsTxt: {}\n", "ads_txt"},
		{"  humansTxt: {}\n", "humans_txt"},
		{"  license: {}\n", "license"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			dir := scanProject(t, "projectName: p\nstack: unknown\nchecks:\n"+tc.block)
			if !enabledIDs(t, dir)[tc.id] {
				t.Errorf("block without enabled: %s did not run", tc.id)
			}
			// An explicit enabled: false is still an opt-out.
			off := strings.Replace(tc.block, " {}\n", "\n    enabled: false\n", 1)
			if off == tc.block {
				off = tc.block + "    enabled: false\n"
			}
			dir = scanProject(t, "projectName: p\nstack: unknown\nchecks:\n"+off)
			if enabledIDs(t, dir)[tc.id] {
				t.Errorf("enabled: false ignored: %s ran", tc.id)
			}
		})
	}
}

// A key with no value is not a block, and no block means the check is off.
func TestNullBlockStaysOff(t *testing.T) {
	dir := scanProject(t, "projectName: p\nstack: unknown\nchecks:\n  secrets:\n  security:\n")
	ids := enabledIDs(t, dir)
	if ids["secrets"] || ids["security_headers"] {
		t.Errorf("a null block enabled its check: %v", ids)
	}
}

// init no longer writes an opt-out the user never chose.
func TestInitOmitsHealthBlockForStaticStacks(t *testing.T) {
	c := buildDefaultChecks(t.TempDir(), "static", nil, "https://example.com", false, false, "", false, false)
	if c.HealthEndpoint != nil {
		t.Errorf("init wrote healthEndpoint %+v for a static stack", *c.HealthEndpoint)
	}
	c = buildDefaultChecks(t.TempDir(), "rails", nil, "https://example.com", false, false, "", false, false)
	if c.HealthEndpoint == nil || !c.HealthEndpoint.Enabled {
		t.Error("init should still enable healthEndpoint for app stacks")
	}
}
