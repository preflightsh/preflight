package cmd

import (
	"os"
	"path/filepath"
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
