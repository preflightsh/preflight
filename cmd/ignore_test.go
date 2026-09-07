package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commentedConfig = `# Preflight config for Example
projectName: example
stack: rails
urls:
  production: https://example.com   # main site
services:
  stripe:
    declared: true   # we bill through Stripe
checks:
  secrets:
    enabled: true
  healthEndpoint:
    enabled: true
    path: /up      # Rails 7.1 default
`

func inTempProject(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "preflight.yml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return filepath.Join(dir, "preflight.yml")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// normalizedConfig is commentedConfig as yaml.v3 re-emits it: identical
// apart from the run of spaces before each inline comment, which the
// encoder collapses to one. Comments, key order and indentation survive.
const normalizedConfig = `# Preflight config for Example
projectName: example
stack: rails
urls:
  production: https://example.com # main site
services:
  stripe:
    declared: true # we bill through Stripe
checks:
  secrets:
    enabled: true
  healthEndpoint:
    enabled: true
    path: /up # Rails 7.1 default
`

// `preflight ignore` used to decode the file into a map and re-encode it,
// which deleted every comment, alphabetized the keys and re-indented the
// whole file. The edit must be the one line the user asked for.
func TestIgnorePreservesCommentsAndOrder(t *testing.T) {
	path := inTempProject(t, commentedConfig)
	if err := runIgnore(nil, []string{"sitemap"}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	want := normalizedConfig + "ignore:\n  - sitemap\n"
	if got != want {
		t.Errorf("config was rewritten beyond the ignore entry.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	if err := runIgnore(nil, []string{"llms_txt"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !strings.HasSuffix(got, "ignore:\n  - sitemap\n  - llms_txt\n") {
		t.Errorf("second ignore should append to the list:\n%s", got)
	}

	if err := runUnignore(nil, []string{"sitemap"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !strings.HasSuffix(got, "ignore:\n  - llms_txt\n") || !strings.Contains(got, "# we bill through Stripe") {
		t.Errorf("unignore should remove one entry and keep comments:\n%s", got)
	}
	if err := runUnignore(nil, []string{"llms_txt"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != normalizedConfig {
		t.Errorf("removing the last entry should drop the ignore key and restore the file.\n--- got ---\n%s", got)
	}
}

// A misspelled ID used to be written to the file with a success message.
func TestIgnoreRejectsUnknownID(t *testing.T) {
	path := inTempProject(t, commentedConfig)
	err := runIgnore(nil, []string{"sitemapp"})
	if err == nil {
		t.Fatal("ignore accepted an unknown ID")
	}
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitUsage {
		t.Errorf("want ExitUsage, got %v", err)
	}
	if strings.Contains(readFile(t, path), "sitemapp") {
		t.Error("the unknown ID was written to preflight.yml")
	}
	// File globs for the debug-statements scan are still allowed.
	if err := runIgnore(nil, []string{"web/tools/**/*.php"}); err != nil {
		t.Errorf("glob entry rejected: %v", err)
	}
}

func TestIgnoreSecretsAllowlistEntry(t *testing.T) {
	path := inTempProject(t, "projectName: demo\n")
	if err := runIgnore(nil, []string{"secrets", "web/js/golden-hour.js"}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	want := "projectName: demo\nchecks:\n  secrets:\n    enabled: true\n    allowlist:\n      - path: web/js/golden-hour.js\n"
	if got != want {
		t.Errorf("--- got ---\n%s--- want ---\n%s", got, want)
	}
	// Idempotent.
	if err := runIgnore(nil, []string{"secrets", "web/js/golden-hour.js"}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, path) != want {
		t.Error("re-adding the same path changed the file")
	}
}

// A file that is only a comment has its comment on the document node, not
// on a key. Re-encoding just the mapping dropped it.
func TestIgnoreKeepsDocumentComment(t *testing.T) {
	path := inTempProject(t, "# nothing configured yet\n")
	if err := runIgnore(nil, []string{"sitemap"}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, "# nothing configured yet") || !strings.Contains(got, "ignore:\n  - sitemap\n") {
		t.Errorf("--- got ---\n%s", got)
	}
}

// Pre-1.0 IDs keep working: `ignore llmsTxt` writes the current name, and
// `unignore` removes an entry however it was spelled.
func TestIgnoreAcceptsRenamedIDs(t *testing.T) {
	path := inTempProject(t, "projectName: demo\nignore:\n  - seoMeta\n")
	if err := runIgnore(nil, []string{"llmsTxt"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !strings.HasSuffix(got, "ignore:\n  - seoMeta\n  - llms_txt\n") {
		t.Errorf("want the current name written, got:\n%s", got)
	}
	if err := runIgnore(nil, []string{"seo_meta"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Count(got, "seo") != 1 {
		t.Errorf("seo_meta is already listed as seoMeta and must not be added twice:\n%s", got)
	}
	if err := runUnignore(nil, []string{"seo_meta"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Contains(got, "seoMeta") {
		t.Errorf("unignore by the new name should remove the old spelling:\n%s", got)
	}
}
