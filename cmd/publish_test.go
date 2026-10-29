package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
)

// One repository must map to one dashboard project however it was cloned.
// Before this test, ssh:// and https://user@ forms hashed differently from
// the scp-style and plain https forms.
func TestNormalizeRemote(t *testing.T) {
	want := "github.com/preflightsh/preflight"
	forms := []string{
		"git@github.com:preflightsh/preflight.git",
		"git@github.com:preflightsh/preflight",
		"https://github.com/preflightsh/preflight.git",
		"https://github.com/preflightsh/preflight/",
		"http://github.com/preflightsh/preflight",
		"ssh://git@github.com/preflightsh/preflight.git",
		"https://jon@github.com/preflightsh/preflight.git",
		"https://jon:s3cr3t@github.com/preflightsh/preflight.git",
		"  HTTPS://GitHub.com/PreflightSH/Preflight.git\n",
	}
	for _, f := range forms {
		if got := normalizeRemote(f); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", f, got, want)
		}
	}
	// Different repositories must stay different.
	if normalizeRemote("git@github.com:preflightsh/preflight") == normalizeRemote("git@github.com:preflightsh/other") {
		t.Error("distinct repositories collapsed to the same key")
	}
}

// Two apps in one monorepo used to share a dashboard project because the
// key hashed only the remote. The subdirectory is part of the key, and a
// scan at the repository root keeps the key it always had.
func TestProjectKeySeparatesMonorepoApps(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@github.com:acme/mono.git"}} {
		c := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, sub := range []string{"apps/web", "apps/api"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte("github.com/acme/mono"))
	if got, want := projectKey(root, "mono"), "git:"+hex.EncodeToString(sum[:])[:16]; got != want {
		t.Errorf("root key changed: got %s, want %s", got, want)
	}
	web := projectKey(filepath.Join(root, "apps/web"), "web")
	api := projectKey(filepath.Join(root, "apps/api"), "api")
	if web == api || web == projectKey(root, "mono") || !strings.HasPrefix(web, "git:") {
		t.Errorf("monorepo apps collide: root=%s web=%s api=%s", projectKey(root, "mono"), web, api)
	}
	if web != projectKey(filepath.Join(root, "apps", "web"), "renamed") {
		t.Error("the key must not depend on the project name")
	}
}

func TestTruncateIsRuneSafe(t *testing.T) {
	if got := truncate("héllo wörld", 6); got != "héllo…" {
		t.Errorf("truncate = %q, want %q", got, "héllo…")
	}
	if got := truncate("short", 28); got != "short" {
		t.Errorf("truncate should leave short strings alone, got %q", got)
	}
}

// The IndexNow key is cleared from the published config, so the index_now
// check's messages must not carry it either.
func TestRedactChecksMasksIndexNowKey(t *testing.T) {
	key := "23a74777e94982ce283db6a0ee3ad917"
	cfg := &config.PreflightConfig{Checks: config.ChecksConfig{IndexNow: &config.IndexNowConfig{Enabled: true, Key: key}}}
	got := redactChecks(cfg, []checks.CheckResult{
		{ID: "index_now", Passed: true, Message: "Key file found at public/" + key + ".txt"},
		{ID: "seo_meta", Passed: true, Message: "hash " + key},
	})
	if strings.Contains(got[0].Message, key) {
		t.Errorf("index_now message still carries the key: %q", got[0].Message)
	}
	if strings.Contains(got[1].Message, key) {
		t.Errorf("other checks must also exclude arbitrary input: %q", got[1].Message)
	}
}

// Since 0.24 every published message was a placeholder, which left the
// dashboard's AI fixes with nothing to work from. Checks whose messages
// have a known, safe shape publish them again; the rest stay generic.
func TestRedactChecksAllowlist(t *testing.T) {
	cfg := &config.PreflightConfig{
		URLs: config.URLConfig{Staging: "https://jon:hunter2@staging.example.com/app?token=abc"},
		Checks: config.ChecksConfig{
			SEOMeta:   &config.SEOMetaConfig{MainLayout: "private/layouts/main.twig"},
			EnvParity: &config.EnvParityConfig{EnvFile: ".env.secret-name"},
		},
	}
	results := []checks.CheckResult{
		{ID: "seo_meta", Message: "Missing SEO metadata: description"},
		{ID: "debug_statements", Message: "Found 2 debug statement(s)", Suggestions: []string{"src/a.js:10 - console.log", "src/b.js:3 - debugger"}},
		{ID: "image_optimization", Message: "Found 1 large image(s) over 500KB", Suggestions: []string{"public/hero.png (2.1 MB)"}},
		{ID: "viewport", Message: "Could not read layout file: private/layouts/main.twig"},
		{ID: "www_redirect", Message: "www.staging.example.com could not connect to https://jon:hunter2@staging.example.com/app?token=abc"},
		{ID: "secrets", Message: "AWS key in config/prod.yml"},
		{ID: "vulnerability", Message: "npm audit: lodash token=xyz"},
		{ID: "env_parity", Message: "Missing in .env.secret-name: STRIPE_KEY"},
		{ID: "sentry", Message: "Sentry DSN https://abc@o1.ingest.sentry.io/1"},
		{ID: "lang", Message: "Check failed: panic: open /Users/jon/private: denied"},
	}
	got := redactChecks(cfg, results)
	byID := map[string]string{}
	for _, c := range got {
		byID[c.ID] = c.Message
	}
	if byID["seo_meta"] != "Missing SEO metadata: description" {
		t.Errorf("seo_meta message not published: %q", byID["seo_meta"])
	}
	if !strings.Contains(byID["debug_statements"], "src/a.js:10") || !strings.Contains(byID["debug_statements"], "src/b.js:3") {
		t.Errorf("debug_statements should list file:line: %q", byID["debug_statements"])
	}
	if !strings.Contains(byID["image_optimization"], "public/hero.png") {
		t.Errorf("image_optimization should list files: %q", byID["image_optimization"])
	}
	encoded, _ := json.Marshal(got)
	for _, secret := range []string{"private/layouts", "hunter2", "token=abc", "config/prod.yml", "lodash", ".env.secret-name", "STRIPE_KEY", "ingest.sentry.io", "/Users/jon"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("published results contain %q:\n%s", secret, encoded)
		}
	}
	if !strings.Contains(byID["www_redirect"], "staging.example.com") {
		t.Errorf("public host should survive: %q", byID["www_redirect"])
	}
}
