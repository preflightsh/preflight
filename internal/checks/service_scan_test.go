package checks

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/config"
)

// TestStripSourceCommentsKeepsCodeAfterAGlob: a "/*" inside a string is a
// glob or a route, not a comment opener. Treating it as one blanked the
// file up to the next "*/".
func TestStripSourceCommentsKeepsCodeAfterAGlob(t *testing.T) {
	src := "app.use('/api/*', auth)\nconst client = new Resend(key)\nconst glob = 'src/**/*.ts' /* trailing note */\n/*\n new Mailgun()\n*/\n// new Postmark()\nok()\n"
	got := stripSourceComments(src, false)
	for _, want := range []string{"new Resend(key)", "'src/**/*.ts'", "ok()"} {
		if !strings.Contains(got, want) {
			t.Errorf("stripped source lost %q:\n%s", want, got)
		}
	}
	for _, gone := range []string{"trailing note", "new Mailgun()", "new Postmark()"} {
		if strings.Contains(got, gone) {
			t.Errorf("stripped source kept the comment %q:\n%s", gone, got)
		}
	}
}

// TestMayMatchIsNecessary: the literal prefilter may only rule a file out
// when the pattern cannot match it.
func TestMayMatchIsNecessary(t *testing.T) {
	cases := []struct {
		pattern, text string
		may           bool
	}{
		{`\bnew Resend\b`, "x = NEW RESEND(", true}, // case is the pattern's business
		{`\bnew Resend\b`, "nothing here", false},
		{`(?i)posthog\.init`, "PostHog.Init()", true},
		{`from\s+["']resend["']`, "import x from 'resend'", true},
		{`cdn\.segment\.com|@segment/`, "import '@segment/analytics-next'", true},
		{`cdn\.segment\.com|@segment/`, "import 'left-pad'", false},
		{`(?m)^\s*(?:import|from)\s+redis\b`, "import redis", true},
		{`\b[A-Z]{2}[0-9]{4,}\b`, "anything at all", true}, // no usable literal: never ruled out
		{`\bG-[A-Z0-9]{8,12}\b`, "id = 'G-ABCDEFGH12'", true},
		{`gemini-(?:\d|pro|flash)`, "model = 'gemini-2.5-flash'", true},
		{`gemini-(?:\d|pro|flash)`, "zodiac: gemini", false},
	}
	for _, tc := range cases {
		p := regexp.MustCompile(tc.pattern)
		if got := mayMatch(p, strings.ToLower(tc.text)); got != tc.may {
			t.Errorf("mayMatch(%s, %q) = %v, want %v", tc.pattern, tc.text, got, tc.may)
		}
		if p.MatchString(tc.text) && !mayMatch(p, strings.ToLower(tc.text)) {
			t.Errorf("%s matches %q but the prefilter ruled it out", tc.pattern, tc.text)
		}
	}
	// Every registered service pattern: whatever it matches, the prefilter
	// must let through. The round-trip fixtures are the corpus.
	for id, code := range roundTripCode {
		for _, p := range serviceCodeGroups()[id].patterns {
			if p.MatchString(code[1]) && !mayMatch(p, strings.ToLower(code[1])) {
				t.Errorf("%s: %s matches its fixture but the prefilter ruled it out", id, p)
			}
		}
	}
}

// TestManifestDependencies: only dependency names (and package.json
// scripts) are matched, never the prose a manifest carries.
func TestManifestDependencies(t *testing.T) {
	pkg := `{"name":"stripe-notes","description":"notes about sendgrid","keywords":["mailgun"],
		"scripts":{"deploy":"wrangler deploy"},
		"dependencies":{"@sendgrid/mail":"^8"},"devDependencies":{"vitest":"^2"}}`
	got := manifestDependencies("package.json", []byte(pkg))
	if !strings.Contains(got, `"@sendgrid/mail": "^8"`) || !strings.Contains(got, `"vitest"`) || !strings.Contains(got, "wrangler deploy") {
		t.Errorf("dependencies missing from %q", got)
	}
	for _, prose := range []string{"stripe-notes", "notes about", "mailgun"} {
		if strings.Contains(got, prose) {
			t.Errorf("prose %q leaked into %q", prose, got)
		}
	}
	if got := manifestDependencies("package.json", []byte("{not json")); got != "" {
		t.Errorf("malformed package.json = %q, want nothing", got)
	}
	py := "[project]\nname = \"stripe-notes\"\ndescription = \"notes about stripe\"\ndependencies = [\"stripe>=8\"]\n"
	if got := manifestDependencies("pyproject.toml", []byte(py)); strings.Contains(got, "notes about") || !strings.Contains(got, "stripe>=8") {
		t.Errorf("pyproject dependencies = %q", got)
	}
	gem := "# gem \"stripe\"\ngem \"rails\"\n"
	if got := manifestDependencies("Gemfile", []byte(gem)); strings.Contains(got, "stripe") || !strings.Contains(got, "rails") {
		t.Errorf("Gemfile dependencies = %q", got)
	}
}

// TestScanSourceOnePassForEveryService: a scan answers every declared
// service from one walk, shared through the scan context, and each answer
// matches what a search for that service alone finds.
func TestScanSourceOnePassForEveryService(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/mail.js", "const resend = new Resend(key)\n")
	writeFixture(t, root, "src/ai.js", "const client = new OpenAI({ apiKey })\n")
	writeFixture(t, root, "index.html", "<script src=\"//cdn.usefathom.com/script.js\" data-site=\"ABCDEFGH\"></script>\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := Context{
		Ctx:     ctx,
		RootDir: root,
		Config: &config.PreflightConfig{Services: map[string]config.ServiceConfig{
			"resend": {Declared: true}, "openai": {Declared: true}, "fathom": {Declared: true}, "mailgun": {Declared: true},
		}},
	}
	want := map[string]string{"resend": "src/mail.js", "openai": "src/ai.js", "fathom": "index.html", "mailgun": ""}
	for id, file := range want {
		m := c.serviceCodeMatch(id)
		got := ""
		if m != nil {
			got = m.FilePath
		}
		if got != file {
			t.Errorf("%s matched %q, want %q", id, got, file)
		}
	}

	// The shared answers were computed once: a file added afterwards is not
	// seen by this scan.
	writeFixture(t, root, "src/late.js", "const mg = new Mailgun(formData)\n")
	if m := c.serviceCodeMatch("mailgun"); m != nil {
		t.Errorf("mailgun matched %q after the shared pass; the pass ran again", m.FilePath)
	}
	// Without a scan context nothing is shared.
	c.Ctx = nil
	if m := c.serviceCodeMatch("mailgun"); m == nil || m.FilePath != "src/late.js" {
		t.Errorf("mailgun without a scan context = %+v, want src/late.js", m)
	}

	cancel()
	if _, ok := sourceScans.Load(sourceScanKey{ctx: ctx, root: root}); ok {
		// AfterFunc runs in its own goroutine; give it a moment.
		time.Sleep(50 * time.Millisecond)
		if _, ok := sourceScans.Load(sourceScanKey{ctx: ctx, root: root}); ok {
			t.Error("shared scan kept after its context ended")
		}
	}
}

// TestScanSourceHonorsCancellation: a cancelled context stops the walk.
func TestScanSourceHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/a.js", "const resend = new Resend(key)\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	groups := map[string]codeGroup{"x": {patterns: []*regexp.Regexp{regexp.MustCompile(`new Resend`)}}}
	if got := scanSource(ctx, root, "", groups); len(got) != 0 {
		t.Fatalf("matches after cancel = %v, want none", got)
	}
}

// TestScanSourceSkipsCoreAndOutput: CMS core and runtime data are not the
// project's source. Third-party plugins stay in: a plugin's directory is
// often the only sign of an integration.
func TestScanSourceSkipsCoreAndOutput(t *testing.T) {
	root := t.TempDir()
	hit := "const resend = new Resend(key)\n"
	for _, skipped := range []string{
		"wp-admin/js/a.js", "wp-includes/js/a.js", "web/core/misc/a.js",
		"storage/framework/a.js", "node_modules/x/a.js", ".nuxt/a.js", ".output/a.js", "log/a.js",
	} {
		writeFixture(t, root, skipped, hit)
	}
	pattern := []*regexp.Regexp{regexp.MustCompile(`new Resend`)}
	if m := searchForPatternsWithDetails(root, "", pattern); m != nil {
		t.Fatalf("matched %s, want nothing", m.FilePath)
	}
	writeFixture(t, root, "wp-content/plugins/mailer/mailer.php", "<?php // x\n$r = new Resend($key);\n")
	if m := searchForPatternsWithDetails(root, "", pattern); m == nil || m.FilePath != "wp-content/plugins/mailer/mailer.php" {
		t.Fatalf("match = %+v, want the plugin file", m)
	}
}

// TestScanSourceIsOneWalk guards the cost: every declared service used to
// walk the tree on its own (twenty services over 2,000 files took 48
// seconds). In a scan they share one walk. A count, not a stopwatch, so the
// test means the same thing on a slow runner.
func TestScanSourceIsOneWalk(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		p := filepath.Join(root, "src", "m"+string(rune('a'+i)), "f.js")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("export function f(a, b) { return a + b } // filler\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	services := map[string]config.ServiceConfig{"stripe": {Declared: true}}
	for id := range ServiceChecks {
		services[id] = config.ServiceConfig{Declared: true}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := Context{Ctx: ctx, RootDir: root, Config: &config.PreflightConfig{Services: services}}

	before := sourceWalks.Load()
	checks := []Check{StripeWebhookCheck{}}
	for _, check := range ServiceChecks {
		checks = append(checks, check)
	}
	for _, check := range checks {
		if res, err := check.Run(c); err != nil {
			t.Fatalf("%s: %v", check.ID(), err)
		} else if res.Passed {
			t.Errorf("%s passed on a tree with no integrations: %s", check.ID(), res.Message)
		}
	}
	if walks := sourceWalks.Load() - before; walks != 1 {
		t.Fatalf("%d service checks walked the tree %d times, want once", len(checks), walks)
	}
}
