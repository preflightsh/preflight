package cmd

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// initProject makes dir the working directory and feeds answers to init on
// stdin. HOME is a scratch directory so first-run markers stay out of the
// real one.
func initProject(t *testing.T, files map[string]string, answers string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	stdin := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(stdin, []byte(answers), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut, wd := os.Stdin, os.Stdout, ""
	wd, _ = os.Getwd()
	os.Stdin, os.Stdout = in, devNull
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	oldForce, oldYes := initForce, initYes
	t.Cleanup(func() {
		initYes = oldYes
		os.Stdin, os.Stdout = oldIn, oldOut
		_ = in.Close()
		_ = devNull.Close()
		_ = os.Chdir(wd)
		initForce = oldForce
	})
	return dir
}

// With --yes, init takes every default and writes a config that loads,
// in the 2-space layout `preflight ignore` keeps.
func TestInitWritesLoadableConfigWithTwoSpaceIndent(t *testing.T) {
	dir := initProject(t, map[string]string{"index.html": "<html></html>"}, "")
	initYes = true
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, filepath.Join(dir, "preflight.yml"))
	if !strings.Contains(data, "\nchecks:\n  envParity:\n    enabled: true\n") {
		t.Errorf("config is not indented by two spaces:\n%s", data)
	}
	if _, err := config.Load(dir); err != nil {
		t.Fatalf("init wrote a config that does not load: %v", err)
	}
	// The first edit after init changes the ignore list and nothing else.
	if err := runIgnore(nil, []string{"sitemap"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "preflight.yml")); got != data+"ignore:\n  - sitemap\n" {
		t.Errorf("ignore after init changed more than the ignore list")
	}
}

// An existing preflight.yml is kept unless the user says to replace it.
// End of input is not a yes.
func TestInitKeepsExistingConfigByDefault(t *testing.T) {
	const existing = "projectName: mine\nignore:\n  - sitemap\n"
	dir := initProject(t, map[string]string{"preflight.yml": existing}, "")
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "preflight.yml")); got != existing {
		t.Errorf("existing config was replaced:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err == nil {
		t.Error("init touched .gitignore after declining to overwrite")
	}

	// y to the overwrite question, then an empty line (the default) for
	// every question after it.
	dir = initProject(t, map[string]string{"preflight.yml": existing}, "y\n"+strings.Repeat("\n", 60))
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "preflight.yml")); got == existing {
		t.Error("answering y did not replace the config")
	}
}

// A bad email domain is asked for again at its prompt. It used to be
// accepted there and rejected at the very end, with every answer lost and
// exit 64.
func TestInitReasksForABadMailDomain(t *testing.T) {
	answers := strings.Join([]string{
		"demo",                     // project name
		"",                         // staging URL
		"",                         // production URL
		"1",                        // other services: skip
		"n",                        // license
		"n",                        // ads
		"y",                        // email auth
		"https://mail.example.com", // rejected
		"Mail.Example.com.",        // accepted, normalized
		"n",                        // humans.txt
		"n",                        // .gitignore
	}, "\n") + "\n"
	dir := initProject(t, map[string]string{"index.html": "<html></html>"}, answers)
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Checks.EmailAuth == nil || !cfg.Checks.EmailAuth.Enabled || cfg.Checks.EmailAuth.Domain != "mail.example.com" {
		t.Errorf("emailAuth = %+v, want enabled for mail.example.com", cfg.Checks.EmailAuth)
	}
	if cfg.ProjectName != "demo" {
		t.Errorf("projectName = %q: the answers before the bad one were lost", cfg.ProjectName)
	}
}

// A bad domain followed by end of input does not loop: there is nobody
// left to ask, so email auth is left off.
func TestPromptMailDomainStopsAtEndOfInput(t *testing.T) {
	initProject(t, nil, "")
	if got := promptMailDomain(bufio.NewReader(strings.NewReader("not a domain"))); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := promptMailDomain(bufio.NewReader(strings.NewReader("bad/domain\nmail.example.com\n"))); got != "mail.example.com" {
		t.Errorf("got %q, want mail.example.com", got)
	}
}

// The generated IndexNow key file goes where the site serves files from
// its root: the project root for WordPress and Jekyll, never a build
// output directory that the next build wipes.
func TestInitPlacesIndexNowKeyFile(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantDir string
		absent  string
	}{
		{"wordpress", map[string]string{"wp-config.php": "<?php\n"}, ".", "public"},
		{"jekyll", map[string]string{"_config.yml": "title: x\n", "_layouts/default.html": "<html></html>"}, ".", "_site"},
		{"eleventy", map[string]string{".eleventy.js": "module.exports = {}\n", "src/index.njk": "x"}, "src", "_site"},
		{"rails", map[string]string{"Gemfile": "source 'https://rubygems.org'\n", "config/routes.rb": "\n"}, "public", ""},
	}
	keyFile := regexp.MustCompile(`^[a-f0-9]{32}\.txt$`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := initProject(t, tc.files, "")
			if got := config.DetectStack(dir); got != tc.name {
				t.Fatalf("fixture detected as %q", got)
			}
			key := generateIndexNowKey()
			createIndexNowKeyFile(dir, tc.name, key)
			entries, err := os.ReadDir(filepath.Join(dir, tc.wantDir))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range entries {
				if keyFile.MatchString(e.Name()) {
					found = true
				}
			}
			if !found {
				t.Errorf("no key file in %s", tc.wantDir)
			}
			if tc.absent != "" {
				if _, err := os.Stat(filepath.Join(dir, tc.absent)); err == nil {
					t.Errorf("init created %s/", tc.absent)
				}
			}
		})
	}
}

func TestGitignoreCoversPreflightYml(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"", false},
		{"node_modules\n", false},
		{"preflight.yml\n", true},
		{"/preflight.yml\n", true},
		{"  preflight.yml  \n", true},
		{"# preflight.yml\n", false},
		{"*.yml\n", true},
		{"preflight.*\n", true},
		{"*.yaml\n", false},
		{"preflight.yml/\n", false},
		{"*.yml\n!preflight.yml\n", false},
		{"!preflight.yml\npreflight.yml\n", true},
		{"preflight.yml\r\n", true},
	}
	for _, tc := range cases {
		if got := gitignoreCoversPreflightYml([]byte(tc.content)); got != tc.want {
			t.Errorf("gitignoreCoversPreflightYml(%q) = %v, want %v", tc.content, got, tc.want)
		}
	}
}

// init and scan share one layout table, so what init writes as the main
// layout is exactly what turns the SEO checks on in scan.
func TestMainLayoutTableIsShared(t *testing.T) {
	cases := []struct {
		stack string
		file  string
		want  string
	}{
		{"astro", "src/layouts/BaseLayout.astro", "src/layouts/BaseLayout.astro"},
		{"astro", "src/layouts/Base.astro", "src/layouts/Base.astro"},
		{"remix", "app/root.tsx", "app/root.tsx"},
		{"nuxt", "app.vue", "app.vue"},
		{"angular", "src/index.html", "src/index.html"},
		{"svelte", "src/app.html", "src/app.html"},
		{"node", "views/layout.ejs", "views/layout.ejs"},
		{"unknown", "templates/base.twig", "templates/base.twig"},
		{"wordpress", "wp-content/themes/acme/header.php", "wp-content/themes/acme/header.php"},
		{"drupal", "web/themes/custom/acme/templates/html.html.twig", "web/themes/custom/acme/templates/html.html.twig"},
		{"hugo", "themes/acme/layouts/_default/baseof.html", "themes/acme/layouts/_default/baseof.html"},
		// The stack was detected from an app inside a monorepo, so the
		// layout is found there and written relative to the root.
		{"next", "apps/web/app/layout.tsx", "apps/web/app/layout.tsx"},
		{"next", "apps/web/src/app/layout.tsx", "apps/web/src/app/layout.tsx"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, filepath.FromSlash(tc.file))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("<html></html>"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := detectMainLayout(dir, tc.stack); got != tc.want {
			t.Errorf("stack %s with %s: init found %q, want %q", tc.stack, tc.file, got, tc.want)
		}
		if !canAutoDetectLayout(dir, tc.stack) {
			t.Errorf("stack %s with %s: scan found no layout", tc.stack, tc.file)
		}
	}
	// A directory with a layout's name is not a layout.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "index.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := detectMainLayout(dir, "static"); got != "" {
		t.Errorf("a directory was taken as the layout: %q", got)
	}
}

// A monorepo's Next app gets a seoMeta block pointing into the app.
func TestInitWritesMonorepoLayout(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"apps/web/next.config.ts": "export default {}\n",
		"apps/web/app/layout.tsx": "export default function L() {}\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stack := config.DetectStack(dir)
	if stack != "next" {
		t.Fatalf("stack = %q", stack)
	}
	c := buildDefaultChecks(dir, stack, nil, "", false, false, "", false, false)
	if c.SEOMeta == nil || c.SEOMeta.MainLayout != "apps/web/app/layout.tsx" {
		t.Errorf("seoMeta = %+v, want the layout inside apps/web", c.SEOMeta)
	}
}

func TestDetectWebRoot(t *testing.T) {
	cases := map[string]string{
		"wordpress": ".",
		"jekyll":    ".",
		"rails":     "public",
		"craft":     "web",
		"hugo":      "static",
		"gatsby":    "static",
	}
	for stack, want := range cases {
		if got := detectWebRoot(t.TempDir(), stack); got != want {
			t.Errorf("detectWebRoot(%s) = %q, want %q", stack, got, want)
		}
	}
	// An unknown stack uses the first common web root that exists.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := detectWebRoot(dir, "unknown"); got != "static" {
		t.Errorf("unknown stack with static/: %q", got)
	}
	if got := detectWebRoot(t.TempDir(), "eleventy"); got != "." {
		t.Errorf("eleventy with no src/: %q", got)
	}
}

// Input that ends before the questions do used to count as accepting
// every default, so `preflight init < /dev/null` wrote a config and
// edited .gitignore on answers nobody gave.
func TestInitRefusesToWriteWhenInputEnds(t *testing.T) {
	for name, answers := range map[string]string{"no input": "", "input ends partway": "my-project\n"} {
		dir := initProject(t, map[string]string{"index.html": "<html></html>"}, answers)
		err := runInit(initCmd, nil)
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != ExitUsage || !strings.Contains(err.Error(), "--yes") {
			t.Errorf("%s: err = %v, want a usage error naming --yes", name, err)
		}
		for _, f := range []string{"preflight.yml", ".gitignore"} {
			if _, statErr := os.Stat(filepath.Join(dir, f)); statErr == nil {
				t.Errorf("%s: init wrote %s", name, f)
			}
		}
	}
}

// --yes never overwrites on its own: replacing a config still takes
// --force.
func TestInitYesKeepsAnExistingConfigWithoutForce(t *testing.T) {
	const existing = "projectName: mine\nignore:\n  - sitemap\n"
	dir := initProject(t, map[string]string{"preflight.yml": existing}, "")
	initYes = true
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "preflight.yml")); got != existing {
		t.Errorf("--yes replaced an existing config:\n%s", got)
	}

	initForce = true
	if err := runInit(initCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "preflight.yml")); got == existing {
		t.Error("--yes --force did not replace the config")
	}
}
