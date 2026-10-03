package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func writeSrc(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return dir
}

// A debug statement named inside a trailing comment is a note about code,
// not code. The whole-line comment skip could not see those, so the raw
// line matched and reported a console.log that does not exist.
func TestScanForDebugStatements(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		body    string
		wantAny bool
	}{
		{
			name:    "trailing comment mentioning a debug call",
			file:    "app.js",
			body:    "doSomethingReal(); // debug: console.log(response) if this breaks\n",
			wantAny: false,
		},
		{
			name:    "whole-line comment",
			file:    "app.js",
			body:    "// console.log('left over')\nreal();\n",
			wantAny: false,
		},
		{
			name:    "real debug statement",
			file:    "app.js",
			body:    "console.log('left over');\n",
			wantAny: true,
		},
		{
			name:    "real debug statement with a trailing comment",
			file:    "app.js",
			body:    "console.log(x); // TODO remove before launch\n",
			wantAny: true,
		},
		{
			// The comment stripper must not truncate the line at the URL and
			// lose the debug call that follows it.
			name:    "debug statement after a URL on the same line",
			file:    "app.js",
			body:    "const u = \"https://api.example.com/v1\"; console.log(u);\n",
			wantAny: true,
		},
		{
			name:    "clean file",
			file:    "app.js",
			body:    "export function add(a, b) { return a + b }\n",
			wantAny: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForDebugStatements(writeSrc(t, tc.file, tc.body), nil)
			if gotAny := len(got) > 0; gotAny != tc.wantAny {
				t.Errorf("scanForDebugStatements found %v, want any=%v", got, tc.wantAny)
			}
		})
	}
}

// Toolchain output and Claude Code worktrees are not the project's source.
// On a polyglot monorepo with agent worktrees, walking them took minutes and
// reported each finding once per worktree.
func TestScanForDebugStatementsSkipsToolchainAndWorktreeDirs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deps") // a root named like a skipped dir is still scanned
	files := map[string]string{
		"app.js":                              "console.log('real')\n",
		"target/debug/build/gen.rs":           "dbg!(x);\n",
		".venv/lib/site.py":                   "breakpoint()\n",
		"_build/dev/lib/app.ex":               "IO.inspect(x)\n",
		".claude/worktrees/agent-a1/app.js":   "console.log('copy')\n",
		"packages/rust/target/release/gen.rs": "dbg!(y);\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := scanForDebugStatements(root, nil)
	if len(got) != 1 || got[0] != "app.js:1 - console.log" {
		t.Errorf("scanForDebugStatements = %v, want only app.js:1", got)
	}
}

func TestSearchForPatternsSkipsWorktreesButNotRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "build")
	pattern := []*regexp.Regexp{regexp.MustCompile(`application/ld\+json`)}

	writeTree := func(name string) {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`<script type="application/ld+json">{}</script>`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeTree(".claude/worktrees/agent-a1/src/layout.astro")
	if m := searchForPatternsWithDetails(root, "", pattern); m != nil {
		t.Errorf("matched %s inside .claude/worktrees", m.FilePath)
	}

	writeTree("src/layout.astro")
	if m := searchForPatternsWithDetails(root, "", pattern); m == nil || m.FilePath != "src/layout.astro" {
		t.Errorf("searchForPatternsWithDetails = %+v, want src/layout.astro", m)
	}
	if !searchForPatterns(root, "", pattern) {
		t.Error("searchForPatterns missed src/layout.astro under a root named build")
	}
}
