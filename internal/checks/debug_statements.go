package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

type DebugStatementsCheck struct{}

func (c DebugStatementsCheck) ID() string {
	return "debug_statements"
}

func (c DebugStatementsCheck) Title() string {
	return "Debug statements"
}

func (c DebugStatementsCheck) Run(ctx Context) (CheckResult, error) {
	findings := scanForDebugStatements(ctx.RootDir, ctx.Config.Ignore)

	if len(findings) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No debug statements found",
		}, nil
	}

	// Limit findings shown
	maxFindings := 5
	message := fmt.Sprintf("Found %d debug statement(s)", len(findings))

	var suggestions []string
	for i, finding := range findings {
		if i >= maxFindings {
			suggestions = append(suggestions, fmt.Sprintf("... and %d more", len(findings)-maxFindings))
			break
		}
		suggestions = append(suggestions, finding)
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     message,
		Suggestions: suggestions,
	}, nil
}

type debugPattern struct {
	pattern     *regexp.Regexp
	exclude     *regexp.Regexp // a match on the same line cancels the finding
	description string
	extensions  []string // file extensions to check (empty = all supported)
}

// reDebuggerStatement matches `debugger` used as a statement: alone on its
// line or between statement separators (`if (x) { debugger }`), with an
// optional semicolon, or as a Ruby modifier (`debugger if ENV["X"]`).
var reDebuggerStatement = regexp.MustCompile(`(?:^|[;{}])\s*debugger\s*(?:;|\}|$|\s+(?:if|unless)\b)`)

// reInlineCodeSpan matches a <code> or <pre> element opened and closed on
// the same line: documentation that names a debug call.
var reInlineCodeSpan = regexp.MustCompile(`(?i)<(code|pre)\b[^>]*>.*?</(?:code|pre)>`)

func scanForDebugStatements(rootDir string, ignore []string) []string {
	var findings []string

	// Debug patterns by language
	patterns := []debugPattern{
		// JavaScript/TypeScript (including templates with inline scripts)
		{
			pattern:     regexp.MustCompile(`\bconsole\.(log|debug|info|trace|dir|table)\s*\(`),
			description: "console.log",
			extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".twig", ".blade.php", ".erb", ".ejs", ".hbs", ".njk", ".astro"},
		},
		{
			// The statement, not the word: "og-debugger" in a string or
			// <code>debugger</code> in docs is not a breakpoint.
			pattern:     reDebuggerStatement,
			description: "debugger",
			extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".twig", ".blade.php", ".erb", ".ejs", ".hbs", ".njk", ".astro"},
		},

		// Ruby
		{
			pattern:     regexp.MustCompile(`\bbinding\.pry\b`),
			description: "binding.pry",
			extensions:  []string{".rb", ".erb", ".rake"},
		},
		{
			pattern:     regexp.MustCompile(`\bbyebug\b`),
			description: "byebug",
			extensions:  []string{".rb", ".erb", ".rake"},
		},
		{
			pattern:     regexp.MustCompile(`\bbinding\.irb\b`),
			description: "binding.irb",
			extensions:  []string{".rb", ".erb", ".rake"},
		},
		{
			pattern:     reDebuggerStatement,
			description: "debugger",
			extensions:  []string{".rb", ".erb", ".rake"},
		},
		{
			pattern:     regexp.MustCompile(`\bpp\s+`),
			description: "pp (pretty print)",
			extensions:  []string{".rb", ".erb", ".rake"},
		},

		// PHP
		{
			// The global helpers only: Yaml::dump($config), $dumper->dump()
			// and $collection->dd() are ordinary method calls.
			pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])dd\s*\(`),
			description: "dd()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])dump\s*\(`),
			description: "dump()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bvar_dump\s*\(`),
			description: "var_dump()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			// print_r($x, true) returns the string instead of printing it.
			pattern:     regexp.MustCompile(`\bprint_r\s*\(`),
			exclude:     regexp.MustCompile(`\bprint_r\s*\([^;]*,\s*true\s*\)`),
			description: "print_r()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bray\s*\(`),
			description: "ray() - Spatie Ray debugger",
			extensions:  []string{".php", ".blade.php"},
		},

		// Python
		{
			pattern:     regexp.MustCompile(`\bbreakpoint\s*\(\s*\)`),
			description: "breakpoint()",
			extensions:  []string{".py"},
		},
		{
			pattern:     regexp.MustCompile(`\bpdb\.set_trace\s*\(`),
			description: "pdb.set_trace()",
			extensions:  []string{".py"},
		},
		{
			pattern:     regexp.MustCompile(`\bipdb\.set_trace\s*\(`),
			description: "ipdb.set_trace()",
			extensions:  []string{".py"},
		},
		{
			pattern:     regexp.MustCompile(`\bimport\s+pdb\b`),
			description: "import pdb",
			extensions:  []string{".py"},
		},
		{
			pattern:     regexp.MustCompile(`\bimport\s+ipdb\b`),
			description: "import ipdb",
			extensions:  []string{".py"},
		},

		// Go
		{
			pattern:     regexp.MustCompile(`\bfmt\.Print(ln|f)?\s*\([^)]*"DEBUG`),
			description: "fmt.Print with DEBUG",
			extensions:  []string{".go"},
		},
		{
			pattern:     regexp.MustCompile(`\bspew\.Dump\s*\(`),
			description: "spew.Dump()",
			extensions:  []string{".go"},
		},

		// Rust
		{
			pattern:     regexp.MustCompile(`\bdbg!\s*\(`),
			description: "dbg!()",
			extensions:  []string{".rs"},
		},
		{
			pattern:     regexp.MustCompile(`\btodo!\s*\(`),
			description: "todo!()",
			extensions:  []string{".rs"},
		},
		{
			pattern:     regexp.MustCompile(`\bunimplemented!\s*\(`),
			description: "unimplemented!()",
			extensions:  []string{".rs"},
		},

		// Java/Kotlin
		{
			pattern:     regexp.MustCompile(`\bSystem\.out\.print(ln)?\s*\(`),
			description: "System.out.println()",
			extensions:  []string{".java", ".kt"},
		},

		// Elixir
		{
			pattern:     regexp.MustCompile(`\bIO\.inspect\s*\(`),
			description: "IO.inspect()",
			extensions:  []string{".ex", ".exs"},
		},
		{
			pattern:     regexp.MustCompile(`\bIEx\.pry\b`),
			description: "IEx.pry",
			extensions:  []string{".ex", ".exs"},
		},

		// Twig (Craft CMS, Symfony)
		{
			pattern:     regexp.MustCompile(`\{\{\s*dump\s*\(`),
			description: "{{ dump() }}",
			extensions:  []string{".twig", ".html.twig"},
		},
		{
			pattern:     regexp.MustCompile(`\{%\s*dump\s*`),
			description: "{% dump %}",
			extensions:  []string{".twig", ".html.twig"},
		},
	}

	// Directories to skip
	skipDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		"dist":         true,
		"build":        true,
		".next":        true,
		".nuxt":        true,
		"coverage":     true,
		"__pycache__":  true,
		".cache":       true,
		"tmp":          true,
		"log":          true,
		"logs":         true,
		"storage":      true,
		"cpresources":  true,
		".turbo":       true,
		".vercel":      true,
		".netlify":     true,
		"public":       true,
		"static":       true,
		"_site":        true,
		"out":          true,
		"assets":       true,
		// Agent tooling: vendored skills, and full repo checkouts under
		// .claude/worktrees.
		".claude": true,
		".agents": true,
	}

	// Every pattern is scoped to extensions, so a file whose extension no
	// pattern covers is never read.
	scannedExts := map[string]bool{}
	for _, p := range patterns {
		for _, e := range p.extensions {
			scannedExts[e] = true
		}
	}

	// Bundles, tests and configs, matched anywhere in the file name.
	skipInfixes := []string{
		".min.js",
		".bundle.js",
		".config.js",
		".config.ts",
		".test.",
		".spec.",
		"_test.go",
		"_test.rb",
	}
	// Build tooling and vendored libraries, matched as the start of the
	// file name only: a bare substring hid members.ts ("ember"),
	// moments.ts ("moment") and piechart.tsx ("chart.") from the scan.
	skipPrefixes := []string{
		"webpack.config",
		"vite.config",
		// Build scripts log to the terminal by design and never ship.
		"gulpfile",
		"gruntfile",
		"jest.config",
		"vitest.config",
		"tailwind.config",
		"postcss.config",
		"eslint",
		"eslintrc",
		"prettier",
		"prettierrc",
		"test_",
		"alpine",
		"jquery",
		"lodash",
		"underscore",
		"react.",
		"react-dom",
		"vue.",
		"angular",
		"ember",
		"backbone",
		"moment",
		"axios",
		"d3.",
		"chart.",
		"three.",
		"gsap",
		"anime.",
		"htmx",
		"hyperscript",
		"turbo",
		"stimulus",
	}
	skipFile := func(name string) bool {
		for _, s := range skipInfixes {
			if strings.Contains(name, s) {
				return true
			}
		}
		name = strings.TrimLeft(name, ".") // .eslintrc.js, .prettierrc.cjs
		for _, p := range skipPrefixes {
			if !strings.HasPrefix(name, p) {
				continue
			}
			// "jquery.js", "jquery-3.7.js" and "htmx_ext.js" are the library;
			// "moments.ts" and "turbocharge.ts" are the project's own code.
			rest := name[len(p):]
			if strings.HasSuffix(p, ".") || strings.HasSuffix(p, "_") || rest == "" || strings.ContainsRune(".-_", rune(rest[0])) {
				return true
			}
		}
		return false
	}

	// Walk the project
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories
		if d.IsDir() {
			if path != rootDir && (skipDirs[d.Name()] || toolchainDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks, devices, pipes — same path-traversal / DoS
		// concern as the secrets walker (e.g. a symlink to /dev/zero
		// would let os.ReadFile bypass the 500KB size cap below).
		if !d.Type().IsRegular() {
			return nil
		}

		// Honor user-configured ignore globs (the top-level `ignore` list in
		// preflight.yml), so build tooling, vendored code, or files that only
		// mention debug calls in strings/docs can be excluded.
		if rel, relErr := filepath.Rel(rootDir, path); relErr == nil {
			rel = filepath.ToSlash(rel)
			for _, g := range ignore {
				if ok, _ := doublestar.Match(filepath.ToSlash(g), rel); ok {
					return nil
				}
			}
		}

		// Check if file should be skipped
		if skipFile(strings.ToLower(d.Name())) {
			return nil
		}

		// Get file extension
		ext := strings.ToLower(filepath.Ext(path))

		// Handle .blade.php
		if strings.HasSuffix(path, ".blade.php") {
			ext = ".blade.php"
		}
		if !scannedExts[ext] {
			return nil
		}

		// Skip files larger than 500KB
		info, err := d.Info()
		if err != nil || info.Size() > 500*1024 {
			return nil
		}

		// Read file content
		content, err := readSourceFile(path)
		if err != nil {
			return nil
		}

		// Check each line for patterns. Multi-line block comments are blanked
		// first (newlines kept, so line numbers hold): a console.log inside a
		// /* ... */ or <!-- ... --> spanning several lines is commented out,
		// and no per-line test can tell.
		lines := strings.Split(blankBlockComments(string(content)), "\n")
		for lineNum, line := range lines {
			// Skip commented lines (basic check). This only catches whole-line
			// comments; hash-style ones in particular have to be handled here,
			// because stripCodeComments deliberately leaves "#" alone (it is a
			// CSS selector and a YAML key as often as it is a comment).
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "//") ||
				strings.HasPrefix(trimmedLine, "#") ||
				strings.HasPrefix(trimmedLine, "*") ||
				strings.HasPrefix(trimmedLine, "/*") ||
				strings.HasPrefix(trimmedLine, "{#") ||
				strings.HasPrefix(trimmedLine, "<!--") {
				continue
			}

			// A debug statement named in a trailing comment is not a debug
			// statement: `doWork(); // console.log(x) if this breaks` is real
			// code plus a note. The prefix check above can't see those, so
			// strip inline comments before matching. stripCodeComments leaves
			// URLs intact, so a logged https:// link keeps its line.
			line = stripCodeComments(line)
			// <code>console.log()</code> on one line is documentation.
			line = reInlineCodeSpan.ReplaceAllString(line, "")

			for _, p := range patterns {
				// Check if this pattern applies to this file type
				if len(p.extensions) > 0 {
					matches := false
					for _, e := range p.extensions {
						if ext == e {
							matches = true
							break
						}
					}
					if !matches {
						continue
					}
				}

				if p.pattern.MatchString(line) && (p.exclude == nil || !p.exclude.MatchString(line)) {
					if !isDevGuarded(lines, lineNum) && !isInCodeExample(lines, lineNum) {
						relPath := relPath(rootDir, path)
						findings = append(findings, fmt.Sprintf("%s:%d - %s", relPath, lineNum+1, p.description))
					}
				}
			}
		}

		return nil
	})

	return findings
}

func isDevGuarded(lines []string, lineNum int) bool {
	devPatterns := []string{
		// JavaScript/Node.js
		"process.env.NODE_ENV",
		"NODE_ENV",
		"import.meta.env.DEV",
		"import.meta.env.MODE",
		"import.meta.env.PROD",
		"__DEV__",
		"isDev",
		"isDevelopment",
		"isDebug",
		"!production",
		"!== 'production'",
		"!= 'production'",
		"=== 'development'",
		"== 'development'",

		// Vite/Astro
		"import.meta.env.SSR",

		// SvelteKit
		"from '$app/environment'",
		"if (dev)",
		"if(dev)",

		// PHP/Laravel
		"config('app.debug')",
		"config('app.env')",
		"app()->environment",
		"app()->isLocal()",
		"App::environment",
		"App::isLocal()",
		"env('APP_DEBUG')",
		"env('APP_ENV')",
		"APP_DEBUG",
		"APP_ENV",

		// Craft CMS (Twig)
		"devMode",
		"craft.app.config.general.devMode",
		"{% if devmode",
		"{% if craft.app.config.general.devmode",

		// Symfony (Twig)
		"app.debug",
		"app.environment",
		"{% if app.debug",
		"{% if app.environment",

		// Django/Python
		"settings.DEBUG",
		"DEBUG =",
		"DEBUG=",
		"if settings.DEBUG",
		"os.environ",
		"os.getenv",
		"DJANGO_DEBUG",
		"FLASK_DEBUG",
		"FLASK_ENV",

		// Ruby on Rails
		"Rails.env.development",
		"Rails.env.local",
		"Rails.env.test",
		"Rails.env.development?",
		"<% if Rails.env.development",
		"unless Rails.env.production",

		// Go
		"gin.DebugMode",
		"GO_ENV",
		"GIN_MODE",

		// Rust
		"#[cfg(debug_assertions)]",
		"cfg!(debug_assertions)",
		"debug_assertions",

		// ASP.NET/C#
		"IsDevelopment()",
		"Environment.IsDevelopment",
		"#if DEBUG",
		"ASPNETCORE_ENVIRONMENT",

		// Elixir/Phoenix
		"Mix.env()",
		":dev",
		"Application.get_env",

		// Hugo
		".Site.IsServer",
		"hugo.IsServer",

		// Jekyll
		"jekyll.environment",

		// Blade (Laravel)
		"@if(config('app.debug'))",
		"@if(app()->isLocal())",
		"@env('local')",
		"@production",
		"@unless(app()->environment('production'))",
	}

	// Look up to 10 lines back to find dev guards (handles nested code)
	start := lineNum - 10
	if start < 0 {
		start = 0
	}

	for i := start; i <= lineNum; i++ {
		// Strip line/block comments first so a nearby comment that
		// happens to mention NODE_ENV (or whatever) doesn't get
		// mis-read as an actual guard expression.
		line := stripCodeComments(lines[i])
		// A guard is a condition. Reading an env value nearby
		// (const api = import.meta.env.VITE_API_URL) guards nothing.
		if !reConditional.MatchString(line) {
			continue
		}
		lineLower := strings.ToLower(line)
		for _, pattern := range devPatterns {
			if devGuardMatches(lineLower, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

// reConditional matches the syntax of a condition or a conditional block in
// the languages devPatterns covers: if/unless/when, ternaries, short-circuit
// operators, preprocessor and attribute guards, and template conditionals.
var reConditional = regexp.MustCompile(`\b(?:if|unless|elif|elsif|when)\b|&&|\|\||\?|#\[cfg|cfg!|@env|@production|@unless`)

// reIdentifierToken matches a dev-guard token that is a bare identifier.
var reIdentifierToken = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// devGuardMatches reports whether lineLower contains the guard token. Bare
// identifiers must match as whole words, so isDev does not match
// isDeviceMobile; every other token is distinctive enough as a substring.
func devGuardMatches(lineLower, token string) bool {
	if !reIdentifierToken.MatchString(token) {
		return strings.Contains(lineLower, token)
	}
	for i := strings.Index(lineLower, token); i >= 0; {
		end := i + len(token)
		if (i == 0 || !isIdentByte(lineLower[i-1])) && (end == len(lineLower) || !isIdentByte(lineLower[end])) {
			return true
		}
		next := strings.Index(lineLower[i+1:], token)
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z'
}

// heredocStart matches Ruby heredocs: <<~WORD, <<-WORD, <<WORD. Package
// level because isInCodeExample runs once per debug-statement match.
var heredocStart = regexp.MustCompile(`<<[~-]?([A-Z_]+)`)

// isInCodeExample checks if a line is inside a documentation code block or example
func isInCodeExample(lines []string, lineNum int) bool {
	// Look for code block markers in surrounding lines
	start := lineNum - 30
	if start < 0 {
		start = 0
	}

	// Track if we're inside a code block
	inHeredoc := false
	heredocMarker := ""
	inMarkdownCode := false
	inHTMLCode := false

	for i := start; i <= lineNum; i++ {
		line := lines[i]
		lineLower := strings.ToLower(line)

		// Ruby heredocs (<<~CODE, <<-CODE, <<CODE, <<~JAVASCRIPT, etc.)
		if !inHeredoc {
			if matches := heredocStart.FindStringSubmatch(line); len(matches) > 1 {
				inHeredoc = true
				heredocMarker = matches[1]
			}
		} else {
			// End of heredoc - marker alone on a line (possibly indented for <<~)
			trimmed := strings.TrimSpace(line)
			if trimmed == heredocMarker {
				inHeredoc = false
				heredocMarker = ""
			}
		}

		// Markdown code blocks
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inMarkdownCode = !inMarkdownCode
		}

		// HTML code/pre tags
		if strings.Contains(lineLower, "<code") || strings.Contains(lineLower, "<pre") {
			inHTMLCode = true
		}
		if strings.Contains(lineLower, "</code>") || strings.Contains(lineLower, "</pre>") {
			inHTMLCode = false
		}
	}

	// If we're at lineNum and inside any code block, return true
	if inHeredoc || inMarkdownCode || inHTMLCode {
		return true
	}

	// Also check if the line itself looks like documentation
	line := lines[lineNum]
	lineLower := strings.ToLower(line)

	// Common documentation patterns
	docPatterns := []string{
		"// example",
		"# example",
		"/* example",
		"<!-- example",
		"{# example",
		"example:",
		"usage:",
		"sample:",
		"demo:",
	}

	for _, pattern := range docPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	return false
}
