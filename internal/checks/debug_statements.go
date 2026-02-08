package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type DebugStatementsCheck struct{}

func (c DebugStatementsCheck) ID() string {
	return "debug_statements"
}

func (c DebugStatementsCheck) Title() string {
	return "Debug statements"
}

func (c DebugStatementsCheck) Run(ctx Context) (CheckResult, error) {
	findings := scanForDebugStatements(ctx.RootDir)

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
	description string
	extensions  []string // file extensions to check (empty = all supported)
}

func scanForDebugStatements(rootDir string) []string {
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
			pattern:     regexp.MustCompile(`\bdebugger\b`),
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
			pattern:     regexp.MustCompile(`\bdebugger\b`),
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
			pattern:     regexp.MustCompile(`\bdd\s*\(`),
			description: "dd()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bdump\s*\(`),
			description: "dump()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bvar_dump\s*\(`),
			description: "var_dump()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bprint_r\s*\(`),
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
		"node_modules":   true,
		"vendor":         true,
		".git":           true,
		"dist":           true,
		"build":          true,
		".next":          true,
		".nuxt":          true,
		"coverage":       true,
		"__pycache__":    true,
		".cache":         true,
		"tmp":            true,
		"log":            true,
		"logs":           true,
		"storage":        true,
		"cpresources":    true,
		".turbo":         true,
		".vercel":        true,
		".netlify":       true,
		"public":         true,
		"static":         true,
		"_site":          true,
		"out":            true,
		"assets":         true,
	}

	skipFiles := []string{
		".min.js",
		".bundle.js",
		".config.js",
		".config.ts",
		"webpack.config",
		"vite.config",
		"jest.config",
		"vitest.config",
		"tailwind.config",
		"postcss.config",
		"eslint",
		"prettier",
		".test.",
		".spec.",
		"_test.go",
		"_test.rb",
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

	// Walk the project
	filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file should be skipped
		filename := strings.ToLower(d.Name())
		for _, skip := range skipFiles {
			if strings.Contains(filename, skip) {
				return nil
			}
		}

		// Get file extension
		ext := strings.ToLower(filepath.Ext(path))

		// Handle .blade.php
		if strings.HasSuffix(path, ".blade.php") {
			ext = ".blade.php"
		}

		// Skip files larger than 500KB
		info, err := d.Info()
		if err != nil || info.Size() > 500*1024 {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Check each line for patterns
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			// Skip commented lines (basic check)
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "//") ||
				strings.HasPrefix(trimmedLine, "#") ||
				strings.HasPrefix(trimmedLine, "*") ||
				strings.HasPrefix(trimmedLine, "/*") ||
				strings.HasPrefix(trimmedLine, "{#") ||
				strings.HasPrefix(trimmedLine, "<!--") {
				continue
			}

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

				if p.pattern.MatchString(line) {
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
		"import.meta.env",

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

		// General
		"development",
		"localhost",
		"127.0.0.1",
	}

	// Look up to 10 lines back to find dev guards (handles nested code)
	start := lineNum - 10
	if start < 0 {
		start = 0
	}

	for i := start; i <= lineNum; i++ {
		lineLower := strings.ToLower(lines[i])
		for _, pattern := range devPatterns {
			if strings.Contains(lineLower, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

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

	// Regex to match Ruby heredocs: <<~WORD, <<-WORD, <<WORD
	heredocStart := regexp.MustCompile(`<<[~-]?([A-Z_]+)`)

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
