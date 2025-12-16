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
		// JavaScript/TypeScript
		{
			pattern:     regexp.MustCompile(`\bconsole\.(log|debug|info|trace|dir|table)\s*\(`),
			description: "console.log",
			extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
		},
		{
			pattern:     regexp.MustCompile(`\bdebugger\b`),
			description: "debugger",
			extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
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
			pattern:     regexp.MustCompile(`\bdie\s*\(`),
			description: "die()",
			extensions:  []string{".php", ".blade.php"},
		},
		{
			pattern:     regexp.MustCompile(`\bexit\s*\(`),
			description: "exit()",
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
		"public":         true, // Usually compiled assets
		"static":         true,
		"_site":          true,
		"out":            true,
	}

	// Files/patterns to skip
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
					relPath, _ := filepath.Rel(rootDir, path)
					findings = append(findings, fmt.Sprintf("%s:%d - %s", relPath, lineNum+1, p.description))
				}
			}
		}

		return nil
	})

	return findings
}
