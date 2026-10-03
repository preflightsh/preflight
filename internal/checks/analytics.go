package checks

import (
	"os"
	"path/filepath"
	"regexp"
)

// FathomCheck verifies Fathom Analytics is properly set up
type FathomCheck struct{}

func (c FathomCheck) ID() string {
	return "fathom"
}

func (c FathomCheck) Title() string {
	return "Fathom Analytics"
}

func (c FathomCheck) Run(ctx Context) (CheckResult, error) {
	fathomService, declared := ctx.Config.Services["fathom"]
	if !declared || !fathomService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fathom not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`usefathom\.com`),
		regexp.MustCompile(`cdn\.usefathom\.com`),
		regexp.MustCompile(`fathom\.trackPageview`),
		regexp.MustCompile(`data-site=`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fathom Analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Fathom is declared but script not found in templates",
		Suggestions: []string{
			"Add the Fathom script tag to your main layout",
			"Example: <script src=\"https://cdn.usefathom.com/script.js\" data-site=\"XXXXX\" defer></script>",
		},
	}, nil
}

// GoogleAnalyticsCheck verifies Google Analytics is properly set up
type GoogleAnalyticsCheck struct{}

func (c GoogleAnalyticsCheck) ID() string {
	return "google_analytics"
}

func (c GoogleAnalyticsCheck) Title() string {
	return "Google Analytics"
}

func (c GoogleAnalyticsCheck) Run(ctx Context) (CheckResult, error) {
	gaService, declared := ctx.Config.Services["google_analytics"]
	if !declared || !gaService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Google Analytics not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`googletagmanager\.com`),
		regexp.MustCompile(`google-analytics\.com`),
		regexp.MustCompile(`gtag\(`),
		regexp.MustCompile(`ga\(`),
		regexp.MustCompile(`GoogleAnalyticsObject`),
		regexp.MustCompile(`G-[A-Z0-9]+`),      // GA4 measurement ID
		regexp.MustCompile(`UA-[0-9]+-[0-9]+`), // Universal Analytics
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Google Analytics configuration found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Google Analytics is declared but not found in templates",
		Suggestions: []string{
			"Add Google Analytics/GTM script to your main layout",
			"Consider using GA4 with gtag.js for modern tracking",
		},
	}, nil
}

// RedisCheck verifies Redis connection is configured
type RedisCheck struct{}

func (c RedisCheck) ID() string {
	return "redis"
}

func (c RedisCheck) Title() string {
	return "Redis"
}

func (c RedisCheck) Run(ctx Context) (CheckResult, error) {
	redisService, declared := ctx.Config.Services["redis"]
	if !declared || !redisService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Redis not declared, skipping",
		}, nil
	}

	// Check for Redis configuration patterns
	configPatterns := []*regexp.Regexp{
		regexp.MustCompile(`redis://`),
		regexp.MustCompile(`Redis\.new`),
		regexp.MustCompile(`Redis\.current`),
		regexp.MustCompile(`createClient.*redis`),
		regexp.MustCompile(`new Redis\(`),
		regexp.MustCompile(`ioredis`),
		regexp.MustCompile(`@upstash/redis`),
		regexp.MustCompile(`Upstash`),
		// Vercel KV (powered by Upstash Redis)
		regexp.MustCompile(`@vercel/kv`),
		regexp.MustCompile(`from\s+['"]@vercel/kv['"]`),
		regexp.MustCompile(`kv\.(get|set|del|hget|hset|incr|expire)`),
	}

	// First, do a codebase-wide search for Redis patterns
	if match := searchForPatterns(ctx.RootDir, ctx.Config.Stack, configPatterns); match {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Redis configuration found",
		}, nil
	}

	// Also check specific config files for traditional setups
	configFiles := []string{
		"config/redis.yml",
		"config/cable.yml",
		"config/sidekiq.yml",
		"config/initializers/redis.rb",
		"config/initializers/sidekiq.rb",
	}

	for _, file := range configFiles {
		path := filepath.Join(ctx.RootDir, file)
		if _, err := os.Stat(path); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Redis configuration found",
			}, nil
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Redis is declared but configuration not found",
		Suggestions: []string{
			"Ensure REDIS_URL is set in your environment",
			"Add Redis initializer or configuration file",
		},
	}, nil
}

// SidekiqCheck verifies Sidekiq is configured (Rails)
type SidekiqCheck struct{}

func (c SidekiqCheck) ID() string {
	return "sidekiq"
}

func (c SidekiqCheck) Title() string {
	return "Sidekiq"
}

func (c SidekiqCheck) Run(ctx Context) (CheckResult, error) {
	sidekiqService, declared := ctx.Config.Services["sidekiq"]
	if !declared || !sidekiqService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Sidekiq not declared, skipping",
		}, nil
	}

	configFiles := []string{
		"config/sidekiq.yml",
		"config/initializers/sidekiq.rb",
	}

	for _, file := range configFiles {
		path := filepath.Join(ctx.RootDir, file)
		if _, err := os.Stat(path); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sidekiq configuration found",
			}, nil
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Sidekiq is declared but configuration not found",
		Suggestions: []string{
			"Create config/sidekiq.yml with queue configuration",
			"Add Sidekiq initializer for Redis connection",
		},
	}, nil
}

// Helper function to search for patterns in layout files
// dependencyManifests are the package manifests scanned for an integration's
// library name. A declared dependency (e.g. craft-amazon-ses in composer.json,
// @sendgrid/mail in package.json) means the integration is installed even when
// its credentials live outside the repo — a CMS control panel, a platform's
// environment — so a service check shouldn't report it as unconfigured.
var dependencyManifests = []string{
	"composer.json", "package.json", "Gemfile",
	"requirements.txt", "pyproject.toml", "Pipfile", "go.mod",
}

// scanDependencyManifests reports whether any pattern matches a package manifest
// at rootDir, returning the manifest's name on the first hit. Matches raw
// content (manifests are JSON/text, not commented source).
func scanDependencyManifests(rootDir string, patterns []*regexp.Regexp) (string, bool) {
	for _, name := range dependencyManifests {
		content, err := os.ReadFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}
		for _, pattern := range patterns {
			if pattern.Match(content) {
				return name, true
			}
		}
	}
	return "", false
}

func searchForPatterns(rootDir, stack string, patterns []*regexp.Regexp) bool {
	layoutFiles := getLayoutFilesForStack(stack)

	// A declared dependency in a package manifest counts as the integration
	// being present, since credentials are often managed outside the repo.
	if _, ok := scanDependencyManifests(rootDir, patterns); ok {
		return true
	}

	for _, file := range layoutFiles {
		path := filepath.Join(rootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, pattern := range patterns {
			if pattern.Match(content) {
				return true
			}
		}
	}

	return walkSourceFiles(rootDir, func(_ string, content []byte) bool {
		for _, pattern := range patterns {
			if pattern.Match(content) {
				return true
			}
		}
		return false
	})
}

// SearchMatch contains details about a pattern match
type SearchMatch struct {
	FilePath string
	Pattern  string
}

// searchForPatternsWithDetails searches for patterns and returns details about the match
func searchForPatternsWithDetails(rootDir, stack string, patterns []*regexp.Regexp) *SearchMatch {
	layoutFiles := getLayoutFilesForStack(stack)

	// A declared dependency in a package manifest counts as the integration
	// being present, since credentials are often managed outside the repo.
	if name, ok := scanDependencyManifests(rootDir, patterns); ok {
		return &SearchMatch{FilePath: name, Pattern: "dependency manifest"}
	}

	for _, file := range layoutFiles {
		path := filepath.Join(rootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Strip comments to avoid false positives on commented-out code
		contentStr := stripComments(string(content))

		for _, pattern := range patterns {
			if pattern.MatchString(contentStr) {
				relPath := relPath(rootDir, path)
				return &SearchMatch{
					FilePath: relPath,
					Pattern:  pattern.String(),
				}
			}
		}
	}

	var result *SearchMatch
	walkSourceFiles(rootDir, func(path string, content []byte) bool {
		// Strip comments to avoid false positives on commented-out code
		contentStr := stripComments(string(content))

		for _, pattern := range patterns {
			if pattern.MatchString(contentStr) {
				result = &SearchMatch{
					FilePath: relPath(rootDir, path),
					Pattern:  pattern.String(),
				}
				return true
			}
		}
		return false
	})
	return result
}

// sourceExtensions are the file types searchForPatterns and
// searchForPatternsWithDetails look inside when walking the project.
var sourceExtensions = map[string]bool{
	// JavaScript/TypeScript
	".tsx": true, ".jsx": true, ".js": true, ".ts": true, ".mjs": true, ".cjs": true,
	// PHP
	".php": true,
	// Template engines
	".twig": true, ".erb": true, ".haml": true, ".slim": true,
	".ejs": true, ".pug": true, ".hbs": true, ".handlebars": true, ".mustache": true,
	".njk": true, ".liquid": true,
	// HTML
	".html": true, ".htm": true,
	// Frontend frameworks
	".vue": true, ".svelte": true, ".astro": true,
	// Python
	".py": true,
	// Ruby
	".rb": true,
	// Go
	".go": true, ".tmpl": true, ".gohtml": true,
}

// walkSourceFiles calls visit with the content of every source file in the
// project, skipping dependency trees and build output, until visit returns
// true. It reports whether visit did.
//
// This replaces a walk of "." followed by walks of src, app, packages and
// other common subdirectories: "." already covered them, so on a miss
// every one of them was walked a second time.
func walkSourceFiles(rootDir string, visit func(path string, content []byte) bool) bool {
	found := false
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Skip common build/dependency directories, but never the root
		// itself (a project can live in a directory named build or deps).
		if d.IsDir() {
			if path == rootDir {
				return nil
			}
			switch name := d.Name(); name {
			case "node_modules", "vendor", ".git", "dist", "build", "cache",
				".next", ".turbo", "coverage", "__pycache__", "_generated",
				".convex", ".claude", ".agents":
				return filepath.SkipDir
			default:
				if toolchainDirs[name] {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !sourceExtensions[filepath.Ext(path)] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if visit(path, content) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func getLayoutFilesForStack(stack string) []string {
	layouts := map[string][]string{
		// Backend Frameworks
		"rails":   {"app/views/layouts/application.html.erb", "app/views/layouts/application.html.haml"},
		"laravel": {"resources/views/layouts/app.blade.php", "resources/views/app.blade.php"},
		"django":  {"templates/base.html", "templates/layout.html", "templates/index.html"},
		"python":  {"templates/base.html", "templates/layout.html", "templates/index.html"},
		"go":      {"templates/base.html", "templates/layout.html", "views/base.html", "web/templates/base.html"},
		"rust":    {"templates/base.html", "templates/layout.html"},
		"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs", "views/layouts/main.hbs"},

		// Frontend Frameworks
		"next":    {"app/layout.tsx", "app/layout.js", "pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js", "src/app/layout.tsx"},
		"react":   {"src/App.tsx", "src/App.jsx", "src/App.js", "src/index.tsx", "src/index.jsx", "public/index.html"},
		"vue":     {"src/App.vue", "src/main.ts", "src/main.js", "index.html", "public/index.html"},
		"vite":    {"index.html", "src/App.tsx", "src/App.jsx", "src/App.vue", "src/App.svelte"},
		"svelte":  {"src/App.svelte", "src/routes/+layout.svelte", "src/app.html"},
		"angular": {"src/index.html", "src/app/app.component.ts", "src/app/app.component.html"},

		// Traditional CMS
		"wordpress": {"wp-content/themes/theme/header.php", "wp-content/themes/theme/functions.php", "header.php"},
		"craft":     {"templates/_layout.twig", "templates/_layout.html", "templates/_partials/head.twig"},
		"drupal":    {"themes/custom/theme/templates/html.html.twig", "web/themes/custom/theme/templates/html.html.twig"},
		"ghost":     {"content/themes/casper/default.hbs", "default.hbs"},

		// Static Site Generators
		"hugo":     {"layouts/_default/baseof.html", "themes/theme/layouts/_default/baseof.html", "layouts/partials/head.html"},
		"jekyll":   {"_layouts/default.html", "_includes/head.html", "_includes/header.html"},
		"gatsby":   {"src/components/layout.js", "src/components/layout.tsx", "src/html.js", "gatsby-browser.js"},
		"eleventy": {"_includes/layout.njk", "_includes/base.njk", "_includes/layout.liquid", "src/_includes/layout.njk"},
		"astro":    {"src/layouts/Layout.astro", "src/layouts/BaseLayout.astro", "src/components/Head.astro"},

		// Headless CMS (frontend detection)
		"strapi":     {"src/index.js", "config/server.js"},
		"sanity":     {"sanity.config.ts", "sanity.config.js"},
		"contentful": {"src/templates/page.js", "src/App.js"},
		"prismic":    {"src/components/Layout.js", "slicemachine.config.json"},

		// Generic PHP
		"php": {"header.php", "includes/header.php", "partials/header.php", "templates/header.php", "inc/header.php"},

		// Static
		"static": {"index.html", "public/index.html", "dist/index.html"},
	}

	if files, ok := layouts[stack]; ok {
		return files
	}
	return []string{"index.html", "public/index.html"}
}
