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
		regexp.MustCompile(`G-[A-Z0-9]+`), // GA4 measurement ID
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

	// Check for Redis configuration in common locations
	configPatterns := []*regexp.Regexp{
		regexp.MustCompile(`redis://`),
		regexp.MustCompile(`Redis\.new`),
		regexp.MustCompile(`Redis\.current`),
		regexp.MustCompile(`createClient.*redis`),
		regexp.MustCompile(`new Redis\(`),
		regexp.MustCompile(`ioredis`),
		regexp.MustCompile(`@upstash/redis`),
		regexp.MustCompile(`Upstash`),
	}

	configFiles := []string{
		"config/redis.yml",
		"config/cable.yml",
		"config/sidekiq.yml",
		"config/initializers/redis.rb",
		"config/initializers/sidekiq.rb",
		"src/config/redis.ts",
		"src/lib/redis.ts",
		"src/redis.ts",
		"lib/redis.js",
		"lib/redis.ts",
	}

	// Also check monorepo structures
	monorepoRoots := []string{"apps", "packages", "services"}
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(ctx.RootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// Add monorepo paths
			configFiles = append(configFiles,
				filepath.Join(monoRoot, entry.Name(), "src", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "src", "lib", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "src", "config", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "lib", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "lib", "redis.js"),
			)
		}
	}

	for _, file := range configFiles {
		path := filepath.Join(ctx.RootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, pattern := range configPatterns {
			if pattern.Match(content) {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "Redis configuration found",
				}, nil
			}
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
func searchForPatterns(rootDir, stack string, patterns []*regexp.Regexp) bool {
	layoutFiles := getLayoutFilesForStack(stack)

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

	// Search in common directories across all stacks
	searchDirs := []string{
		".", // root directory
		// Frontend
		"src", "app", "components", "pages", "lib",
		// Monorepo patterns
		"apps", "packages",
		// PHP
		"includes", "partials", "inc",
		// Templates
		"templates", "views", "layouts", "_layouts", "_includes",
		// Public/Static
		"public", "web", "static", "dist", "www", "_site", "out",
		// Rails
		"app/views", "app/views/layouts",
		// Laravel
		"resources/views", "resources/views/layouts",
		// WordPress
		"wp-content/themes",
		// Craft CMS
		"templates/_partials",
		// Hugo
		"layouts/_default", "layouts/partials",
		// SvelteKit
		"src/routes",
		// Gatsby
		"gatsby-browser.js",
	}
	extensions := []string{
		// JavaScript/TypeScript
		".tsx", ".jsx", ".js", ".ts", ".mjs", ".cjs",
		// PHP
		".php",
		// Template engines
		".twig", ".blade.php", ".erb", ".haml", ".slim",
		".ejs", ".pug", ".hbs", ".handlebars", ".mustache",
		".njk", ".liquid",
		// HTML
		".html", ".htm",
		// Frontend frameworks
		".vue", ".svelte", ".astro",
		// Python
		".py",
		// Ruby
		".rb",
		// Go
		".go", ".tmpl", ".gohtml",
	}

	for _, dir := range searchDirs {
		dirPath := filepath.Join(rootDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		found := false
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || found {
				return nil
			}

			// Skip common build/dependency directories
			baseName := filepath.Base(path)
			if info.IsDir() {
				if baseName == "node_modules" || baseName == "vendor" ||
					baseName == ".git" || baseName == "dist" ||
					baseName == "build" || baseName == "cache" ||
					baseName == ".next" || baseName == ".turbo" ||
					baseName == "coverage" || baseName == "__pycache__" ||
					baseName == "_generated" || baseName == ".convex" {
					return filepath.SkipDir
				}
				return nil
			}

			ext := filepath.Ext(path)
			validExt := false
			for _, e := range extensions {
				if ext == e {
					validExt = true
					break
				}
			}
			if !validExt {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			for _, pattern := range patterns {
				if pattern.Match(content) {
					found = true
					return filepath.SkipAll
				}
			}

			return nil
		})

		if found {
			return true
		}
	}

	return false
}

// SearchMatch contains details about a pattern match
type SearchMatch struct {
	FilePath string
	Pattern  string
}

// searchForPatternsWithDetails searches for patterns and returns details about the match
func searchForPatternsWithDetails(rootDir, stack string, patterns []*regexp.Regexp) *SearchMatch {
	layoutFiles := getLayoutFilesForStack(stack)

	for _, file := range layoutFiles {
		path := filepath.Join(rootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, pattern := range patterns {
			if pattern.Match(content) {
				relPath, _ := filepath.Rel(rootDir, path)
				return &SearchMatch{
					FilePath: relPath,
					Pattern:  pattern.String(),
				}
			}
		}
	}

	// Search in common directories across all stacks
	searchDirs := []string{
		".", // root directory
		// Frontend
		"src", "app", "components", "pages", "lib",
		// Monorepo patterns
		"apps", "packages",
		// PHP
		"includes", "partials", "inc",
		// Templates
		"templates", "views", "layouts", "_layouts", "_includes",
		// Public/Static
		"public", "web", "static", "dist", "www", "_site", "out",
		// Rails
		"app/views", "app/views/layouts",
		// Laravel
		"resources/views", "resources/views/layouts",
		// WordPress
		"wp-content/themes",
		// Craft CMS
		"templates/_partials",
		// Hugo
		"layouts/_default", "layouts/partials",
		// SvelteKit
		"src/routes",
		// Gatsby
		"gatsby-browser.js",
	}
	extensions := []string{
		// JavaScript/TypeScript
		".tsx", ".jsx", ".js", ".ts", ".mjs", ".cjs",
		// PHP
		".php",
		// Template engines
		".twig", ".blade.php", ".erb", ".haml", ".slim",
		".ejs", ".pug", ".hbs", ".handlebars", ".mustache",
		".njk", ".liquid",
		// HTML
		".html", ".htm",
		// Frontend frameworks
		".vue", ".svelte", ".astro",
		// Python
		".py",
		// Ruby
		".rb",
		// Go
		".go", ".tmpl", ".gohtml",
	}

	var result *SearchMatch
	for _, dir := range searchDirs {
		dirPath := filepath.Join(rootDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || result != nil {
				return nil
			}

			// Skip common build/dependency directories
			baseName := filepath.Base(path)
			if info.IsDir() {
				if baseName == "node_modules" || baseName == "vendor" ||
					baseName == ".git" || baseName == "dist" ||
					baseName == "build" || baseName == "cache" ||
					baseName == ".next" || baseName == ".turbo" ||
					baseName == "coverage" || baseName == "__pycache__" ||
					baseName == "_generated" || baseName == ".convex" {
					return filepath.SkipDir
				}
				return nil
			}

			ext := filepath.Ext(path)
			validExt := false
			for _, e := range extensions {
				if ext == e {
					validExt = true
					break
				}
			}
			if !validExt {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			for _, pattern := range patterns {
				if pattern.Match(content) {
					relPath, _ := filepath.Rel(rootDir, path)
					result = &SearchMatch{
						FilePath: relPath,
						Pattern:  pattern.String(),
					}
					return filepath.SkipAll
				}
			}

			return nil
		})

		if result != nil {
			return result
		}
	}

	return nil
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
