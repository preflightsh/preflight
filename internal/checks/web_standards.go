package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RobotsTxtCheck verifies robots.txt exists
type RobotsTxtCheck struct{}

func (c RobotsTxtCheck) ID() string {
	return "robotsTxt"
}

func (c RobotsTxtCheck) Title() string {
	return "robots.txt"
}

func (c RobotsTxtCheck) Run(ctx Context) (CheckResult, error) {
	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"",        // Root directory
	}

	for _, root := range webRoots {
		var path string
		if root == "" {
			path = "robots.txt"
		} else {
			path = root + "/robots.txt"
		}
		fullPath := filepath.Join(ctx.RootDir, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			// Check if it has meaningful content
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "robots.txt found at " + path,
				}, nil
			}
		}
	}

	// Check monorepo public directories for static robots.txt
	monorepoStaticPaths := findMonorepoPublicFiles(ctx.RootDir, "robots.txt")
	for _, path := range monorepoStaticPaths {
		if content, err := os.ReadFile(path); err == nil {
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				relPath, _ := filepath.Rel(ctx.RootDir, path)
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "robots.txt found at " + relPath,
				}, nil
			}
		}
	}

	// Check for dynamic robots.txt generation across JS/TS frameworks
	jsRobotsPaths := []string{
		// Next.js App Router
		"app/robots.ts", "app/robots.tsx", "app/robots.js", "app/robots.jsx",
		"src/app/robots.ts", "src/app/robots.tsx", "src/app/robots.js", "src/app/robots.jsx",
		// SvelteKit
		"src/routes/robots.txt/+server.ts", "src/routes/robots.txt/+server.js",
		// Nuxt
		"server/routes/robots.txt.ts", "server/routes/robots.txt.js",
		"server/routes/robots.txt.get.ts", "server/routes/robots.txt.get.js",
		// Remix
		"app/routes/robots[.]txt.ts", "app/routes/robots[.]txt.tsx",
		"app/routes/robots.txt.ts", "app/routes/robots.txt.tsx",
		// Angular
		"src/assets/robots.txt",
		// Eleventy
		"src/robots.txt.njk", "src/robots.txt.liquid", "robots.txt.njk", "robots.txt.liquid",
	}

	for _, path := range jsRobotsPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "robots.txt generated via " + path,
			}, nil
		}
	}

	// Check monorepo structures for Next.js App Router robots
	monorepoRobotsPaths := findMonorepoNextFiles(ctx.RootDir, []string{"robots.ts", "robots.tsx", "robots.js", "robots.jsx"})
	for _, path := range monorepoRobotsPaths {
		if _, err := os.Stat(path); err == nil {
			relPath, _ := filepath.Rel(ctx.RootDir, path)
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "robots.txt generated via " + relPath,
			}, nil
		}
	}

	// Flexible search: walk app/ and src/app/ for robots files in any location
	// This catches route groups like app/(marketing)/robots.ts
	robotsFound := false
	var robotsFoundPath string
	flexRobotsDirs := []string{"app", "src/app"}
	for _, dir := range flexRobotsDirs {
		if robotsFound {
			break
		}
		dirPath := filepath.Join(ctx.RootDir, dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue
		}
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || robotsFound {
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			nameLower := strings.ToLower(info.Name())
			// Match robots.ts, robots.tsx, robots.js, robots.jsx
			if nameLower == "robots.ts" || nameLower == "robots.tsx" || nameLower == "robots.js" || nameLower == "robots.jsx" {
				robotsFound = true
				robotsFoundPath, _ = filepath.Rel(ctx.RootDir, path)
				return nil
			}
			// Match route.ts/js in robots.txt/ or robots/ directory
			parentDir := strings.ToLower(filepath.Base(filepath.Dir(path)))
			if (parentDir == "robots.txt" || parentDir == "robots") && strings.HasPrefix(nameLower, "route.") {
				robotsFound = true
				robotsFoundPath, _ = filepath.Rel(ctx.RootDir, path)
				return nil
			}
			return nil
		})
	}
	if robotsFound {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "robots.txt generated via " + robotsFoundPath,
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "robots.txt not found",
		Suggestions: []string{
			"Add robots.txt to public/ directory",
			"Include Sitemap directive pointing to sitemap.xml",
		},
	}, nil
}

// SitemapCheck verifies sitemap.xml exists
type SitemapCheck struct{}

func (c SitemapCheck) ID() string {
	return "sitemap"
}

func (c SitemapCheck) Title() string {
	return "sitemap.xml"
}

func (c SitemapCheck) Run(ctx Context) (CheckResult, error) {
	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"",        // Root directory
	}

	for _, root := range webRoots {
		var path string
		if root == "" {
			path = "sitemap.xml"
		} else {
			path = root + "/sitemap.xml"
		}
		fullPath := filepath.Join(ctx.RootDir, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			// Check if it has meaningful content
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml found at " + path,
				}, nil
			}
		}
	}

	// Check monorepo public directories for static sitemap.xml
	monorepoStaticPaths := findMonorepoPublicFiles(ctx.RootDir, "sitemap.xml")
	for _, path := range monorepoStaticPaths {
		if content, err := os.ReadFile(path); err == nil {
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				relPath, _ := filepath.Rel(ctx.RootDir, path)
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml found at " + relPath,
				}, nil
			}
		}
	}

	// Check for dynamic sitemap generation across JS/TS frameworks
	jsSitemapPaths := []string{
		// Next.js App Router
		"app/sitemap.ts", "app/sitemap.tsx", "app/sitemap.js", "app/sitemap.jsx",
		"app/sitemap.xml/route.ts", "app/sitemap.xml/route.tsx", "app/sitemap.xml/route.js", "app/sitemap.xml/route.jsx",
		"src/app/sitemap.ts", "src/app/sitemap.tsx", "src/app/sitemap.js", "src/app/sitemap.jsx",
		"src/app/sitemap.xml/route.ts", "src/app/sitemap.xml/route.tsx", "src/app/sitemap.xml/route.js", "src/app/sitemap.xml/route.jsx",
		// SvelteKit
		"src/routes/sitemap.xml/+server.ts", "src/routes/sitemap.xml/+server.js",
		// Nuxt
		"server/routes/sitemap.xml.ts", "server/routes/sitemap.xml.js",
		"server/routes/sitemap.xml.get.ts", "server/routes/sitemap.xml.get.js",
		// Remix
		"app/routes/sitemap[.]xml.ts", "app/routes/sitemap[.]xml.tsx",
		"app/routes/sitemap.xml.ts", "app/routes/sitemap.xml.tsx",
		// Angular (universal/SSR)
		"src/assets/sitemap.xml",
		// Eleventy
		"src/sitemap.njk", "src/sitemap.liquid", "sitemap.njk", "sitemap.liquid",
		"src/sitemap.11ty.js", "sitemap.11ty.js",
	}

	for _, path := range jsSitemapPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via " + path,
			}, nil
		}
	}

	// Check monorepo structures for Next.js App Router sitemap
	monorepoSitemapPaths := findMonorepoNextFiles(ctx.RootDir, []string{"sitemap.ts", "sitemap.tsx", "sitemap.js", "sitemap.jsx"})
	for _, path := range monorepoSitemapPaths {
		if _, err := os.Stat(path); err == nil {
			relPath, _ := filepath.Rel(ctx.RootDir, path)
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via " + relPath,
			}, nil
		}
	}

	// Flexible search: walk app/ and src/app/ for sitemap files in any location
	// This catches route groups like app/(marketing)/sitemap.ts
	sitemapFound := false
	var sitemapFoundPath string
	flexSitemapDirs := []string{"app", "src/app"}
	for _, dir := range flexSitemapDirs {
		if sitemapFound {
			break
		}
		dirPath := filepath.Join(ctx.RootDir, dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue
		}
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || sitemapFound {
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			nameLower := strings.ToLower(info.Name())
			// Match sitemap.ts, sitemap.tsx, sitemap.js, sitemap.jsx
			if nameLower == "sitemap.ts" || nameLower == "sitemap.tsx" || nameLower == "sitemap.js" || nameLower == "sitemap.jsx" {
				sitemapFound = true
				sitemapFoundPath, _ = filepath.Rel(ctx.RootDir, path)
				return nil
			}
			// Match route.ts/js in sitemap.xml/ or sitemap/ directory
			parentDir := strings.ToLower(filepath.Base(filepath.Dir(path)))
			if (parentDir == "sitemap.xml" || parentDir == "sitemap") && strings.HasPrefix(nameLower, "route.") {
				sitemapFound = true
				sitemapFoundPath, _ = filepath.Rel(ctx.RootDir, path)
				return nil
			}
			return nil
		})
	}
	if sitemapFound {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "sitemap.xml generated via " + sitemapFoundPath,
		}, nil
	}

	// Check for dynamic sitemap generation across backend frameworks
	dynamicSitemapPaths := []string{
		// Ruby on Rails
		"app/controllers/sitemap_controller.rb",
		"app/controllers/sitemaps_controller.rb",
		"config/sitemap.rb", // sitemap_generator gem config
		// Laravel
		"app/Http/Controllers/SitemapController.php",
		"routes/sitemap.php",
		// Django
		"sitemaps.py",
		// Phoenix/Elixir
		"lib/*/controllers/sitemap_controller.ex",
		// Go
		"handlers/sitemap.go",
		"internal/handlers/sitemap.go",
		"pkg/handlers/sitemap.go",
		"cmd/server/sitemap.go",
		// Rust (Actix, Axum)
		"src/routes/sitemap.rs",
		"src/handlers/sitemap.rs",
		// Node.js/Express
		"routes/sitemap.js", "routes/sitemap.ts",
		"src/routes/sitemap.js", "src/routes/sitemap.ts",
		// ASP.NET
		"Controllers/SitemapController.cs",
	}

	for _, path := range dynamicSitemapPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via " + path,
			}, nil
		}
	}

	// Check for sitemap view directories
	sitemapViewDirs := []string{
		// Rails
		"app/views/sitemap",
		"app/views/sitemaps",
		// Laravel
		"resources/views/sitemap",
	}

	for _, path := range sitemapViewDirs {
		fullPath := filepath.Join(ctx.RootDir, path)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via view templates",
			}, nil
		}
	}

	// Check for sitemap in Django urls.py
	djangoUrlsPaths := []string{
		"urls.py",
		"config/urls.py",
		"project/urls.py",
	}
	for _, path := range djangoUrlsPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			if strings.Contains(string(content), "sitemap") {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml configured in Django urls",
				}, nil
			}
		}
	}

	// Check for sitemap generation in package.json (Node/Next.js)
	pkgPath := filepath.Join(ctx.RootDir, "package.json")
	if content, err := os.ReadFile(pkgPath); err == nil {
		if strings.Contains(string(content), "next-sitemap") ||
			strings.Contains(string(content), "sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sitemap generation configured via npm package",
			}, nil
		}
	}

	// Check for sitemap in Gemfile (Rails)
	gemfilePath := filepath.Join(ctx.RootDir, "Gemfile")
	if content, err := os.ReadFile(gemfilePath); err == nil {
		if strings.Contains(string(content), "sitemap_generator") ||
			strings.Contains(string(content), "sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sitemap generation configured via Ruby gem",
			}, nil
		}
	}

	// Check for sitemap in composer.json (Laravel/PHP)
	composerPath := filepath.Join(ctx.RootDir, "composer.json")
	if content, err := os.ReadFile(composerPath); err == nil {
		if strings.Contains(string(content), "spatie/laravel-sitemap") ||
			strings.Contains(string(content), "sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sitemap generation configured via Composer package",
			}, nil
		}
	}

	// Check for sitemap in requirements.txt (Python/Flask/Django)
	requirementsPath := filepath.Join(ctx.RootDir, "requirements.txt")
	if content, err := os.ReadFile(requirementsPath); err == nil {
		if strings.Contains(string(content), "django-sitemap") ||
			strings.Contains(string(content), "flask-sitemap") ||
			strings.Contains(string(content), "sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sitemap generation configured via Python package",
			}, nil
		}
	}

	// === CMS-specific sitemap detection ===

	// WordPress: Check for SEO plugins that generate sitemaps
	wpPluginDirs := []string{
		"wp-content/plugins/wordpress-seo",        // Yoast SEO
		"wp-content/plugins/all-in-one-seo-pack",  // All in One SEO
		"wp-content/plugins/seo-by-rank-math",     // Rank Math
		"wp-content/plugins/google-sitemap-generator", // Google XML Sitemaps
	}
	for _, dir := range wpPluginDirs {
		fullPath := filepath.Join(ctx.RootDir, dir)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via WordPress SEO plugin",
			}, nil
		}
	}

	// Craft CMS: Check for SEO plugins in composer.json
	craftComposerPath := filepath.Join(ctx.RootDir, "composer.json")
	if content, err := os.ReadFile(craftComposerPath); err == nil {
		// Check for Craft CMS SEO plugins that generate sitemaps
		craftSeoPlugins := []string{
			"nystudio107/craft-seomatic",
			"ether/seo",
			"doublesecretagency/craft-sitemap",
		}
		for _, plugin := range craftSeoPlugins {
			if strings.Contains(string(content), plugin) {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml generated via Craft CMS SEO plugin",
				}, nil
			}
		}
	}

	// Craft CMS: Check for SEOmatic config
	craftSitemapPaths := []string{
		"config/seomatic.php",
		"config/sitemap.php",
	}
	for _, path := range craftSitemapPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml configured via Craft CMS",
			}, nil
		}
	}

	// Hugo: Check hugo config for sitemap settings (Hugo has built-in sitemap)
	hugoConfigs := []string{"hugo.toml", "hugo.yaml", "hugo.json", "config.toml", "config.yaml"}
	for _, cfg := range hugoConfigs {
		fullPath := filepath.Join(ctx.RootDir, cfg)
		if _, err := os.Stat(fullPath); err == nil {
			// Hugo generates sitemap by default
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated by Hugo (built-in)",
			}, nil
		}
	}

	// Jekyll: Check for jekyll-sitemap in _config.yml or Gemfile
	jekyllConfig := filepath.Join(ctx.RootDir, "_config.yml")
	if content, err := os.ReadFile(jekyllConfig); err == nil {
		if strings.Contains(string(content), "jekyll-sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via jekyll-sitemap plugin",
			}, nil
		}
	}

	// Gatsby: Check for gatsby-plugin-sitemap
	gatsbyConfig := filepath.Join(ctx.RootDir, "gatsby-config.js")
	if content, err := os.ReadFile(gatsbyConfig); err == nil {
		if strings.Contains(string(content), "gatsby-plugin-sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml generated via gatsby-plugin-sitemap",
			}, nil
		}
	}

	// Astro: Check for @astrojs/sitemap
	astroConfigs := []string{"astro.config.mjs", "astro.config.ts", "astro.config.js"}
	for _, cfg := range astroConfigs {
		fullPath := filepath.Join(ctx.RootDir, cfg)
		if content, err := os.ReadFile(fullPath); err == nil {
			if strings.Contains(string(content), "@astrojs/sitemap") || strings.Contains(string(content), "sitemap") {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml generated via Astro sitemap integration",
				}, nil
			}
		}
	}

	// Nuxt: Check for @nuxtjs/sitemap module
	nuxtConfigs := []string{"nuxt.config.ts", "nuxt.config.js"}
	for _, cfg := range nuxtConfigs {
		fullPath := filepath.Join(ctx.RootDir, cfg)
		if content, err := os.ReadFile(fullPath); err == nil {
			if strings.Contains(string(content), "@nuxtjs/sitemap") || strings.Contains(string(content), "sitemap") {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml generated via Nuxt sitemap module",
				}, nil
			}
		}
	}

	// SvelteKit: Check for sitemap in svelte.config.js
	svelteConfig := filepath.Join(ctx.RootDir, "svelte.config.js")
	if content, err := os.ReadFile(svelteConfig); err == nil {
		if strings.Contains(string(content), "sitemap") {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml configured via SvelteKit",
			}, nil
		}
	}

	// Eleventy: Check for sitemap in .eleventy.js or eleventy.config.js
	eleventyConfigs := []string{".eleventy.js", "eleventy.config.js", "eleventy.config.cjs", "eleventy.config.mjs"}
	for _, cfg := range eleventyConfigs {
		fullPath := filepath.Join(ctx.RootDir, cfg)
		if content, err := os.ReadFile(fullPath); err == nil {
			if strings.Contains(string(content), "sitemap") {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "sitemap.xml configured via Eleventy",
				}, nil
			}
		}
	}

	// Ghost: Built-in sitemap (Ghost always has /sitemap.xml)
	ghostConfig := filepath.Join(ctx.RootDir, "content/themes")
	if info, err := os.Stat(ghostConfig); err == nil && info.IsDir() {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "sitemap.xml generated by Ghost (built-in)",
		}, nil
	}

	// Drupal: Check for sitemap module
	drupalModules := filepath.Join(ctx.RootDir, "modules/contrib/simple_sitemap")
	if info, err := os.Stat(drupalModules); err == nil && info.IsDir() {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "sitemap.xml generated via Drupal Simple Sitemap module",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "sitemap.xml not found",
		Suggestions: []string{
			"Add sitemap.xml to public/ directory",
			"Consider using next-sitemap or similar generator",
		},
	}, nil
}

// LLMsTxtCheck verifies llms.txt exists for AI crawlers
type LLMsTxtCheck struct{}

func (c LLMsTxtCheck) ID() string {
	return "llmsTxt"
}

func (c LLMsTxtCheck) Title() string {
	return "llms.txt"
}

func (c LLMsTxtCheck) Run(ctx Context) (CheckResult, error) {
	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"",        // Root directory
	}

	// Check both root and .well-known locations
	for _, root := range webRoots {
		var paths []string
		if root == "" {
			paths = []string{"llms.txt", ".well-known/llms.txt"}
		} else {
			paths = []string{root + "/llms.txt", root + "/.well-known/llms.txt"}
		}
		for _, path := range paths {
			fullPath := filepath.Join(ctx.RootDir, path)
			if content, err := os.ReadFile(fullPath); err == nil {
				// Check if it has meaningful content
				contentStr := strings.TrimSpace(string(content))
				if len(contentStr) > 0 {
					return CheckResult{
						ID:       c.ID(),
						Title:    c.Title(),
						Severity: SeverityInfo,
						Passed:   true,
						Message:  "llms.txt found at " + path,
					}, nil
				}
			}
		}
	}

	// Check monorepo public directories
	monorepoPublicPaths := findMonorepoPublicFiles(ctx.RootDir, "llms.txt")
	for _, path := range monorepoPublicPaths {
		if content, err := os.ReadFile(path); err == nil {
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				relPath, _ := filepath.Rel(ctx.RootDir, path)
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "llms.txt found at " + relPath,
				}, nil
			}
		}
	}

	// Check for dynamic llms.txt generation across JS/TS frameworks
	jsLLMsPaths := []string{
		// Next.js App Router
		"app/llms.txt/route.ts", "app/llms.txt/route.tsx", "app/llms.txt/route.js", "app/llms.txt/route.jsx",
		"app/.well-known/llms.txt/route.ts", "app/.well-known/llms.txt/route.tsx",
		"src/app/llms.txt/route.ts", "src/app/llms.txt/route.tsx", "src/app/llms.txt/route.js", "src/app/llms.txt/route.jsx",
		"src/app/.well-known/llms.txt/route.ts", "src/app/.well-known/llms.txt/route.tsx",
		// SvelteKit
		"src/routes/llms.txt/+server.ts", "src/routes/llms.txt/+server.js",
		"src/routes/.well-known/llms.txt/+server.ts", "src/routes/.well-known/llms.txt/+server.js",
		// Nuxt
		"server/routes/llms.txt.ts", "server/routes/llms.txt.js",
		"server/routes/llms.txt.get.ts", "server/routes/llms.txt.get.js",
		// Remix
		"app/routes/llms[.]txt.ts", "app/routes/llms[.]txt.tsx",
		"app/routes/llms.txt.ts", "app/routes/llms.txt.tsx",
		// Angular
		"src/assets/llms.txt",
		// Eleventy
		"src/llms.txt.njk", "src/llms.txt.liquid", "llms.txt.njk", "llms.txt.liquid",
	}

	for _, path := range jsLLMsPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "llms.txt generated via " + path,
			}, nil
		}
	}

	// Check monorepo structures for Next.js App Router llms.txt
	monorepoLLMsPaths := findMonorepoNextFiles(ctx.RootDir, []string{
		"llms.txt/route.ts", "llms.txt/route.tsx", "llms.txt/route.js", "llms.txt/route.jsx",
	})
	for _, path := range monorepoLLMsPaths {
		if _, err := os.Stat(path); err == nil {
			relPath, _ := filepath.Rel(ctx.RootDir, path)
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "llms.txt generated via " + relPath,
			}, nil
		}
	}

	// Check for dynamic llms.txt in backend frameworks
	backendLLMsPaths := []string{
		// Ruby on Rails
		"app/controllers/llms_controller.rb",
		// Laravel
		"app/Http/Controllers/LlmsController.php",
		"routes/llms.php",
		// Go
		"handlers/llms.go", "internal/handlers/llms.go",
		// Rust
		"src/routes/llms.rs", "src/handlers/llms.rs",
		// Node.js/Express
		"routes/llms.js", "routes/llms.ts",
		"src/routes/llms.js", "src/routes/llms.ts",
	}

	for _, path := range backendLLMsPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "llms.txt generated via " + path,
			}, nil
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "llms.txt not found",
		Suggestions: []string{
			"Add llms.txt to help AI understand your site",
			"See https://llmstxt.org for specification",
		},
	}, nil
}

// AdsTxtCheck verifies ads.txt exists (optional, for ad-supported sites)
type AdsTxtCheck struct{}

func (c AdsTxtCheck) ID() string {
	return "adsTxt"
}

func (c AdsTxtCheck) Title() string {
	return "ads.txt"
}

func (c AdsTxtCheck) Run(ctx Context) (CheckResult, error) {
	// Check if ads.txt check is enabled in config
	// This is optional - only matters for ad-supported sites
	if ctx.Config.Checks.AdsTxt == nil || !ctx.Config.Checks.AdsTxt.Enabled {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "ads.txt check not enabled",
		}, nil
	}

	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"",        // Root directory
	}

	for _, root := range webRoots {
		var path string
		if root == "" {
			path = "ads.txt"
		} else {
			path = root + "/ads.txt"
		}
		fullPath := filepath.Join(ctx.RootDir, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			// Check if it has meaningful content
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "ads.txt found at " + path,
				}, nil
			}
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "ads.txt not found",
		Suggestions: []string{
			"Add ads.txt for authorized digital sellers",
			"Required if running programmatic ads",
		},
	}, nil
}

// IndexNowCheck verifies IndexNow key file exists with correct content
type IndexNowCheck struct{}

func (c IndexNowCheck) ID() string {
	return "indexNow"
}

func (c IndexNowCheck) Title() string {
	return "IndexNow key file"
}

func (c IndexNowCheck) Run(ctx Context) (CheckResult, error) {
	// Check if IndexNow check is enabled in config
	if ctx.Config.Checks.IndexNow == nil || !ctx.Config.Checks.IndexNow.Enabled {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "IndexNow check not enabled",
		}, nil
	}

	key := ctx.Config.Checks.IndexNow.Key

	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"",        // Root directory
	}

	// If we have a configured key, check for that specific file first
	if key != "" {
		for _, root := range webRoots {
			var paths []string
			if root == "" {
				paths = []string{key + ".txt", ".well-known/" + key + ".txt"}
			} else {
				paths = []string{root + "/" + key + ".txt", root + "/.well-known/" + key + ".txt"}
			}
			for _, path := range paths {
				fullPath := filepath.Join(ctx.RootDir, path)
				if content, err := os.ReadFile(fullPath); err == nil {
					contentStr := strings.TrimSpace(string(content))
					if contentStr == key {
						return CheckResult{
							ID:       c.ID(),
							Title:    c.Title(),
							Severity: SeverityInfo,
							Passed:   true,
							Message:  "IndexNow key file found at " + path,
						}, nil
					}
				}
			}
		}
	}

	// Also look for any valid IndexNow key file (32-char hex filename)
	hexPattern := regexp.MustCompile(`^[a-f0-9]{32}\.txt$`)
	for _, root := range webRoots {
		dir := filepath.Join(ctx.RootDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && hexPattern.MatchString(entry.Name()) {
				foundKey := strings.TrimSuffix(entry.Name(), ".txt")
				content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err == nil && strings.TrimSpace(string(content)) == foundKey {
					path := entry.Name()
					if root != "" {
						path = root + "/" + path
					}
					// If config key doesn't match, warn but pass
					if key != "" && key != foundKey {
						return CheckResult{
							ID:       c.ID(),
							Title:    c.Title(),
							Severity: SeverityInfo,
							Passed:   true,
							Message:  fmt.Sprintf("IndexNow key file found at %s (update preflight.yml key to: %s)", path, foundKey),
						}, nil
					}
					return CheckResult{
						ID:       c.ID(),
						Title:    c.Title(),
						Severity: SeverityInfo,
						Passed:   true,
						Message:  "IndexNow key file found at " + path,
					}, nil
				}
			}
		}
	}

	if key == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "IndexNow enabled but no key file found",
			Suggestions: []string{
				"Create a 32-character hex key file (e.g., abc123...def.txt) in your web root",
			},
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "IndexNow key file not found",
		Suggestions: []string{
			fmt.Sprintf("Create %s.txt in your web root containing: %s", key, key),
			"Or place it at .well-known/" + key + ".txt",
		},
	}, nil
}

// HumansTxtCheck verifies humans.txt exists (optional, credits the team)
type HumansTxtCheck struct{}

func (c HumansTxtCheck) ID() string {
	return "humansTxt"
}

func (c HumansTxtCheck) Title() string {
	return "humans.txt"
}

func (c HumansTxtCheck) Run(ctx Context) (CheckResult, error) {
	if ctx.Config.Checks.HumansTxt == nil || !ctx.Config.Checks.HumansTxt.Enabled {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "humans.txt check not enabled",
		}, nil
	}

	webRoots := []string{"public", "static", "web", "www", "dist", "build", "_site", "out", ""}

	for _, root := range webRoots {
		var path string
		if root == "" {
			path = "humans.txt"
		} else {
			path = root + "/humans.txt"
		}
		fullPath := filepath.Join(ctx.RootDir, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) > 0 {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "humans.txt found at " + path,
				}, nil
			}
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "humans.txt not found",
		Suggestions: []string{
			"Add humans.txt to credit the team behind the site",
			"See https://humanstxt.org for format",
		},
	}, nil
}

// findMonorepoNextFiles searches for files in monorepo structures with Next.js App Router
// convention (apps/*/src/app/, packages/*/src/app/, apps/*/app/)
func findMonorepoNextFiles(rootDir string, filenames []string) []string {
	var paths []string

	monorepoRoots := []string{"apps", "packages", "services"}

	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			for _, filename := range filenames {
				// Check src/app/ pattern (standard Next.js App Router)
				srcAppPath := filepath.Join(monoDir, entry.Name(), "src", "app", filename)
				paths = append(paths, srcAppPath)

				// Check app/ pattern (alternative)
				appPath := filepath.Join(monoDir, entry.Name(), "app", filename)
				paths = append(paths, appPath)
			}
		}
	}

	return paths
}

// findMonorepoPublicFiles searches for static files in monorepo public directories
// (apps/*/public/, packages/*/public/, etc.)
func findMonorepoPublicFiles(rootDir, filename string) []string {
	var paths []string

	monorepoRoots := []string{"apps", "packages", "services"}
	publicDirs := []string{"public", "static", "web"}

	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			for _, pubDir := range publicDirs {
				// Check public directory
				pubPath := filepath.Join(monoDir, entry.Name(), pubDir, filename)
				paths = append(paths, pubPath)

				// Also check .well-known subdirectory
				wellKnownPath := filepath.Join(monoDir, entry.Name(), pubDir, ".well-known", filename)
				paths = append(paths, wellKnownPath)
			}
		}
	}

	return paths
}
