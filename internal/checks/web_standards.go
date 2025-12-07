package checks

import (
	"os"
	"path/filepath"
	"strings"
)

// RobotsTxtCheck verifies robots.txt exists
type RobotsTxtCheck struct{}

func (c RobotsTxtCheck) ID() string {
	return "robotsTxt"
}

func (c RobotsTxtCheck) Title() string {
	return "robots.txt is present"
}

func (c RobotsTxtCheck) Run(ctx Context) (CheckResult, error) {
	paths := []string{
		"public/robots.txt",
		"static/robots.txt",
		"robots.txt",
		"app/robots.txt",
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
					Message:  "robots.txt found at " + path,
				}, nil
			}
		}
	}

	// Also check for Next.js robots.ts/js
	nextRobotsPaths := []string{
		"app/robots.ts",
		"app/robots.js",
	}

	for _, path := range nextRobotsPaths {
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
	return "sitemap.xml is present"
}

func (c SitemapCheck) Run(ctx Context) (CheckResult, error) {
	paths := []string{
		"public/sitemap.xml",
		"static/sitemap.xml",
		"sitemap.xml",
	}

	for _, path := range paths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "sitemap.xml found at " + path,
			}, nil
		}
	}

	// Check for Next.js sitemap generator
	nextSitemapPaths := []string{
		"app/sitemap.ts",
		"app/sitemap.js",
		"app/sitemap.xml/route.ts",
	}

	for _, path := range nextSitemapPaths {
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

	// Check for dynamic sitemap generation across various frameworks
	dynamicSitemapPaths := []string{
		// Rails
		"app/controllers/sitemap_controller.rb",
		"app/controllers/sitemaps_controller.rb",
		// Laravel
		"app/Http/Controllers/SitemapController.php",
		// Django
		"sitemaps.py",
		// Phoenix/Elixir
		"lib/*/controllers/sitemap_controller.ex",
		// Go
		"handlers/sitemap.go",
		"internal/handlers/sitemap.go",
		"pkg/handlers/sitemap.go",
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

	// Craft CMS: Check for SEOmatic or native sitemap
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
	return "llms.txt is present"
}

func (c LLMsTxtCheck) Run(ctx Context) (CheckResult, error) {
	paths := []string{
		"public/llms.txt",
		"static/llms.txt",
		"llms.txt",
		"public/.well-known/llms.txt",
	}

	for _, path := range paths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "llms.txt found at " + path,
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
	return "ads.txt is present"
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

	paths := []string{
		"public/ads.txt",
		"static/ads.txt",
		"ads.txt",
	}

	for _, path := range paths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "ads.txt found at " + path,
			}, nil
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
