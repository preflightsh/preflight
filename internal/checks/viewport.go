package checks

import (
	"os"
	"path/filepath"
	"regexp"
)

type ViewportCheck struct{}

func (c ViewportCheck) ID() string {
	return "viewport"
}

func (c ViewportCheck) Title() string {
	return "Viewport meta tag"
}

func (c ViewportCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.SEOMeta
	if cfg == nil || cfg.MainLayout == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Check not configured (no main layout set)",
		}, nil
	}

	layoutPath := filepath.Join(ctx.RootDir, cfg.MainLayout)
	content, err := os.ReadFile(layoutPath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read layout file: " + cfg.MainLayout,
		}, nil
	}

	contentStr := string(content)

	// Check for viewport meta tag
	if hasViewportMeta(contentStr, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Viewport meta tag configured",
		}, nil
	}

	// Also check common head partials
	if checkViewportPartials(ctx.RootDir, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Viewport meta tag configured (in partial)",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "No viewport meta tag found",
		Suggestions: []string{
			"Add to <head>: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
			"This ensures proper mobile responsiveness",
		},
	}, nil
}

func hasViewportMeta(content, stack string) bool {
	// Standard HTML viewport meta tag
	htmlViewport := regexp.MustCompile(`(?i)<meta[^>]+name=["']viewport["'][^>]*>`)
	if htmlViewport.MatchString(content) {
		return true
	}

	// Alternate order: content before name
	htmlViewportAlt := regexp.MustCompile(`(?i)<meta[^>]+content=["'][^"']*width[^"']*["'][^>]+name=["']viewport["'][^>]*>`)
	if htmlViewportAlt.MatchString(content) {
		return true
	}

	// Next.js App Router - viewport is auto-generated, check for viewport export
	nextjsViewport := regexp.MustCompile(`(?i)export\s+(const|let|var)\s+viewport\s*=`)
	if nextjsViewport.MatchString(content) {
		return true
	}

	// Next.js metadata with viewport
	nextjsMetaViewport := regexp.MustCompile(`(?i)viewport\s*:\s*\{`)
	if nextjsMetaViewport.MatchString(content) {
		return true
	}

	// React Helmet
	helmetViewport := regexp.MustCompile(`(?i)<Helmet[^>]*>.*viewport.*</Helmet>`)
	if helmetViewport.MatchString(content) {
		return true
	}

	// Vue Meta / useHead
	vueMetaViewport := regexp.MustCompile(`(?i)name:\s*["']viewport["']`)
	if vueMetaViewport.MatchString(content) {
		return true
	}

	// Template variables that likely include viewport
	templateViewport := regexp.MustCompile(`(?i)viewport`)
	if templateViewport.MatchString(content) {
		return true
	}

	return false
}

func checkViewportPartials(rootDir, stack string) bool {
	// Common locations for head partials
	partialPaths := []string{
		// Generic
		"_includes/head.html",
		"partials/head.html",
		"includes/head.html",

		// Rails
		"app/views/layouts/_head.html.erb",
		"app/views/shared/_head.html.erb",

		// Laravel
		"resources/views/partials/head.blade.php",
		"resources/views/layouts/partials/head.blade.php",

		// Craft CMS
		"templates/_partials/head.twig",
		"templates/_head.twig",

		// Hugo
		"layouts/partials/head.html",
		"themes/theme/layouts/partials/head.html",

		// Jekyll
		"_includes/head.html",

		// Next.js - App Router handles viewport automatically
		"app/layout.tsx",
		"app/layout.jsx",
		"src/app/layout.tsx",
		"src/app/layout.jsx",

		// Astro
		"src/components/Head.astro",
		"src/layouts/Layout.astro",
	}

	for _, partialPath := range partialPaths {
		fullPath := filepath.Join(rootDir, partialPath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		if hasViewportMeta(string(content), stack) {
			return true
		}
	}

	return false
}
