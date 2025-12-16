package checks

import (
	"os"
	"path/filepath"
	"regexp"
)

type LangAttributeCheck struct{}

func (c LangAttributeCheck) ID() string {
	return "lang"
}

func (c LangAttributeCheck) Title() string {
	return "HTML lang attribute"
}

func (c LangAttributeCheck) Run(ctx Context) (CheckResult, error) {
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

	// Check for lang attribute on html tag
	if hasLangAttribute(contentStr, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "HTML lang attribute set",
		}, nil
	}

	// Check common layout partials
	if checkLangPartials(ctx.RootDir, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "HTML lang attribute set (in partial)",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "No lang attribute on <html> tag",
		Suggestions: getLangSuggestions(ctx.Config.Stack),
	}, nil
}

func hasLangAttribute(content, stack string) bool {
	// Standard HTML lang attribute: <html lang="en">
	htmlLang := regexp.MustCompile(`(?i)<html[^>]+lang=["'][a-z]{2}(-[A-Za-z]{2,})?["']`)
	if htmlLang.MatchString(content) {
		return true
	}

	// Dynamic lang attribute with template variable
	dynamicLang := regexp.MustCompile(`(?i)<html[^>]+lang=["']\{`)
	if dynamicLang.MatchString(content) {
		return true
	}

	// JSX/TSX: <html lang={...}>
	jsxLang := regexp.MustCompile(`(?i)<html[^>]+lang=\{`)
	if jsxLang.MatchString(content) {
		return true
	}

	// ERB: <html lang="<%= ... %>">
	erbLang := regexp.MustCompile(`(?i)<html[^>]+lang=["']<%=`)
	if erbLang.MatchString(content) {
		return true
	}

	// Blade: <html lang="{{ ... }}">
	bladeLang := regexp.MustCompile(`(?i)<html[^>]+lang=["']\{\{`)
	if bladeLang.MatchString(content) {
		return true
	}

	// Twig/Jinja: <html lang="{{ ... }}">
	twigLang := regexp.MustCompile(`(?i)<html[^>]+lang=["']\{\{`)
	if twigLang.MatchString(content) {
		return true
	}

	// Hugo: {{ with .Site.Language.Lang }}
	hugoLang := regexp.MustCompile(`(?i)<html[^>]+lang=["']\{\{.*\.Language`)
	if hugoLang.MatchString(content) {
		return true
	}

	// Next.js App Router - lang is set in RootLayout
	// Check for lang prop or hardcoded lang
	nextjsLang := regexp.MustCompile(`(?i)lang[:=]\s*["'][a-z]{2}`)
	if nextjsLang.MatchString(content) {
		return true
	}

	return false
}

func checkLangPartials(rootDir, stack string) bool {
	// Common locations for layout files that contain <html> tag
	layoutPaths := []string{
		// Generic
		"index.html",

		// Rails
		"app/views/layouts/application.html.erb",

		// Laravel
		"resources/views/layouts/app.blade.php",
		"resources/views/app.blade.php",

		// Craft CMS
		"templates/_layout.twig",
		"templates/_layouts/base.twig",

		// Hugo
		"layouts/_default/baseof.html",
		"themes/theme/layouts/_default/baseof.html",

		// Jekyll
		"_layouts/default.html",

		// Next.js App Router
		"app/layout.tsx",
		"app/layout.jsx",
		"src/app/layout.tsx",
		"src/app/layout.jsx",

		// Next.js Pages Router
		"pages/_document.tsx",
		"pages/_document.jsx",
		"src/pages/_document.tsx",
		"src/pages/_document.jsx",

		// Astro
		"src/layouts/Layout.astro",
		"src/layouts/BaseLayout.astro",

		// Eleventy
		"_includes/layout.njk",
		"_includes/base.njk",

		// Gatsby
		"src/components/layout.js",
		"src/components/layout.tsx",
	}

	for _, layoutPath := range layoutPaths {
		fullPath := filepath.Join(rootDir, layoutPath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		if hasLangAttribute(string(content), stack) {
			return true
		}
	}

	return false
}

func getLangSuggestions(stack string) []string {
	switch stack {
	case "next":
		return []string{
			"Add lang to RootLayout: <html lang=\"en\">",
		}
	case "rails":
		return []string{
			"Add to application.html.erb: <html lang=\"en\">",
			"Or dynamically: <html lang=\"<%= I18n.locale %>\">",
		}
	case "laravel":
		return []string{
			"Add to layout: <html lang=\"{{ str_replace('_', '-', app()->getLocale()) }}\">",
		}
	case "django":
		return []string{
			"Add to base template: <html lang=\"{{ LANGUAGE_CODE }}\">",
		}
	case "craft":
		return []string{
			"Add to layout: <html lang=\"{{ craft.app.language }}\">",
		}
	case "hugo":
		return []string{
			"Add to baseof.html: <html lang=\"{{ .Site.Language.Lang }}\">",
		}
	case "jekyll":
		return []string{
			"Add to default layout: <html lang=\"{{ page.lang | default: site.lang | default: 'en' }}\">",
		}
	case "astro":
		return []string{
			"Add to Layout: <html lang=\"en\"> or use Astro.currentLocale",
		}
	default:
		return []string{
			"Add lang attribute: <html lang=\"en\">",
			"Use appropriate language code (en, es, fr, de, etc.)",
		}
	}
}
