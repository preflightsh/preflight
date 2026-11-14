package checks

import (
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
	if r, ok := renderedResult(ctx, c, func(doc renderedDoc) []string {
		if doc.htmlLang != "" {
			return nil
		}
		return []string{"lang"}
	}); ok {
		return r, nil
	}
	cfg := ctx.Config.Checks.SEOMeta

	// Get configured layout or auto-detect
	var configuredLayout string
	if cfg != nil {
		configuredLayout = cfg.MainLayout
	}
	layoutFile := getLayoutFile(ctx.RootDir, ctx.Config.Stack, configuredLayout)

	if layoutFile == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "No layout file found, skipping",
		}, nil
	}

	content, err := readProjectFile(ctx.RootDir, layoutFile)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read layout file: " + layoutFile,
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

	// Check included template files
	for _, includePath := range resolveTemplateIncludes(contentStr, ctx.RootDir, ctx.Config.Stack) {
		includeContent, err := readSourceFile(includePath)
		if err != nil {
			continue
		}
		if hasLangAttribute(string(includeContent), ctx.Config.Stack) {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "HTML lang attribute set (in included template)",
			}, nil
		}
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
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     "No lang attribute on <html> tag",
		Suggestions: getLangSuggestions(ctx.Config.Stack),
	}, nil
}

func hasLangAttribute(content, stack string) bool {
	// Strip comments to avoid false positives on commented-out code
	content = stripCodeComments(content)

	// A lang attribute on the <html> tag itself, static (lang="en") or
	// dynamic (lang="{{ ... }}", lang="<%= ... %>", lang={...}).
	if htmlLangAttrRE.MatchString(content) {
		return true
	}

	// The document language set as an object key rather than an attribute:
	// Nuxt's htmlAttrs: { lang: 'en' }, a head() config, an i18n default.
	// Only the key form counts. An attribute form anywhere but <html> is a
	// different element's language: <style lang="scss">, <script lang="ts">.
	return langKeyRE.MatchString(content)
}

var (
	// The lang must be its own attribute: hreflang="en" and data-lang="en"
	// are something else.
	htmlLangAttrRE = regexp.MustCompile(`(?i)<html\b[^>]*[\s"']lang\s*=\s*(?:["'][^"'\s]|\{)`)
	langKeyRE      = regexp.MustCompile(`(?im)(?:^|[\s{,(])lang\s*:\s*["'][a-z]{2}`)
)

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
		content, err := readSourceFile(fullPath)
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
