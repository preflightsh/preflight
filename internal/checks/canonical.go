package checks

import (
	"os"
	"path/filepath"
	"regexp"
)

type CanonicalURLCheck struct{}

func (c CanonicalURLCheck) ID() string {
	return "canonical"
}

func (c CanonicalURLCheck) Title() string {
	return "Canonical URL"
}

func (c CanonicalURLCheck) Run(ctx Context) (CheckResult, error) {
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

	// Check for canonical URL patterns
	if hasCanonicalURL(contentStr, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Canonical URL configured",
		}, nil
	}

	// Also check common SEO partials/includes
	if checkSEOPartials(ctx.RootDir, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Canonical URL configured (in partial)",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "No canonical URL tag found",
		Suggestions: getCanonicalSuggestions(ctx.Config.Stack),
	}, nil
}

func hasCanonicalURL(content, stack string) bool {
	// Standard HTML canonical link
	htmlCanonical := regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]*>`)
	if htmlCanonical.MatchString(content) {
		return true
	}

	// Also check reverse order: href before rel
	htmlCanonicalAlt := regexp.MustCompile(`(?i)<link[^>]+href=["'][^"']+["'][^>]+rel=["']canonical["'][^>]*>`)
	if htmlCanonicalAlt.MatchString(content) {
		return true
	}

	// Next.js App Router metadata API
	nextjsCanonical := regexp.MustCompile(`(?i)alternates\s*:\s*\{[^}]*canonical`)
	if nextjsCanonical.MatchString(content) {
		return true
	}

	// Next.js metadataBase (implies canonical handling)
	nextjsMetadataBase := regexp.MustCompile(`(?i)metadataBase\s*[:=]`)
	if nextjsMetadataBase.MatchString(content) {
		return true
	}

	// React Helmet / react-helmet-async
	helmetCanonical := regexp.MustCompile(`(?i)<Helmet[^>]*>.*canonical.*</Helmet>`)
	if helmetCanonical.MatchString(content) {
		return true
	}

	// Vue Meta
	vueMetaCanonical := regexp.MustCompile(`(?i)link\s*:\s*\[[^\]]*rel:\s*["']canonical["']`)
	if vueMetaCanonical.MatchString(content) {
		return true
	}

	// Nuxt/Vue useHead
	useHeadCanonical := regexp.MustCompile(`(?i)useHead\s*\([^)]*canonical`)
	if useHeadCanonical.MatchString(content) {
		return true
	}

	// Rails canonical helper
	railsCanonical := regexp.MustCompile(`(?i)<%=.*canonical.*%>`)
	if railsCanonical.MatchString(content) {
		return true
	}

	// Django/Jinja canonical
	djangoCanonical := regexp.MustCompile(`(?i)\{%.*canonical.*%\}|\{\{.*canonical.*\}\}`)
	if djangoCanonical.MatchString(content) {
		return true
	}

	// Twig canonical (Craft CMS, Symfony)
	twigCanonical := regexp.MustCompile(`(?i)\{\{.*canonical.*\}\}|\{%.*canonical.*%\}`)
	if twigCanonical.MatchString(content) {
		return true
	}

	// PHP canonical
	phpCanonical := regexp.MustCompile(`(?i)<\?.*canonical.*\?>`)
	if phpCanonical.MatchString(content) {
		return true
	}

	// Blade canonical (Laravel)
	bladeCanonical := regexp.MustCompile(`(?i)\{\{.*canonical.*\}\}|@.*canonical`)
	if bladeCanonical.MatchString(content) {
		return true
	}

	// Hugo canonical
	hugoCanonical := regexp.MustCompile(`(?i)\{\{.*\.Permalink.*\}\}.*rel=["']canonical["']|\.Site\.BaseURL`)
	if hugoCanonical.MatchString(content) {
		return true
	}

	// Astro canonical
	astroCanonical := regexp.MustCompile(`(?i)Astro\.url|canonical\s*=`)
	if astroCanonical.MatchString(content) {
		return true
	}

	return false
}

func checkSEOPartials(rootDir, stack string) bool {
	// Common locations for SEO partials that might contain canonical tags
	partialPaths := []string{
		// Generic
		"_includes/head.html",
		"_includes/seo.html",
		"partials/head.html",
		"partials/seo.html",
		"includes/head.html",
		"includes/seo.html",

		// Rails
		"app/views/layouts/_head.html.erb",
		"app/views/shared/_head.html.erb",
		"app/views/shared/_seo.html.erb",

		// Laravel
		"resources/views/partials/head.blade.php",
		"resources/views/partials/seo.blade.php",
		"resources/views/layouts/partials/head.blade.php",

		// Craft CMS
		"templates/_partials/head.twig",
		"templates/_partials/seo.twig",
		"templates/_head.twig",
		"templates/_seo.twig",

		// Hugo
		"layouts/partials/head.html",
		"layouts/partials/seo.html",
		"themes/theme/layouts/partials/head.html",

		// Jekyll
		"_includes/head.html",
		"_includes/seo.html",

		// Next.js
		"components/SEO.tsx",
		"components/SEO.jsx",
		"components/Seo.tsx",
		"components/Seo.jsx",
		"components/Head.tsx",
		"components/Head.jsx",
		"src/components/SEO.tsx",
		"src/components/SEO.jsx",

		// Astro
		"src/components/SEO.astro",
		"src/components/Head.astro",
		"src/layouts/SEO.astro",
	}

	for _, partialPath := range partialPaths {
		fullPath := filepath.Join(rootDir, partialPath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		if hasCanonicalURL(string(content), stack) {
			return true
		}
	}

	return false
}

func getCanonicalSuggestions(stack string) []string {
	switch stack {
	case "next":
		return []string{
			"Add canonical to metadata: alternates: { canonical: 'https://...' }",
			"Or set metadataBase in root layout.tsx",
		}
	case "rails":
		return []string{
			"Add to layout: <%= tag.link rel: 'canonical', href: request.original_url %>",
		}
	case "laravel":
		return []string{
			"Add to layout: <link rel=\"canonical\" href=\"{{ url()->current() }}\">",
		}
	case "django":
		return []string{
			"Add to template: <link rel=\"canonical\" href=\"{{ request.build_absolute_uri }}\">",
		}
	case "craft":
		return []string{
			"Add to layout: <link rel=\"canonical\" href=\"{{ craft.app.request.absoluteUrl }}\">",
			"Or use SEOmatic plugin for automatic canonical URLs",
		}
	case "hugo":
		return []string{
			"Add to head: <link rel=\"canonical\" href=\"{{ .Permalink }}\">",
		}
	case "jekyll":
		return []string{
			"Add jekyll-seo-tag plugin or manual: <link rel=\"canonical\" href=\"{{ page.url | absolute_url }}\">",
		}
	case "gatsby":
		return []string{
			"Use gatsby-plugin-canonical-urls or add to SEO component",
		}
	case "astro":
		return []string{
			"Add to head: <link rel=\"canonical\" href={Astro.url}>",
		}
	case "vue", "nuxt":
		return []string{
			"Use useHead() with link: [{ rel: 'canonical', href: '...' }]",
		}
	case "react":
		return []string{
			"Use react-helmet: <Helmet><link rel=\"canonical\" href=\"...\" /></Helmet>",
		}
	default:
		return []string{
			"Add <link rel=\"canonical\" href=\"...\"> to your <head>",
		}
	}
}
