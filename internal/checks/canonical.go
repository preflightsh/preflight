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
			Passed:   true,
			Message:  "No layout file found, skipping",
		}, nil
	}

	layoutPath := filepath.Join(ctx.RootDir, layoutFile)
	content, err := os.ReadFile(layoutPath)
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

// canonicalPatterns covers the full set of template / framework idioms
// we recognize as declaring a canonical URL. Compiled once so
// hasCanonicalURL doesn't rebuild 14 regexes per invocation.
var canonicalPatterns = []*regexp.Regexp{
	// Standard HTML canonical link (rel before href)
	regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]*>`),
	// Reverse order: href before rel
	regexp.MustCompile(`(?i)<link[^>]+href=["'][^"']+["'][^>]+rel=["']canonical["'][^>]*>`),
	// Next.js App Router metadata API
	regexp.MustCompile(`(?i)alternates\s*:\s*\{[^}]*canonical`),
	// Next.js metadataBase (implies canonical handling)
	regexp.MustCompile(`(?i)metadataBase\s*[:=]`),
	// React Helmet / react-helmet-async
	regexp.MustCompile(`(?i)<Helmet[^>]*>.*canonical.*</Helmet>`),
	// Vue Meta
	regexp.MustCompile(`(?i)link\s*:\s*\[[^\]]*rel:\s*["']canonical["']`),
	// Nuxt/Vue useHead
	regexp.MustCompile(`(?i)useHead\s*\([^)]*canonical`),
	// Rails canonical helper
	regexp.MustCompile(`(?i)<%=.*canonical.*%>`),
	// Django/Jinja canonical
	regexp.MustCompile(`(?i)\{%.*canonical.*%\}|\{\{.*canonical.*\}\}`),
	// Twig canonical (Craft CMS, Symfony)
	regexp.MustCompile(`(?i)\{\{.*canonical.*\}\}|\{%.*canonical.*%\}`),
	// PHP canonical
	regexp.MustCompile(`(?i)<\?.*canonical.*\?>`),
	// Blade canonical (Laravel)
	regexp.MustCompile(`(?i)\{\{.*canonical.*\}\}|@.*canonical`),
	// Hugo canonical
	regexp.MustCompile(`(?i)\{\{.*\.Permalink.*\}\}.*rel=["']canonical["']|\.Site\.BaseURL`),
	// Astro canonical
	regexp.MustCompile(`(?i)Astro\.url|canonical\s*=`),
}

func hasCanonicalURL(content, stack string) bool {
	// Strip comments to avoid false positives on commented-out code
	content = stripCodeComments(content)
	for _, re := range canonicalPatterns {
		if re.MatchString(content) {
			return true
		}
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

