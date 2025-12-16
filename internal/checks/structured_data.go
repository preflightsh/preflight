package checks

import (
	"os"
	"path/filepath"
	"regexp"
)

type StructuredDataCheck struct{}

func (c StructuredDataCheck) ID() string {
	return "structured_data"
}

func (c StructuredDataCheck) Title() string {
	return "Structured data (JSON-LD)"
}

func (c StructuredDataCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.SEOMeta

	// Check main layout if configured
	if cfg != nil && cfg.MainLayout != "" {
		layoutPath := filepath.Join(ctx.RootDir, cfg.MainLayout)
		content, err := os.ReadFile(layoutPath)
		if err == nil {
			if hasStructuredData(string(content), ctx.Config.Stack) {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "Schema.org structured data found",
				}, nil
			}
		}
	}

	// Check common partials
	if checkStructuredDataPartials(ctx.RootDir, ctx.Config.Stack) {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Schema.org structured data found (in partial)",
		}, nil
	}

	// If no SEOMeta configured, return skipped status
	if cfg == nil || cfg.MainLayout == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Check skipped (no main layout set)",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "No structured data found",
		Suggestions: getStructuredDataSuggestions(ctx.Config.Stack),
	}, nil
}

func hasStructuredData(content, stack string) bool {
	// JSON-LD script tag
	jsonLD := regexp.MustCompile(`(?i)<script[^>]+type=["']application/ld\+json["'][^>]*>`)
	if jsonLD.MatchString(content) {
		return true
	}

	// Schema.org context in code
	schemaContext := regexp.MustCompile(`(?i)["']@context["']\s*:\s*["']https?://schema\.org`)
	if schemaContext.MatchString(content) {
		return true
	}

	// Next.js generateMetadata with JSON-LD
	nextJSJsonLD := regexp.MustCompile(`(?i)application/ld\+json|jsonLd|json-ld`)
	if nextJSJsonLD.MatchString(content) {
		return true
	}

	// Craft CMS SEOmatic
	seomatic := regexp.MustCompile(`(?i)seomatic\..*jsonLd|craft\.seomatic`)
	if seomatic.MatchString(content) {
		return true
	}

	// WordPress Yoast/RankMath
	wpSEO := regexp.MustCompile(`(?i)wpseo|rank_math|schema.*graph`)
	if wpSEO.MatchString(content) {
		return true
	}

	// Rails structured_data helper or schema.org gem
	railsSchema := regexp.MustCompile(`(?i)structured_data|json_ld|schemaOrg`)
	if railsSchema.MatchString(content) {
		return true
	}

	// Hugo schema partial
	hugoSchema := regexp.MustCompile(`(?i)schema\.html|partial.*schema`)
	if hugoSchema.MatchString(content) {
		return true
	}

	// Generic Schema.org type detection
	schemaType := regexp.MustCompile(`(?i)["']@type["']\s*:\s*["'](Organization|WebSite|Article|Product|LocalBusiness|Person|BreadcrumbList|FAQPage|HowTo|Event|Recipe|Review)["']`)
	if schemaType.MatchString(content) {
		return true
	}

	return false
}

func checkStructuredDataPartials(rootDir, stack string) bool {
	partialPaths := []string{
		"_includes/schema.html",
		"_includes/structured-data.html",
		"_includes/json-ld.html",
		"_includes/head.html",
		"partials/schema.html",
		"partials/structured-data.html",
		"partials/head.html",

		"app/views/layouts/_head.html.erb",
		"app/views/layouts/_schema.html.erb",
		"app/views/shared/_head.html.erb",
		"app/views/shared/_schema.html.erb",

		"resources/views/partials/head.blade.php",
		"resources/views/partials/schema.blade.php",
		"resources/views/layouts/partials/head.blade.php",

		"templates/_partials/header.twig",
		"templates/_partials/head.twig",
		"templates/_partials/schema.twig",
		"templates/_partials/json-ld.twig",
		"templates/_header.twig",
		"templates/_head.twig",
		"templates/_schema.twig",

		"layouts/partials/head.html",
		"layouts/partials/schema.html",
		"themes/theme/layouts/partials/head.html",
		"themes/theme/layouts/partials/schema.html",

		"components/Schema.tsx",
		"components/JsonLd.tsx",
		"components/StructuredData.tsx",
		"components/Head.tsx",
		"src/components/Schema.tsx",
		"src/components/JsonLd.tsx",
		"src/components/StructuredData.tsx",
		"src/components/Head.tsx",

		"src/components/Schema.astro",
		"src/components/JsonLd.astro",
		"src/components/Head.astro",
	}

	for _, partialPath := range partialPaths {
		fullPath := filepath.Join(rootDir, partialPath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		if hasStructuredData(string(content), stack) {
			return true
		}
	}

	return false
}

func getStructuredDataSuggestions(stack string) []string {
	switch stack {
	case "next":
		return []string{
			"Add JSON-LD script in layout: <script type=\"application/ld+json\">{...}</script>",
			"Or use next-seo package for structured data",
		}
	case "rails":
		return []string{
			"Use json_ld_helper gem or add JSON-LD manually to layout",
		}
	case "laravel":
		return []string{
			"Use spatie/schema-org package or add JSON-LD to layout",
		}
	case "craft":
		return []string{
			"Use SEOmatic plugin: {{ seomatic.jsonLd.render() }}",
			"Or add JSON-LD manually to templates",
		}
	case "wordpress":
		return []string{
			"Use Yoast SEO or RankMath plugin for automatic schema",
		}
	case "hugo":
		return []string{
			"Create layouts/partials/schema.html with JSON-LD",
		}
	case "jekyll":
		return []string{
			"Use jekyll-seo-tag plugin or create _includes/schema.html",
		}
	case "gatsby":
		return []string{
			"Use gatsby-plugin-schema-org or add JSON-LD to SEO component",
		}
	case "astro":
		return []string{
			"Add JSON-LD script in BaseLayout or use @astrolib/seo",
		}
	default:
		return []string{
			"Add <script type=\"application/ld+json\">{\"@context\":\"https://schema.org\",...}</script>",
		}
	}
}
