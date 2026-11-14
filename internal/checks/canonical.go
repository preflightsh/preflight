package checks

import (
	"path/filepath"
	"regexp"
	"strings"
)

type CanonicalURLCheck struct{}

func (c CanonicalURLCheck) ID() string {
	return "canonical"
}

func (c CanonicalURLCheck) Title() string {
	return "Canonical URL"
}

func (c CanonicalURLCheck) Run(ctx Context) (CheckResult, error) {
	if r, ok := renderedResultEnv(ctx, c, func(env string, doc renderedDoc) []string {
		href := doc.linkHref("canonical")
		if href == "" {
			return []string{"canonical"}
		}
		// On production the canonical is what search engines index under,
		// so it has to be a full URL on a real host. A relative one, or a
		// dev server's address left in, points them at nothing. Staging is
		// left alone, and so is a production URL that is itself local.
		if env != "prod" || IsLocalURL(ctx.Config.URLs.Production) {
			return nil
		}
		lower := strings.ToLower(href)
		switch {
		case !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://"):
			return []string{"canonical with an absolute URL (found " + truncate(href, 60) + ")"}
		case IsLocalURL(href):
			return []string{"canonical that points at the live site (found " + truncate(href, 60) + ")"}
		}
		return nil
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
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     "No canonical URL tag found",
		Suggestions: getCanonicalSuggestions(ctx.Config.Stack),
	}, nil
}

// canonicalPatterns covers the full set of template / framework idioms
// we recognize as declaring a canonical URL. Compiled once so
// hasCanonicalURL doesn't rebuild a dozen regexes per invocation.
var canonicalPatterns = []*regexp.Regexp{
	// Standard HTML canonical link (rel before href)
	regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]*>`),
	// Reverse order: href before rel
	regexp.MustCompile(`(?i)<link[^>]+href=["'][^"']+["'][^>]+rel=["']canonical["'][^>]*>`),
	// Next.js App Router metadata API
	regexp.MustCompile(`(?i)alternates\s*:\s*\{[^}]*canonical`),
	// React Helmet / react-helmet-async
	regexp.MustCompile(`(?i)<Helmet[^>]*>.*canonical.*</Helmet>`),
	// Vue Meta
	regexp.MustCompile(`(?i)link\s*:\s*\[[^\]]*rel:\s*["']canonical["']`),
	// Nuxt/Vue useHead
	regexp.MustCompile(`(?i)useHead\s*\([^)]*canonical`),
	// Blade directive naming a canonical section, stack, or partial
	// (@yield('canonical'), @include('partials.canonical')). Only the
	// directive's first argument counts: @section('title', 'Our canonical
	// guide') is a page title.
	regexp.MustCompile(`(?i)@(?:include\w*|yield|stack|section|push|prepend|component)\s*\(\s*["'][^"'\s]*canonical[^"'\s]*["']|@canonical\b`),
	// Hugo canonical
	regexp.MustCompile(`(?i)\{\{.*\.Permalink.*\}\}.*rel=["']canonical["']`),
	// Astro canonical. Astro.url alone is everywhere (nav highlighting);
	// it only counts in the same statement as a canonical. Next.js
	// metadataBase is not here either: it resolves relative URLs and emits
	// no canonical unless alternates.canonical is set.
	regexp.MustCompile(`(?i)canonical[^\n]*Astro\.url|Astro\.url[^\n]*canonical|canonical\s*=`),
}

func hasCanonicalURL(content, stack string) bool {
	// Strip comments to avoid false positives on commented-out code
	content = stripCodeComments(content)
	for _, re := range canonicalPatterns {
		if re.MatchString(content) {
			return true
		}
	}
	return templateExpressionMentions(content, "canonical")
}

var (
	// templateExpressionRE matches one template expression or statement on
	// a single line: Twig, Jinja, Blade, Liquid, and Hugo ({{ }} and {% %}),
	// ERB (<%= %>), and PHP (<? ?>).
	templateExpressionRE = regexp.MustCompile(`\{\{.*?\}\}|\{%.*?%\}|<%.*?%>|<\?.*?\?>`)
	quotedStringRE       = regexp.MustCompile(`"[^"\n]*"|'[^'\n]*'`)
)

// templateExpressionMentions reports whether a template expression refers
// to word as code: an identifier ({{ seo.canonical }}, canonical_url()), or
// a quoted name with no spaces in it ("canonical", "partials/_canonical").
// A sentence that merely contains the word ({{ "Our canonical guide" }}) is
// text, and text must not satisfy a check.
func templateExpressionMentions(content, word string) bool {
	for _, expr := range templateExpressionRE.FindAllString(content, -1) {
		lower := strings.ToLower(expr)
		if !strings.Contains(lower, word) {
			continue
		}
		if strings.Contains(quotedStringRE.ReplaceAllString(lower, ""), word) {
			return true
		}
		for _, quoted := range quotedStringRE.FindAllString(lower, -1) {
			if strings.Contains(quoted, word) && !strings.ContainsAny(quoted, " \t") {
				return true
			}
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
		content, err := readSourceFile(fullPath)
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
