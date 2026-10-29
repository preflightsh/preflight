package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SEOMetadataCheck struct{}

func (c SEOMetadataCheck) ID() string {
	return "seo_meta"
}

func (c SEOMetadataCheck) Title() string {
	return "SEO metadata"
}

func (c SEOMetadataCheck) Run(ctx Context) (CheckResult, error) {
	if r, ok := renderedResult(ctx, c, func(doc renderedDoc) []string {
		var missing []string
		for _, name := range []string{"title", "description", "og:title", "og:description"} {
			if !renderedHasSEOTag(doc, name) {
				missing = append(missing, name)
			}
		}
		return missing
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
			Passed:   true,
			Message:  "No layout file found, skipping",
		}, nil
	}

	layoutPath := filepath.Join(ctx.RootDir, layoutFile)
	content, err := readSourceFile(layoutPath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read layout file: " + layoutFile,
			Suggestions: []string{
				"Check that the mainLayout path is correct in preflight.yml",
			},
		}, nil
	}

	// Strip comments to avoid false positives on commented-out code
	contentStr := stripComments(string(content))

	// For the Next.js App Router, the root route's page and any top-level
	// route group layout can carry the Metadata API export instead of the
	// root layout. A metadata export on some nested page says nothing about
	// the rest of the site, so only those root-route files count.
	var nextSources []string
	if strings.Contains(layoutFile, "app/") {
		nextSources = nextRootRouteSources(filepath.Dir(layoutPath))
	}

	// Required SEO elements
	checks := map[string]*regexp.Regexp{
		"title":          regexp.MustCompile(`<title[^>]*>`),
		"description":    regexp.MustCompile(`<meta[^>]+name=["']description["'][^>]*>`),
		"og:title":       regexp.MustCompile(`<meta[^>]+property=["']og:title["'][^>]*>`),
		"og:description": regexp.MustCompile(`<meta[^>]+property=["']og:description["'][^>]*>`),
	}

	var missing []string
	for name, pattern := range checks {
		if !pattern.MatchString(contentStr) {
			// Check for alternate patterns (some frameworks use different formats)
			if !checkAlternatePatterns(contentStr, name) && !anyNextSource(nextSources, name, hasNextJSMetadata) {
				missing = append(missing, name)
			}
		}
	}

	if len(missing) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "All required SEO metadata present",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Missing SEO metadata: " + strings.Join(missing, ", "),
		Suggestions: []string{
			"Add missing meta tags to your layout",
			"Consider using a SEO component or helper",
		},
	}, nil
}

// renderedHasSEOTag reports whether the parsed rendered HTML contains the
// named SEO element.
func renderedHasSEOTag(doc renderedDoc, name string) bool {
	switch name {
	case "title":
		return doc.title != ""
	case "description":
		return strings.TrimSpace(doc.metaName["description"]) != ""
	case "og:title", "og:description":
		return doc.hasMeta(name)
	}
	return false
}

// getLayoutFile returns the configured layout or auto-detects one based on stack
func getLayoutFile(rootDir string, stack string, configuredLayout string) string {
	// Use configured layout if set
	if configuredLayout != "" {
		return configuredLayout
	}

	// Auto-detect based on stack
	layoutsByStack := map[string][]string{
		"next": {
			"app/layout.tsx", "app/layout.js", "app/layout.jsx",
			"src/app/layout.tsx", "src/app/layout.js",
			"pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js",
		},
		"react": {
			"index.html", "public/index.html", "src/index.html",
		},
		"vite": {
			"index.html", "src/index.html",
		},
		"vue": {
			"index.html", "public/index.html", "src/App.vue",
		},
		"svelte": {
			"src/app.html", "index.html",
		},
		"remix": {
			"app/root.tsx", "app/root.jsx",
		},
		"nuxt": {
			"app.vue", "app/app.vue", "layouts/default.vue",
			"nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs",
		},
		"angular": {
			"src/index.html",
		},
		"rails": {
			"app/views/layouts/application.html.erb",
			"app/views/layouts/base.html.erb",
		},
		"laravel": {
			"resources/views/layouts/app.blade.php",
			"resources/views/layouts/main.blade.php",
		},
		"django": {
			"templates/base.html",
			"templates/layout.html",
		},
		"craft": {
			"templates/_layout.twig",
			"templates/_layouts/main.twig",
			"templates/_layouts/base.twig",
			"templates/_base.twig",
		},
		"hugo": {
			"layouts/_default/baseof.html",
			"layouts/_default/base.html",
		},
		"jekyll": {
			"_layouts/default.html",
			"_layouts/base.html",
		},
		"gatsby": {
			"src/components/layout.js",
			"src/components/Layout.js",
			"src/components/layout.tsx",
		},
		"astro": {
			"src/layouts/Layout.astro",
			"src/layouts/Base.astro",
			"src/layouts/BaseLayout.astro",
		},
		"eleventy": {
			"_includes/base.njk",
			"_includes/layout.njk",
		},
		"php": {
			"templates/layout.php",
			"includes/header.php",
			"layout.php",
		},
		"node": {
			"views/layout.ejs",
			"views/layout.pug",
			"views/layouts/main.hbs",
		},
	}

	// Try stack-specific layouts first
	if layouts, ok := layoutsByStack[stack]; ok {
		for _, layout := range layouts {
			if _, err := os.Stat(filepath.Join(rootDir, layout)); err == nil {
				return layout
			}
		}
	}

	// Fallback: try common layouts for any stack
	commonLayouts := []string{
		"app/layout.tsx", "app/layout.js",
		"index.html", "public/index.html",
		"src/app.html",                 // SvelteKit
		"app/root.tsx", "app/root.jsx", // Remix
		"templates/_layout.twig",
		"app/views/layouts/application.html.erb",
	}
	for _, layout := range commonLayouts {
		if _, err := os.Stat(filepath.Join(rootDir, layout)); err == nil {
			return layout
		}
	}

	return ""
}

func checkAlternatePatterns(content, name string) bool {
	alternates := map[string][]*regexp.Regexp{
		"title": {
			// A title prop on a component (<Seo title="...">, <Head title=...>)
			// or a title key in a JS object. A bare title= attribute on an
			// HTML element (<a title="Home">) is a tooltip, not the page title.
			regexp.MustCompile(`<[A-Z][\w.]*\b[^>]*\btitle\s*=`),
			regexp.MustCompile(`\btitle\s*:`),
			regexp.MustCompile(`<Title>`), // Next.js Head
		},
		"description": {
			regexp.MustCompile(`name:\s*["']description["']`),
			regexp.MustCompile(`<meta\s+name="description"`),
		},
		"og:title": {
			regexp.MustCompile(`property:\s*["']og:title["']`),
		},
		"og:description": {
			regexp.MustCompile(`property:\s*["']og:description["']`),
		},
	}

	if patterns, ok := alternates[name]; ok {
		for _, pattern := range patterns {
			if pattern.MatchString(content) {
				return true
			}
		}
	}

	// Check for Next.js Metadata API (handles multi-line)
	if hasNextJSMetadata(content, name) {
		return true
	}

	return false
}

// hasNextJSMetadata checks for Next.js App Router Metadata API patterns
func hasNextJSMetadata(content, name string) bool {
	// Check if this looks like a Next.js metadata export or generateMetadata function
	metadataExport := regexp.MustCompile(`(?s)export\s+(const|let|var)\s+metadata\s*[=:]`)
	generateMetadata := regexp.MustCompile(`(?s)export\s+(async\s+)?function\s+generateMetadata`)

	// A dynamic generator is not evidence that any required field exists.
	if generateMetadata.MatchString(content) {
		return false
	}

	if !metadataExport.MatchString(content) {
		return false
	}

	// Find the start of the metadata object using brace matching
	metadataStart := regexp.MustCompile(`(?s)export\s+(?:const|let|var)\s+metadata[^=]*=\s*\{`)
	loc := metadataStart.FindStringIndex(content)
	if loc == nil {
		return false
	}

	// Extract metadata block with proper brace matching
	metadataContent := extractBraceBlockSEO(content, loc[1]-1)
	if metadataContent == "" {
		return false
	}

	switch name {
	case "title":
		// title: "...", title: siteConfig.name or title: { default, template }
		titlePattern := regexp.MustCompile(`(?m)^\s*title\s*:\s*[^\s,}]`)
		return titlePattern.MatchString(metadataContent)

	case "description":
		// description at the top level of metadata, as a literal or an identifier
		descPattern := regexp.MustCompile(`(?m)^\s*description\s*:\s*[^\s,}]`)
		return descPattern.MatchString(metadataContent)

	case "og:title":
		// openGraph: { ... title: ... }
		ogBlock := extractNestedBlockSEO(metadataContent, "openGraph")
		if ogBlock != "" {
			titleInOG := regexp.MustCompile(`(?m)title\s*:\s*[^\s,}]`)
			return titleInOG.MatchString(ogBlock)
		}
		return false

	case "og:description":
		// openGraph: { ... description: ... }
		ogBlock := extractNestedBlockSEO(metadataContent, "openGraph")
		if ogBlock != "" {
			descInOG := regexp.MustCompile(`(?m)description\s*:\s*[^\s,}]`)
			return descInOG.MatchString(ogBlock)
		}
		return false
	}

	return false
}

// extractBraceBlockSEO extracts content between matching braces starting at pos
func extractBraceBlockSEO(content string, pos int) string {
	if pos >= len(content) || content[pos] != '{' {
		return ""
	}
	depth := 0
	inString := false
	stringChar := byte(0)
	for i := pos; i < len(content); i++ {
		c := content[i]
		// Handle string literals to avoid counting braces inside strings
		if !inString && (c == '"' || c == '\'' || c == '`') {
			inString = true
			stringChar = c
		} else if inString && c == stringChar && (i == 0 || content[i-1] != '\\') {
			inString = false
		} else if !inString {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					return content[pos : i+1]
				}
			}
		}
	}
	return ""
}

// extractNestedBlockSEO extracts a nested object block like openGraph: { ... }
func extractNestedBlockSEO(content, key string) string {
	pattern := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(key) + `\s*:\s*\{`)
	loc := pattern.FindStringIndex(content)
	if loc == nil {
		return ""
	}
	return extractBraceBlockSEO(content, loc[1]-1)
}

// resolveTemplateIncludes extracts template include/extends paths from content,
// resolves them relative to the template root, and returns absolute paths that exist on disk.
func resolveTemplateIncludes(content, rootDir, stack string) []string {
	var paths []string
	seen := make(map[string]bool)

	templateRoots := getTemplateRoots(rootDir, stack)
	rawPaths := extractIncludePaths(content)

	for _, raw := range rawPaths {
		for _, root := range templateRoots {
			fullPath := filepath.Join(root, raw)
			if _, err := os.Stat(fullPath); err == nil {
				if !seen[fullPath] {
					seen[fullPath] = true
					paths = append(paths, fullPath)
				}
			}
		}
	}

	return paths
}

func getTemplateRoots(rootDir, stack string) []string {
	switch stack {
	case "craft":
		return []string{filepath.Join(rootDir, "templates")}
	case "laravel":
		return []string{filepath.Join(rootDir, "resources", "views")}
	case "rails":
		return []string{filepath.Join(rootDir, "app", "views")}
	case "hugo":
		return []string{filepath.Join(rootDir, "layouts")}
	case "jekyll":
		return []string{
			filepath.Join(rootDir, "_layouts"),
			filepath.Join(rootDir, "_includes"),
		}
	default:
		return []string{rootDir}
	}
}

func extractIncludePaths(content string) []string {
	var paths []string

	// Twig: {% include '...' %} and {% extends '...' %}
	twigPattern := regexp.MustCompile(`\{%[-\s]+(?:include|extends)\s+['"]([^'"]+)['"]`)
	for _, match := range twigPattern.FindAllStringSubmatch(content, -1) {
		path := match[1]
		if idx := strings.Index(path, "|"); idx != -1 {
			path = path[:idx]
		}
		paths = append(paths, path)
	}

	// Blade: @include('...') and @extends('...')
	bladePattern := regexp.MustCompile(`@(?:include|extends)\s*\(\s*['"]([^'"]+)['"]`)
	for _, match := range bladePattern.FindAllStringSubmatch(content, -1) {
		path := strings.ReplaceAll(match[1], ".", "/") + ".blade.php"
		paths = append(paths, path)
	}

	// ERB: <%= render partial: '...' %> and <%= render '...' %>
	erbPattern := regexp.MustCompile(`<%=\s*render\s+(?:partial:\s*)?['"]([^'"]+)['"]`)
	for _, match := range erbPattern.FindAllStringSubmatch(content, -1) {
		path := match[1]
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		if !strings.HasPrefix(base, "_") {
			base = "_" + base
		}
		if !strings.HasSuffix(base, ".html.erb") {
			base = base + ".html.erb"
		}
		if dir == "." {
			paths = append(paths, base)
		} else {
			paths = append(paths, filepath.Join(dir, base))
		}
	}

	return paths
}
