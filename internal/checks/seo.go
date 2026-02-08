package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SEOMetadataCheck struct{}

func (c SEOMetadataCheck) ID() string {
	return "seoMeta"
}

func (c SEOMetadataCheck) Title() string {
	return "SEO metadata"
}

func (c SEOMetadataCheck) Run(ctx Context) (CheckResult, error) {
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
			Suggestions: []string{
				"Check that the mainLayout path is correct in preflight.yml",
			},
		}, nil
	}

	// Strip comments to avoid false positives on commented-out code
	contentStr := stripComments(string(content))

	// For Next.js, also check page files for metadata/generateMetadata
	if strings.Contains(layoutFile, "app/") {
		hasMetadataInApp := false
		appDir := filepath.Dir(filepath.Join(ctx.RootDir, layoutFile))
		// Check if layout has generateMetadata or metadata export
		generateMetadataPattern := regexp.MustCompile(`(?s)export\s+(async\s+)?function\s+generateMetadata`)
		metadataExportPattern := regexp.MustCompile(`(?s)export\s+(const|let|var)\s+metadata\s*[=:]`)

		_ = filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || hasMetadataInApp {
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			// Only check tsx/ts/jsx/js files
			nameLower := strings.ToLower(info.Name())
			if !strings.HasSuffix(nameLower, ".tsx") && !strings.HasSuffix(nameLower, ".ts") &&
				!strings.HasSuffix(nameLower, ".jsx") && !strings.HasSuffix(nameLower, ".js") {
				return nil
			}
			fileContent, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if generateMetadataPattern.Match(fileContent) || metadataExportPattern.Match(fileContent) {
				hasMetadataInApp = true
			}
			return nil
		})

		if hasMetadataInApp {
			// Metadata is handled somewhere in the app, pass all checks
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "SEO metadata configured via Next.js Metadata API",
			}, nil
		}
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
			if !checkAlternatePatterns(contentStr, name) {
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
			regexp.MustCompile(`\btitle\s*[:=]`),  // JSX/React
			regexp.MustCompile(`<Title>`),         // Next.js Head
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

	// If using generateMetadata, assume all metadata is handled dynamically
	if generateMetadata.MatchString(content) {
		return true
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
		// title: "..." or title: '...' or title: `...`
		titlePattern := regexp.MustCompile(`(?m)^\s*title\s*:\s*["'\x60]`)
		return titlePattern.MatchString(metadataContent)

	case "description":
		// description: "..." at the top level of metadata
		descPattern := regexp.MustCompile(`(?m)^\s*description\s*:\s*["'\x60]`)
		return descPattern.MatchString(metadataContent)

	case "og:title":
		// openGraph: { ... title: ... }
		ogBlock := extractNestedBlockSEO(metadataContent, "openGraph")
		if ogBlock != "" {
			titleInOG := regexp.MustCompile(`(?m)title\s*:\s*["'\x60]`)
			return titleInOG.MatchString(ogBlock)
		}
		return false

	case "og:description":
		// openGraph: { ... description: ... }
		ogBlock := extractNestedBlockSEO(metadataContent, "openGraph")
		if ogBlock != "" {
			descInOG := regexp.MustCompile(`(?m)description\s*:\s*["'\x60]`)
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
	pattern := regexp.MustCompile(`(?s)` + key + `\s*:\s*\{`)
	loc := pattern.FindStringIndex(content)
	if loc == nil {
		return ""
	}
	return extractBraceBlockSEO(content, loc[1]-1)
}
