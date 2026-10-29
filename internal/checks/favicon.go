package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Compiled once; both used to be rebuilt inside per-file loops.
var (
	appleTouchIconRe = regexp.MustCompile(`(?i)apple-touch-icon`)
	// Next.js metadata icons API with an apple entry.
	nextAppleIconRe = regexp.MustCompile(`(?i)icons\s*[:=]\s*\{[^}]*apple\s*:`)
	// <link rel="icon">, rel="shortcut icon" or rel="icon shortcut", in
	// any attribute order. apple-touch-icon is its own token and does not
	// count as a favicon.
	faviconLinkRe = regexp.MustCompile(`(?i)<link\b[^>]*\brel\s*=\s*["'](?:shortcut\s+)?icon(?:\s+shortcut)?["']`)
	// Next.js metadata icons API: icons: '/x.png', icons: ['/x.png'],
	// icons: { icon: ... } or icons: { shortcut: ... }.
	nextFaviconRe = regexp.MustCompile("(?i)\\bicons\\s*:\\s*(?:[\"'`\\[]|\\{[^}]*\\b(?:icon|shortcut)\\s*:)")
	// Rails' favicon_link_tag helper emits <link rel="icon">.
	railsFaviconTagRe = regexp.MustCompile(`\bfavicon_link_tag\b`)
)

// iconLayoutTemplates are layouts and head partials that commonly declare
// <link rel="icon"> and <link rel="apple-touch-icon">.
var iconLayoutTemplates = []string{
	"templates/_layout.twig", // Craft CMS
	"templates/_layout.html", // Craft CMS
	"templates/_head.twig",   // Craft CMS partials
	"templates/_head.html",
	"templates/_partials/head.twig",          // Craft CMS partials
	"templates/_partials/header.twig",        // Craft CMS partials
	"app/views/layouts/application.html.erb", // Rails
	"resources/views/layouts/app.blade.php",  // Laravel
	"_includes/head.html",                    // Jekyll
	"layouts/_default/baseof.html",           // Hugo
	"src/layouts/Layout.astro",               // Astro
	"index.html",                             // Vite, static
	"public/index.html",                      // Create React App, Vue CLI
	"src/index.html",                         // Angular
	"src/app.html",                           // SvelteKit
	"app/root.tsx",                           // Remix
	"app/root.jsx",
	"app.vue", // Nuxt
	"nuxt.config.ts",
	"nuxt.config.js",
	"pages/_document.tsx", // Next.js Pages Router
	"pages/_document.js",
	"src/pages/_document.tsx",
	"src/pages/_document.js",
}

// iconLayoutSources lists the layout files, relative to the root, that the
// favicon check reads for icon declarations: the configured layout, the
// common templates above, and Next.js App Router root layouts (including
// monorepo apps).
func iconLayoutSources(ctx Context) []string {
	var paths []string
	if cfg := ctx.Config.Checks.SEOMeta; cfg != nil && cfg.MainLayout != "" {
		paths = append(paths, cfg.MainLayout)
	}
	paths = append(paths, iconLayoutTemplates...)
	paths = append(paths,
		"app/layout.tsx",
		"app/layout.js",
		"app/layout.jsx",
		"src/app/layout.tsx",
		"src/app/layout.js",
		"src/app/layout.jsx",
	)
	monorepoLayoutPaths := findMonorepoAppRouterPaths(ctx.RootDir, "layout.tsx")
	monorepoLayoutPaths = append(monorepoLayoutPaths, findMonorepoAppRouterPaths(ctx.RootDir, "layout.js")...)
	for _, path := range monorepoLayoutPaths {
		paths = append(paths, relPath(ctx.RootDir, path))
	}
	return paths
}

// sourceDeclaresFavicon returns the first layout that declares a favicon
// through a <link rel="icon"> tag, the Next.js metadata icons API, or
// Rails' favicon_link_tag. Commented-out declarations do not count.
func sourceDeclaresFavicon(ctx Context) (string, bool) {
	for _, rel := range iconLayoutSources(ctx) {
		content, err := readSourceFile(filepath.Join(ctx.RootDir, rel))
		if err != nil {
			continue
		}
		text := stripCodeComments(string(content))
		if faviconLinkRe.MatchString(text) || nextFaviconRe.MatchString(text) || railsFaviconTagRe.MatchString(text) {
			return rel, true
		}
	}
	return "", false
}

type FaviconCheck struct{}

func (c FaviconCheck) ID() string {
	return "favicon"
}

func (c FaviconCheck) Title() string {
	return "Favicon and app icons"
}

func (c FaviconCheck) Run(ctx Context) (CheckResult, error) {
	var found []string
	var missing []string

	// Common web root directories across frameworks
	webRoots := []string{
		"public",  // Laravel, Rails, many Node.js
		"static",  // Hugo, some SSGs
		"web",     // Craft CMS, Symfony
		"www",     // Some PHP apps
		"dist",    // Built static sites
		"build",   // Build outputs
		"_site",   // Jekyll
		"out",     // Next.js static export
		"app",     // Next.js App Router (pages)
		"src/app", // Next.js App Router (standard)
		"src",     // Angular (src/favicon.ico)
		"",        // Root directory
	}

	// Also check monorepo structures for Next.js App Router
	monorepoFaviconPaths := findMonorepoAppRouterPaths(ctx.RootDir, "favicon.ico")
	monorepoFaviconPaths = append(monorepoFaviconPaths, findMonorepoAppRouterPaths(ctx.RootDir, "favicon.png")...)
	monorepoFaviconPaths = append(monorepoFaviconPaths, findMonorepoAppRouterPaths(ctx.RootDir, "icon.png")...)
	monorepoFaviconPaths = append(monorepoFaviconPaths, findMonorepoAppRouterPaths(ctx.RootDir, "icon.svg")...)

	// Check for common favicon locations
	faviconFiles := []string{"favicon.ico", "favicon.png", "favicon.svg", "favicon.webp", "icon.png", "icon.svg"}
	var faviconPaths []string
	for _, root := range webRoots {
		for _, file := range faviconFiles {
			if root == "" {
				faviconPaths = append(faviconPaths, file)
			} else {
				faviconPaths = append(faviconPaths, root+"/"+file)
				// Also check assets subdirectories
				faviconPaths = append(faviconPaths, root+"/assets/"+file)
				faviconPaths = append(faviconPaths, root+"/assets/images/"+file)
				faviconPaths = append(faviconPaths, root+"/images/"+file)
				faviconPaths = append(faviconPaths, root+"/img/"+file)
				// realfavicongenerator and similar tools dump everything
				// into a /favicons/ subdir.
				faviconPaths = append(faviconPaths, root+"/favicons/"+file)
				faviconPaths = append(faviconPaths, root+"/favicon/"+file)
			}
		}
	}

	hasFavicon := false
	for _, path := range faviconPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			hasFavicon = true
			found = append(found, path)
			break
		}
	}

	// Check monorepo paths if not found
	if !hasFavicon {
		for _, path := range monorepoFaviconPaths {
			if _, err := os.Stat(path); err == nil {
				hasFavicon = true
				// Make path relative for display
				relPath := relPath(ctx.RootDir, path)
				found = append(found, relPath)
				break
			}
		}
	}

	// Flexible search: walk app directories for dynamic icon files (Next.js icon.tsx, etc.)
	if !hasFavicon {
		flexIconDirs := []string{"app", "src/app"}
		for _, dir := range flexIconDirs {
			if hasFavicon {
				break
			}
			dirPath := filepath.Join(ctx.RootDir, dir)
			if _, err := os.Stat(dirPath); err != nil {
				continue
			}
			_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if hasFavicon {
					return nil
				}
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == ".git" {
						return filepath.SkipDir
					}
					return nil
				}
				nameLower := strings.ToLower(info.Name())
				// Match icon.tsx, icon.ts, icon.jsx, icon.js, favicon.tsx, etc.
				if nameLower == "icon.tsx" || nameLower == "icon.ts" || nameLower == "icon.jsx" || nameLower == "icon.js" ||
					nameLower == "favicon.tsx" || nameLower == "favicon.ts" || nameLower == "favicon.jsx" || nameLower == "favicon.js" {
					hasFavicon = true
					relPath := relPath(ctx.RootDir, path)
					found = append(found, relPath)
					return nil
				}
				return nil
			})
		}
	}

	// A layout that links its icon from a non-standard path
	// (<link rel="icon" href="/brand/mark.svg">, Next.js
	// icons: { icon: ... }) still has one.
	if !hasFavicon {
		if rel, ok := sourceDeclaresFavicon(ctx); ok {
			hasFavicon = true
			found = append(found, "favicon (declared in "+rel+")")
		}
	}

	if !hasFavicon {
		missing = append(missing, "favicon")
	}

	// Check for Apple Touch Icon (supports multiple formats)
	appleIconFiles := []string{
		"apple-touch-icon.png", "apple-touch-icon.webp", "apple-touch-icon.jpg", "apple-touch-icon.svg",
		"apple-icon.png", "apple-icon.webp", "apple-icon.jpg", "apple-icon.svg",
	}
	var appleTouchPaths []string
	for _, root := range webRoots {
		for _, file := range appleIconFiles {
			if root == "" {
				appleTouchPaths = append(appleTouchPaths, file)
			} else {
				appleTouchPaths = append(appleTouchPaths, root+"/"+file)
				// Also check assets subdirectories
				appleTouchPaths = append(appleTouchPaths, root+"/assets/"+file)
				appleTouchPaths = append(appleTouchPaths, root+"/assets/images/"+file)
				appleTouchPaths = append(appleTouchPaths, root+"/images/"+file)
				appleTouchPaths = append(appleTouchPaths, root+"/img/"+file)
				appleTouchPaths = append(appleTouchPaths, root+"/favicons/"+file)
				appleTouchPaths = append(appleTouchPaths, root+"/favicon/"+file)
			}
		}
	}

	hasAppleIcon := false
	for _, path := range appleTouchPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			hasAppleIcon = true
			found = append(found, path)
			break
		}
	}

	// Also check HTML/templates for apple-touch-icon link
	if !hasAppleIcon {
		// Check configured layout first
		cfg := ctx.Config.Checks.SEOMeta
		if cfg != nil && cfg.MainLayout != "" {
			layoutPath := filepath.Join(ctx.RootDir, cfg.MainLayout)
			if content, err := readSourceFile(layoutPath); err == nil {
				if appleTouchIconRe.Match(content) {
					hasAppleIcon = true
					found = append(found, "apple-touch-icon (in HTML)")
				}
			}
		}

		// Check common template locations
		if !hasAppleIcon {
			for _, tplPath := range iconLayoutTemplates {
				fullPath := filepath.Join(ctx.RootDir, tplPath)
				if content, err := readSourceFile(fullPath); err == nil {
					if appleTouchIconRe.Match(content) {
						hasAppleIcon = true
						found = append(found, "apple-touch-icon (in HTML)")
						break
					}
				}
			}
		}

		// Check Next.js App Router layout.tsx for metadata icons API
		if !hasAppleIcon {
			nextLayoutPaths := []string{
				"app/layout.tsx",
				"app/layout.js",
				"src/app/layout.tsx",
				"src/app/layout.js",
			}
			// Also check monorepo paths
			monorepoLayoutPaths := findMonorepoAppRouterPaths(ctx.RootDir, "layout.tsx")
			monorepoLayoutPaths = append(monorepoLayoutPaths, findMonorepoAppRouterPaths(ctx.RootDir, "layout.js")...)

			allLayoutPaths := nextLayoutPaths
			for _, path := range monorepoLayoutPaths {
				relPath := relPath(ctx.RootDir, path)
				allLayoutPaths = append(allLayoutPaths, relPath)
			}

			for _, layoutPath := range allLayoutPaths {
				fullPath := filepath.Join(ctx.RootDir, layoutPath)
				if content, err := readSourceFile(fullPath); err == nil {
					// Check for Next.js metadata icons with apple property
					if nextAppleIconRe.Match(content) {
						hasAppleIcon = true
						found = append(found, "apple-touch-icon (in Next.js metadata)")
						break
					}
				}
			}
		}
	}

	// Flexible search: walk app directories for dynamic apple-icon files
	if !hasAppleIcon {
		flexAppleDirs := []string{"app", "src/app"}
		for _, dir := range flexAppleDirs {
			if hasAppleIcon {
				break
			}
			dirPath := filepath.Join(ctx.RootDir, dir)
			if _, err := os.Stat(dirPath); err != nil {
				continue
			}
			_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if hasAppleIcon {
					return nil
				}
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == ".git" {
						return filepath.SkipDir
					}
					return nil
				}
				nameLower := strings.ToLower(info.Name())
				// Match apple-icon.tsx, apple-icon.ts, etc.
				if strings.HasPrefix(nameLower, "apple-icon.") && (strings.HasSuffix(nameLower, ".tsx") || strings.HasSuffix(nameLower, ".ts") || strings.HasSuffix(nameLower, ".jsx") || strings.HasSuffix(nameLower, ".js")) {
					hasAppleIcon = true
					relPath := relPath(ctx.RootDir, path)
					found = append(found, relPath)
					return nil
				}
				return nil
			})
		}
	}

	if !hasAppleIcon {
		missing = append(missing, "apple-touch-icon")
	}

	// Check for web app manifest
	var manifestPaths []string
	for _, root := range webRoots {
		if root == "" {
			manifestPaths = append(manifestPaths, "manifest.json", "site.webmanifest")
		} else {
			manifestPaths = append(manifestPaths,
				root+"/manifest.json",
				root+"/site.webmanifest",
				root+"/manifest.ts",
				root+"/manifest.js",
				root+"/favicons/site.webmanifest",
				root+"/favicons/manifest.json",
				root+"/favicon/site.webmanifest",
				root+"/favicon/manifest.json",
			)
		}
	}

	// Add Next.js App Router manifest locations
	nextManifestPaths := []string{
		"app/manifest.ts",
		"app/manifest.js",
		"src/app/manifest.ts",
		"src/app/manifest.js",
	}
	manifestPaths = append(manifestPaths, nextManifestPaths...)

	hasManifest := false
	for _, path := range manifestPaths {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			hasManifest = true
			found = append(found, path)
			break
		}
	}

	// Check monorepo paths for manifest
	if !hasManifest {
		monorepoManifestPaths := findMonorepoAppRouterPaths(ctx.RootDir, "manifest.ts")
		monorepoManifestPaths = append(monorepoManifestPaths, findMonorepoAppRouterPaths(ctx.RootDir, "manifest.js")...)
		for _, path := range monorepoManifestPaths {
			if _, err := os.Stat(path); err == nil {
				hasManifest = true
				relPath := relPath(ctx.RootDir, path)
				found = append(found, relPath)
				break
			}
		}
	}

	// Flexible search: walk app directories for dynamic manifest files
	if !hasManifest {
		flexManifestDirs := []string{"app", "src/app"}
		for _, dir := range flexManifestDirs {
			if hasManifest {
				break
			}
			dirPath := filepath.Join(ctx.RootDir, dir)
			if _, err := os.Stat(dirPath); err != nil {
				continue
			}
			_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if hasManifest {
					return nil
				}
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == ".git" {
						return filepath.SkipDir
					}
					return nil
				}
				nameLower := strings.ToLower(info.Name())
				// Match manifest.ts, manifest.tsx, manifest.js, manifest.jsx, webmanifest files
				if nameLower == "manifest.ts" || nameLower == "manifest.tsx" || nameLower == "manifest.js" || nameLower == "manifest.jsx" {
					hasManifest = true
					relPath := relPath(ctx.RootDir, path)
					found = append(found, relPath)
					return nil
				}
				return nil
			})
		}
	}

	if !hasManifest {
		missing = append(missing, "web manifest")
	}

	// Final fallback: scan rendered homepage HTML for <link rel="icon">,
	// apple-touch-icon, and manifest references. Catches CMS-driven sites
	// (Craft+SEOmatic, WordPress, etc.) where icons live in a partial we
	// haven't catalogued, or are emitted by a plugin at runtime.
	if ctx.PageHTML != "" && len(missing) > 0 {
		doc := parseRenderedHTML(ctx.PageHTML)
		if !hasFavicon && doc.hasLinkRel("icon") {
			hasFavicon = true
			found = append(found, "favicon (in rendered HTML)")
		}
		if !hasAppleIcon && doc.hasLinkRel("apple-touch-icon") {
			hasAppleIcon = true
			found = append(found, "apple-touch-icon (in rendered HTML)")
		}
		if !hasManifest && doc.hasLinkRel("manifest") {
			hasManifest = true
			found = append(found, "manifest (in rendered HTML)")
		}
		missing = missing[:0]
		if !hasFavicon {
			missing = append(missing, "favicon")
		}
		if !hasAppleIcon {
			missing = append(missing, "apple-touch-icon")
		}
		if !hasManifest {
			missing = append(missing, "web manifest")
		}
	}

	// Determine result
	if len(missing) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "All icons and manifest present",
		}, nil
	}

	if hasFavicon && len(missing) <= 2 {
		// Has favicon but missing apple icon or manifest - just warn
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Missing: " + strings.Join(missing, ", "),
			Suggestions: []string{
				"Add apple-touch-icon.png (180x180px) for iOS",
				"Add manifest.json for PWA support",
			},
		}, nil
	}

	// A missing favicon is a polish issue, not a launch blocker.
	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Missing: " + strings.Join(missing, ", "),
		Suggestions: []string{
			"Add favicon.ico or favicon.png to public/",
			"Use https://realfavicongenerator.net for complete icon set",
		},
	}, nil
}

// findMonorepoAppRouterPaths searches for a file in common monorepo structures
// with Next.js App Router convention (apps/*/src/app/, packages/*/src/app/)
func findMonorepoAppRouterPaths(rootDir, filename string) []string {
	var paths []string

	// Common monorepo directory names
	monorepoRoots := []string{"apps", "packages", "services"}

	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			// Check src/app/ pattern (standard Next.js App Router)
			srcAppPath := filepath.Join(monoDir, entry.Name(), "src", "app", filename)
			paths = append(paths, srcAppPath)

			// Check app/ pattern (alternative)
			appPath := filepath.Join(monoDir, entry.Name(), "app", filename)
			paths = append(paths, appPath)
		}
	}

	return paths
}
