package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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
		"public",     // Laravel, Rails, many Node.js
		"static",     // Hugo, some SSGs
		"web",        // Craft CMS, Symfony
		"www",        // Some PHP apps
		"dist",       // Built static sites
		"build",      // Build outputs
		"_site",      // Jekyll
		"out",        // Next.js static export
		"app",        // Next.js App Router (pages)
		"src/app",    // Next.js App Router (standard)
		"",           // Root directory
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
				relPath, _ := filepath.Rel(ctx.RootDir, path)
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
			filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || hasFavicon {
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
					relPath, _ := filepath.Rel(ctx.RootDir, path)
					found = append(found, relPath)
					return nil
				}
				return nil
			})
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
			if content, err := os.ReadFile(layoutPath); err == nil {
				if regexp.MustCompile(`(?i)apple-touch-icon`).Match(content) {
					hasAppleIcon = true
					found = append(found, "apple-touch-icon (in HTML)")
				}
			}
		}

		// Check common template locations
		if !hasAppleIcon {
			templatePaths := []string{
				"templates/_layout.twig",           // Craft CMS
				"templates/_layout.html",           // Craft CMS
				"templates/_head.twig",             // Craft CMS partials
				"templates/_head.html",
				"templates/_partials/head.twig",    // Craft CMS partials
				"templates/_partials/header.twig",  // Craft CMS partials
				"app/views/layouts/application.html.erb", // Rails
				"resources/views/layouts/app.blade.php",  // Laravel
				"_includes/head.html",              // Jekyll
				"layouts/_default/baseof.html",     // Hugo
				"src/layouts/Layout.astro",         // Astro
			}
			for _, tplPath := range templatePaths {
				fullPath := filepath.Join(ctx.RootDir, tplPath)
				if content, err := os.ReadFile(fullPath); err == nil {
					if regexp.MustCompile(`(?i)apple-touch-icon`).Match(content) {
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
				relPath, _ := filepath.Rel(ctx.RootDir, path)
				allLayoutPaths = append(allLayoutPaths, relPath)
			}

			for _, layoutPath := range allLayoutPaths {
				fullPath := filepath.Join(ctx.RootDir, layoutPath)
				if content, err := os.ReadFile(fullPath); err == nil {
					// Check for Next.js metadata icons with apple property
					if regexp.MustCompile(`(?i)icons\s*[:=]\s*\{[^}]*apple\s*:`).Match(content) {
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
			filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || hasAppleIcon {
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
					relPath, _ := filepath.Rel(ctx.RootDir, path)
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
				relPath, _ := filepath.Rel(ctx.RootDir, path)
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
			filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || hasManifest {
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
					relPath, _ := filepath.Rel(ctx.RootDir, path)
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
			Message:  "Missing: " + joinStrings(missing, ", "),
			Suggestions: []string{
				"Add apple-touch-icon.png (180x180px) for iOS",
				"Add manifest.json for PWA support",
			},
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityError,
		Passed:   false,
		Message:  "Missing favicon",
		Suggestions: []string{
			"Add favicon.ico or favicon.png to public/",
			"Use https://realfavicongenerator.net for complete icon set",
		},
	}, nil
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
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
