package checks

import (
	"os"
	"path/filepath"
)

type ErrorPagesCheck struct{}

func (c ErrorPagesCheck) ID() string {
	return "error_pages"
}

func (c ErrorPagesCheck) Title() string {
	return "Error pages (404, 500)"
}

func (c ErrorPagesCheck) Run(ctx Context) (CheckResult, error) {
	stack := ctx.Config.Stack

	// Get expected error page paths for this stack
	paths404, paths500 := getErrorPagePaths(stack)

	// Also check common web roots for static error pages
	webRoots := []string{"public", "static", "web", "www", "dist", "build", "_site", "out", ""}

	has404 := false
	has500 := false
	found404 := ""

	// Check stack-specific paths first
	for _, path := range paths404 {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			has404 = true
			found404 = path
			break
		}
	}

	for _, path := range paths500 {
		fullPath := filepath.Join(ctx.RootDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			has500 = true
			break
		}
	}

	// Check web roots for static 404.html/500.html if not found
	if !has404 {
		for _, root := range webRoots {
			path := filepath.Join(root, "404.html")
			fullPath := filepath.Join(ctx.RootDir, path)
			if _, err := os.Stat(fullPath); err == nil {
				has404 = true
				found404 = path
				break
			}
		}
	}

	if !has500 {
		for _, root := range webRoots {
			path := filepath.Join(root, "500.html")
			fullPath := filepath.Join(ctx.RootDir, path)
			if _, err := os.Stat(fullPath); err == nil {
				has500 = true
				break
			}
		}
	}

	// Check monorepo paths for Next.js
	if !has404 && (stack == "next" || stack == "react") {
		monorepo404 := findMonorepoErrorPages(ctx.RootDir, "404")
		if len(monorepo404) > 0 {
			has404 = true
			relPath, _ := filepath.Rel(ctx.RootDir, monorepo404[0])
			found404 = relPath
		}
	}

	if !has500 && (stack == "next" || stack == "react") {
		monorepo500 := findMonorepoErrorPages(ctx.RootDir, "500")
		if len(monorepo500) > 0 {
			has500 = true
		}
	}

	// Build result
	if has404 && has500 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Custom error pages configured",
		}, nil
	}

	if has404 && !has500 {
		// 404 is more important, 500 is nice to have
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "404 page found (" + found404 + "), 500 page not found",
		}, nil
	}

	// Missing 404 page - this is a warning
	suggestions := getErrorPageSuggestions(stack)

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     "No custom 404 page found",
		Suggestions: suggestions,
	}, nil
}

// getErrorPagePaths returns the expected paths for 404 and 500 error pages based on stack
func getErrorPagePaths(stack string) (paths404 []string, paths500 []string) {
	switch stack {
	case "rails":
		paths404 = []string{"public/404.html"}
		paths500 = []string{"public/500.html", "public/422.html"}

	case "laravel":
		paths404 = []string{
			"resources/views/errors/404.blade.php",
			"resources/views/errors/404.html",
		}
		paths500 = []string{
			"resources/views/errors/500.blade.php",
			"resources/views/errors/500.html",
		}

	case "next":
		// Pages Router
		paths404 = []string{
			"pages/404.tsx", "pages/404.js", "pages/404.jsx",
			"src/pages/404.tsx", "src/pages/404.js", "src/pages/404.jsx",
			// App Router
			"app/not-found.tsx", "app/not-found.js", "app/not-found.jsx",
			"src/app/not-found.tsx", "src/app/not-found.js", "src/app/not-found.jsx",
		}
		paths500 = []string{
			"pages/500.tsx", "pages/500.js", "pages/500.jsx",
			"pages/_error.tsx", "pages/_error.js", "pages/_error.jsx",
			"src/pages/500.tsx", "src/pages/500.js", "src/pages/500.jsx",
			// App Router
			"app/error.tsx", "app/error.js", "app/error.jsx",
			"app/global-error.tsx", "app/global-error.js", "app/global-error.jsx",
			"src/app/error.tsx", "src/app/error.js", "src/app/error.jsx",
		}

	case "django":
		paths404 = []string{"templates/404.html", "templates/errors/404.html"}
		paths500 = []string{"templates/500.html", "templates/errors/500.html"}

	case "wordpress":
		// WordPress uses 404.php in theme directory
		paths404 = []string{
			"404.php",
			"wp-content/themes/theme/404.php",
		}
		paths500 = []string{}

	case "craft":
		paths404 = []string{
			"templates/404.twig",
			"templates/404.html",
			"templates/error.twig",
			"templates/errors/404.twig",
			"templates/errors/404.html",
		}
		paths500 = []string{
			"templates/500.twig",
			"templates/500.html",
			"templates/error.twig",
			"templates/errors/500.twig",
		}

	case "drupal":
		paths404 = []string{
			"themes/custom/theme/templates/page--404.html.twig",
			"web/themes/custom/theme/templates/page--404.html.twig",
		}
		paths500 = []string{}

	case "hugo":
		paths404 = []string{
			"layouts/404.html",
			"themes/theme/layouts/404.html",
		}
		paths500 = []string{}

	case "jekyll":
		paths404 = []string{"404.html", "404.md", "_pages/404.html", "_pages/404.md"}
		paths500 = []string{}

	case "gatsby":
		paths404 = []string{
			"src/pages/404.js", "src/pages/404.tsx", "src/pages/404.jsx",
		}
		paths500 = []string{}

	case "astro":
		paths404 = []string{
			"src/pages/404.astro",
			"src/pages/404.md",
		}
		paths500 = []string{
			"src/pages/500.astro",
		}

	case "eleventy":
		paths404 = []string{
			"404.html", "404.md", "404.njk", "404.liquid",
			"src/404.html", "src/404.md", "src/404.njk",
		}
		paths500 = []string{}

	case "ghost":
		paths404 = []string{
			"content/themes/casper/error.hbs",
			"content/themes/casper/error-404.hbs",
		}
		paths500 = []string{}

	case "vue", "vite", "react", "angular", "svelte":
		// SPAs typically handle routing client-side
		// Check for common patterns
		paths404 = []string{
			"src/pages/404.vue", "src/views/404.vue", "src/pages/NotFound.vue",
			"src/pages/404.tsx", "src/pages/404.jsx", "src/pages/NotFound.tsx",
			"src/routes/404.svelte", "src/pages/404.svelte",
			"public/404.html",
		}
		paths500 = []string{}

	case "go", "rust", "node", "python":
		// These typically handle errors in code, check for static fallbacks
		paths404 = []string{"public/404.html", "static/404.html", "templates/404.html"}
		paths500 = []string{"public/500.html", "static/500.html", "templates/500.html"}

	case "static":
		paths404 = []string{"404.html"}
		paths500 = []string{"500.html"}

	default:
		paths404 = []string{"404.html", "public/404.html"}
		paths500 = []string{"500.html", "public/500.html"}
	}

	return paths404, paths500
}

// getErrorPageSuggestions returns helpful suggestions based on stack
func getErrorPageSuggestions(stack string) []string {
	switch stack {
	case "rails":
		return []string{"Add custom public/404.html and public/500.html"}

	case "laravel":
		return []string{
			"Run: php artisan vendor:publish --tag=laravel-errors",
			"Or create resources/views/errors/404.blade.php",
		}

	case "next":
		return []string{
			"Create pages/404.tsx (Pages Router)",
			"Or create app/not-found.tsx (App Router)",
		}

	case "django":
		return []string{"Create templates/404.html and templates/500.html"}

	case "wordpress":
		return []string{"Create 404.php in your theme directory"}

	case "craft":
		return []string{"Create templates/404.twig for custom 404 page"}

	case "hugo":
		return []string{"Create layouts/404.html for custom 404 page"}

	case "jekyll":
		return []string{"Create 404.html or 404.md in project root"}

	case "gatsby":
		return []string{"Create src/pages/404.js for custom 404 page"}

	case "astro":
		return []string{"Create src/pages/404.astro for custom 404 page"}

	case "eleventy":
		return []string{"Create 404.md or 404.njk in project root"}

	case "vue", "vite":
		return []string{
			"Create src/pages/404.vue or handle in router",
			"Add public/404.html for server-side fallback",
		}

	case "react":
		return []string{
			"Handle 404 in your router (e.g., React Router's '*' route)",
			"Add public/404.html for server-side fallback",
		}

	default:
		return []string{"Add a custom 404.html page"}
	}
}

// findMonorepoErrorPages searches monorepo structures for error pages
func findMonorepoErrorPages(rootDir string, errorType string) []string {
	var paths []string

	monorepoRoots := []string{"apps", "packages", "services"}
	extensions := []string{".tsx", ".ts", ".js", ".jsx"}

	var filenames []string
	if errorType == "404" {
		filenames = []string{"404", "not-found"}
	} else {
		filenames = []string{"500", "error", "global-error"}
	}

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

			// Check pages directory (Pages Router)
			for _, filename := range filenames {
				for _, ext := range extensions {
					pagesPath := filepath.Join(monoDir, entry.Name(), "pages", filename+ext)
					if _, err := os.Stat(pagesPath); err == nil {
						paths = append(paths, pagesPath)
					}

					srcPagesPath := filepath.Join(monoDir, entry.Name(), "src", "pages", filename+ext)
					if _, err := os.Stat(srcPagesPath); err == nil {
						paths = append(paths, srcPagesPath)
					}

					// Check app directory (App Router)
					appPath := filepath.Join(monoDir, entry.Name(), "app", filename+ext)
					if _, err := os.Stat(appPath); err == nil {
						paths = append(paths, appPath)
					}

					srcAppPath := filepath.Join(monoDir, entry.Name(), "src", "app", filename+ext)
					if _, err := os.Stat(srcAppPath); err == nil {
						paths = append(paths, srcAppPath)
					}
				}
			}
		}
	}

	return paths
}
