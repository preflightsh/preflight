package cmd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// One table of main-layout locations serves both `preflight init`, which
// writes the layout it finds to checks.seoMeta.mainLayout, and `preflight
// scan`, which turns the SEO checks on when a layout exists. They used to
// keep a table each, and the two had drifted: init knew BaseLayout.astro,
// templates/base.twig and views/layout.ejs, scan knew Remix, Nuxt, Svelte
// and Angular, and neither had the other's entries, so init could skip the
// seoMeta block for a project whose SEO checks scan then ran anyway.
//
// A path may hold a * for a directory whose name is the project's own
// (the active theme); the first match in sorted order is used.
var stackLayouts = map[string][]string{
	// Frameworks
	"rails": {
		"app/views/layouts/application.html.erb",
		"app/views/layouts/base.html.erb",
	},
	"next": {
		"app/layout.tsx", "app/layout.js", "app/layout.jsx",
		"src/app/layout.tsx", "src/app/layout.js", "src/app/layout.jsx",
		"pages/_document.tsx", "pages/_document.js",
		"pages/_app.tsx", "pages/_app.js",
		"src/pages/_document.tsx", "src/pages/_document.js",
		"src/pages/_app.tsx", "src/pages/_app.js",
	},
	"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs"},
	"react":   {"index.html", "public/index.html", "src/index.html"},
	"vite":    {"index.html", "src/index.html"},
	"vue":     {"index.html", "public/index.html", "src/App.vue"},
	"svelte":  {"src/app.html", "index.html"},
	"angular": {"src/index.html"},
	"remix":   {"app/root.tsx", "app/root.jsx"},
	"nuxt":    {"app.vue", "app/app.vue", "layouts/default.vue", "nuxt.config.ts", "nuxt.config.js"},
	"laravel": {
		"resources/views/layouts/app.blade.php",
		"resources/views/layouts/main.blade.php",
		"resources/views/layout.blade.php",
	},
	"django": {"templates/base.html", "templates/layout.html"},
	"static": {"index.html"},

	// Traditional CMS
	"wordpress": {"wp-content/themes/*/header.php"},
	"craft": {
		"templates/_layout.twig",
		"templates/_layout.html",
		"templates/_layouts/main.twig",
		"templates/_layouts/base.twig",
	},
	"drupal": {
		"web/themes/custom/*/templates/html.html.twig",
		"web/themes/custom/*/templates/layout/html.html.twig",
		"themes/custom/*/templates/html.html.twig",
		"themes/custom/*/templates/layout/html.html.twig",
	},
	"ghost": {"content/themes/*/default.hbs"},

	// Static Site Generators
	"hugo":     {"layouts/_default/baseof.html", "themes/*/layouts/_default/baseof.html"},
	"jekyll":   {"_layouts/default.html", "_layouts/base.html", "_includes/head.html"},
	"gatsby":   {"src/components/layout.js", "src/components/layout.tsx", "src/components/Layout.js", "src/templates/page.js"},
	"eleventy": {"_includes/layout.njk", "_includes/base.njk", "_includes/layout.liquid"},
	"astro":    {"src/layouts/Layout.astro", "src/layouts/BaseLayout.astro", "src/layouts/Base.astro"},
}

// fallbackLayouts are tried for every stack after its own list: common
// conventions that hold whatever the stack was detected as (a config saved
// before 0.25 may say stack: vite for a SvelteKit or Remix project).
var fallbackLayouts = []string{
	// PHP
	"partials/header.php",
	"includes/header.php",
	"inc/header.php",
	"templates/header.php",
	"views/partials/header.php",
	"views/includes/header.php",
	"app/views/header.php",
	"resources/views/partials/header.php",
	"public/index.php",
	"index.php",

	// HTML and static
	"index.html",
	"public/index.html",
	"src/index.html",

	// Node and Express
	"views/layout.ejs",
	"views/layout.pug",
	"views/layout.hbs",
	"views/layouts/main.hbs",
	"views/layouts/main.ejs",

	// React, Vue, Svelte, Remix
	"src/App.tsx",
	"src/App.jsx",
	"src/App.js",
	"src/App.vue",
	"src/App.svelte",
	"src/app.html",
	"app/root.tsx",
	"app/root.jsx",
	"src/main.tsx",
	"src/main.jsx",
	"src/main.js",
	"app/layout.tsx",
	"app/layout.jsx",
	"app/layout.js",
	"src/app/layout.tsx",
	"src/app/layout.js",
	"pages/_app.tsx",
	"pages/_app.jsx",
	"pages/_app.js",
	"pages/_document.tsx",
	"pages/_document.jsx",
	"pages/_document.js",

	// Twig (Symfony, Craft)
	"templates/base.twig",
	"templates/_layout.twig",
	"templates/layout.twig",
	"templates/base.html.twig",

	// Blade (Laravel)
	"resources/views/layouts/app.blade.php",
	"resources/views/layout.blade.php",
	"resources/views/layouts/main.blade.php",

	// Rails
	"app/views/layouts/application.html.erb",

	// Django, Flask, Go templates
	"templates/base.html",
	"templates/layout.html",
	"views/base.html",
	"views/layout.html",

	// Static site generators
	"_layouts/default.html",
	"_includes/head.html",
	"layouts/_default/baseof.html",
	"src/layouts/Layout.astro",
	"_includes/layout.njk",
}

// monorepoRoots are the directories whose children are separate apps or
// packages. config.DetectStack looks one level into them, so a layout
// must be looked for there too.
var monorepoRoots = []string{"apps", "packages", "services"}

// findMainLayout returns the project-relative path (slash separated) of
// the file most likely to hold the site's <head>, or "" when none of the
// known locations exists. The stack's own locations are tried at the
// project root, then inside each monorepo app (the stack may have been
// detected from apps/web, where the layout then lives), then the
// conventions shared by every stack at the root.
func findMainLayout(rootDir, stack string) string {
	own := stackLayouts[stack]
	if found := firstExisting(rootDir, "", own); found != "" {
		return found
	}
	for _, mono := range monorepoRoots {
		entries, err := os.ReadDir(filepath.Join(rootDir, mono))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if found := firstExisting(rootDir, mono+"/"+entry.Name(), own); found != "" {
				return found
			}
		}
	}
	return firstExisting(rootDir, "", fallbackLayouts)
}

// firstExisting returns the first of candidates that exists under
// rootDir/prefix, as a slash-separated path relative to rootDir.
func firstExisting(rootDir, prefix string, candidates []string) string {
	for _, candidate := range candidates {
		rel := candidate
		if prefix != "" {
			rel = prefix + "/" + candidate
		}
		if !strings.Contains(rel, "*") {
			if info, err := os.Stat(filepath.Join(rootDir, filepath.FromSlash(rel))); err == nil && !info.IsDir() {
				return rel
			}
			continue
		}
		matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.IsDir() {
				continue
			}
			if relMatch, err := filepath.Rel(rootDir, match); err == nil {
				return filepath.ToSlash(relMatch)
			}
		}
	}
	return ""
}

// detectMainLayout is what init writes to checks.seoMeta.mainLayout.
func detectMainLayout(cwd, stack string) string {
	return findMainLayout(cwd, stack)
}

// canAutoDetectLayout reports whether scan can find a layout for the SEO
// checks without one being configured.
func canAutoDetectLayout(rootDir, stack string) bool {
	return findMainLayout(rootDir, stack) != ""
}
