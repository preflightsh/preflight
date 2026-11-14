package checks

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/preflightsh/preflight/internal/gitutil"
)

// trackedSet is what git tracks under a scanned root: the files, and every
// directory that holds one. Paths are slash separated and relative to the
// root.
type trackedSet struct {
	files map[string]bool
	dirs  map[string]bool
}

// loadTrackedFiles lists the files git tracks under root. It returns nil
// outside a work tree, when git is missing, or when git fails or takes too
// long, and callers then fall back to directory names alone.
//
// Only the index is read (`git ls-files`). The untracked and ignored listings
// need .gitignore contents, which in a partial clone makes git fetch.
func loadTrackedFiles(ctx context.Context, root string) *trackedSet {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := gitutil.Command(ctx, root, "ls-files", "-z").Output()
	if err != nil {
		return nil
	}
	t := &trackedSet{files: map[string]bool{}, dirs: map[string]bool{}}
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" {
			continue
		}
		t.files[f] = true
		for d := path.Dir(f); d != "." && !t.dirs[d]; d = path.Dir(d) {
			t.dirs[d] = true
		}
	}
	return t
}

// dependencyDirs hold dependency trees, build output, and tool state at any
// depth. Nothing in them is the project's own source.
var dependencyDirs = map[string]bool{
	"node_modules":     true,
	"bower_components": true,
	"vendor":           true,
	".git":             true,
	"dist":             true,
	"build":            true,
	".next":            true,
	".nuxt":            true,
	".output":          true,
	".turbo":           true,
	".vercel":          true,
	".netlify":         true,
	".cache":           true,
	"coverage":         true,
	"__pycache__":      true,
	"_site":            true,
	"cpresources":      true,
	"_generated":       true,
	".convex":          true,
	// Agent tooling: vendored skills, and full repo checkouts under
	// .claude/worktrees.
	".claude": true,
	".agents": true,
}

// outputDirs are named for what a framework writes at run time or serves as
// is: logs, caches, uploads, compiled assets. The same names are also route
// segments (app/logs/page.tsx) and hand-written web roots (public/js/main.js),
// so the name alone does not decide. See walkPolicy.skipDir.
var outputDirs = map[string]bool{
	"public":  true,
	"static":  true,
	"storage": true,
	"log":     true,
	"logs":    true,
	"tmp":     true,
	"out":     true,
	"cache":   true,
}

// webRootDirs are served directories. An assets directory under one is
// compiled output; anywhere else (assets/js/app.js in Phoenix, Symfony, and
// Hugo, app/assets in Rails, src/assets in Vite) it is source.
var webRootDirs = map[string]bool{
	"public": true, "web": true, "static": true, "www": true,
	"htdocs": true, "public_html": true, "docroot": true,
}

// monorepoRoots are the directories whose children are projects of their own.
var monorepoRoots = map[string]bool{"apps": true, "packages": true, "services": true}

// testDirs hold tests and their fixtures, which print and break on purpose.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true,
	"__mocks__": true, "cypress": true, "e2e": true, "fixtures": true, "testdata": true,
}

// walkPolicy decides which directories and files a source walker reads.
type walkPolicy struct {
	root    string
	tracked *trackedSet
	// shipped narrows the walk to code that ships with the site: it also
	// leaves out tests, root-level scripts and bin, and third-party CMS
	// extensions. The debug-statement scan wants that; the service search
	// does not, since a plugin's directory is often the only sign of an
	// integration.
	shipped bool
}

func (p walkPolicy) rel(full string) string {
	r, err := filepath.Rel(p.root, full)
	if err != nil {
		return filepath.ToSlash(full)
	}
	return filepath.ToSlash(r)
}

// isOutputDir reports whether the directory at rel is one whose name marks
// build output or runtime data.
func isOutputDir(rel string) bool {
	name := path.Base(rel)
	if outputDirs[name] {
		return true
	}
	return name == "assets" && webRootDirs[path.Base(path.Dir(rel))]
}

// atProjectRoot reports whether rel is a top-level directory of the scanned
// project or of a project inside a monorepo (apps/web/public).
func atProjectRoot(rel string) bool {
	parts := strings.Split(rel, "/")
	return len(parts) == 1 || (len(parts) == 3 && monorepoRoots[parts[0]])
}

// skipDir reports whether the walk should stay out of the directory at full.
func (p walkPolicy) skipDir(full string) bool {
	rel := p.rel(full)
	name := path.Base(rel)
	if dependencyDirs[name] || toolchainDirs[name] || isCMSCoreDir(full, rel) {
		return true
	}
	if p.shipped {
		if testDirs[name] || isCMSExtensionDir(rel) {
			return true
		}
		// Build and maintenance scripts log to the terminal by design. Only
		// at the top: src/scripts and assets/scripts are client code.
		if (name == "scripts" || name == "bin") && atProjectRoot(rel) {
			return true
		}
	}
	if !isOutputDir(rel) {
		return false
	}
	if p.tracked != nil {
		// Inside a repository git answers the question: output and runtime
		// data are ignored, source is tracked.
		return !p.tracked.dirs[rel]
	}
	if p.shipped {
		return atProjectRoot(rel) || name == "public" || name == "static" || name == "assets"
	}
	// The service search still reads an untracked web root: a script tag in
	// public/index.html is the integration.
	return atProjectRoot(rel) && name != "public" && name != "static" && name != "out" && name != "assets"
}

// skipFile reports whether a file is build output or runtime data: inside a
// repository, an untracked file under an output directory.
func (p walkPolicy) skipFile(full string) bool {
	if p.tracked == nil {
		return false
	}
	rel := p.rel(full)
	if p.tracked.files[rel] {
		return false
	}
	for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
		if isOutputDir(dir) {
			return true
		}
	}
	return false
}

// isCMSCoreDir reports whether the directory is a CMS's own code: WordPress
// core, or Drupal core (wherever the web root is, core/lib/Drupal.php marks
// it).
func isCMSCoreDir(full, rel string) bool {
	switch path.Base(rel) {
	case "wp-admin", "wp-includes":
		return true
	case "core":
		if parent := path.Base(path.Dir(rel)); parent == "web" || parent == "docroot" {
			return true
		}
		_, err := os.Stat(filepath.Join(full, "lib", "Drupal.php"))
		return err == nil
	}
	return false
}

// isCMSExtensionDir reports whether the directory holds third-party CMS
// extensions and uploads: WordPress plugins, Drupal contrib modules, themes,
// profiles, and libraries.
func isCMSExtensionDir(rel string) bool {
	name, parent := path.Base(rel), path.Base(path.Dir(rel))
	switch {
	case parent == "wp-content" && (name == "plugins" || name == "uploads" || name == "upgrade" || name == "cache"):
		return true
	case name == "contrib" && (parent == "modules" || parent == "themes" || parent == "profiles"):
		return true
	case name == "libraries" && (parent == "web" || parent == "docroot"):
		return true
	}
	return false
}

// looksBundled reports whether JavaScript content is a compiled bundle: a
// bundler or minifier writes lines no person does.
func looksBundled(content []byte) bool {
	const maxLine = 2000
	run := 0
	for _, c := range content {
		if c == '\n' {
			run = 0
			continue
		}
		run++
		if run > maxLine {
			return true
		}
	}
	return false
}
