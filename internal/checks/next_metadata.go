package checks

import (
	"os"
	"path/filepath"
	"strings"
)

// nextRouteFileExts are the extensions Next.js accepts for layout and page files.
var nextRouteFileExts = []string{".tsx", ".ts", ".jsx", ".js"}

// nextRootRouteSources returns the comment-stripped contents of the App Router
// files whose Metadata API export applies to the site's root route, apart from
// the root layout itself (the caller has that): the root page next to it, and
// the layout and page of each top-level route group, app/(marketing)/layout.tsx.
// A metadata export on some nested page only covers that page, so it is not
// evidence the site as a whole has its SEO or social tags.
func nextRootRouteSources(appDir string) []string {
	dirs := []string{appDir}
	if entries, err := os.ReadDir(appDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "(") && strings.HasSuffix(e.Name(), ")") {
				dirs = append(dirs, filepath.Join(appDir, e.Name()))
			}
		}
	}

	var sources []string
	for i, dir := range dirs {
		names := []string{"page"}
		if i > 0 {
			names = append(names, "layout")
		}
		for _, name := range names {
			for _, ext := range nextRouteFileExts {
				content, err := readSourceFile(filepath.Join(dir, name+ext))
				if err != nil {
					continue
				}
				sources = append(sources, stripComments(string(content)))
			}
		}
	}
	return sources
}

// anyNextSource reports whether has finds the named tag in any of sources.
func anyNextSource(sources []string, name string, has func(content, name string) bool) bool {
	for _, s := range sources {
		if has(s, name) {
			return true
		}
	}
	return false
}
