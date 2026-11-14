package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ImageOptimizationCheck struct{}

func (c ImageOptimizationCheck) ID() string {
	return "image_optimization"
}

func (c ImageOptimizationCheck) Title() string {
	return "Image optimization"
}

func (c ImageOptimizationCheck) Run(ctx Context) (CheckResult, error) {
	largeImages := findLargeImages(ctx.RootDir, 500*1024)

	if len(largeImages) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No large images found",
		}, nil
	}

	maxShow := 5
	var suggestions []string
	for i, img := range largeImages {
		if i >= maxShow {
			suggestions = append(suggestions, fmt.Sprintf("... and %d more", len(largeImages)-maxShow))
			break
		}
		suggestions = append(suggestions, fmt.Sprintf("%s (%s)", img.path, formatSize(img.size)))
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     fmt.Sprintf("Found %d large image(s) over 500KB", len(largeImages)),
		Suggestions: suggestions,
	}, nil
}

type largeImage struct {
	path string
	size int64
}

// imageSourceRoots hold the images a project ships.
var imageSourceRoots = []string{"public", "static", "web", "www", "assets"}

// imageBuildRoots are build output. They repeat what a source root already
// holds (public/hero.png and dist/hero.png are one image), so they are only
// looked at when the project has no source root of its own.
var imageBuildRoots = []string{"dist", "build", "_site", "out"}

// imageSkipDirs are never walked: dependencies, and Craft's published
// asset copies.
var imageSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	"cpresources":  true,
}

// isUploadsDir reports a directory of files uploaded through a CMS: WordPress
// wp-content/uploads, Drupal sites/<site>/files, Laravel storage. Editors put
// those there; they are content, not something the project's build can
// optimize, and they rarely exist on the machine running the scan.
func isUploadsDir(rel string) bool {
	parent, name := pathSplit(rel)
	switch name {
	case "uploads", "storage":
		return true
	case "files":
		grandparent, _ := pathSplit(parent)
		_, sites := pathSplit(grandparent)
		return sites == "sites"
	}
	return false
}

func findLargeImages(rootDir string, threshold int64) []largeImage {
	var images []largeImage

	imageExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".webp": true, ".svg": true, ".bmp": true, ".tiff": true,
	}

	var roots []string
	for _, r := range imageSourceRoots {
		if info, err := os.Stat(filepath.Join(rootDir, r)); err == nil && info.IsDir() {
			roots = append(roots, r)
		}
	}
	if len(roots) == 0 {
		roots = imageBuildRoots
	}

	// What git ignores is generated or local: build output inside a source
	// root, uploads, caches. Outside a repository nothing is known to be
	// ignored and the name rules above do the work.
	git := loadGitStatus(rootDir)

	for _, webRoot := range roots {
		rootPath := filepath.Join(rootDir, webRoot)
		if _, err := os.Stat(rootPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel := filepath.ToSlash(relPath(rootDir, path))

			if d.IsDir() {
				if imageSkipDirs[d.Name()] || isUploadsDir(rel) || (git.inRepo && git.ignoredDirs[rel]) {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if !imageExts[ext] {
				return nil
			}
			if git.inRepo && git.ignored[rel] {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			if info.Size() > threshold {
				images = append(images, largeImage{path: relPath(rootDir, path), size: info.Size()})
			}

			return nil
		})
	}

	return images
}

func formatSize(bytes int64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%dKB", bytes/1024)
}
