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

func findLargeImages(rootDir string, threshold int64) []largeImage {
	var images []largeImage

	webRoots := []string{"public", "static", "web", "www", "dist", "build", "_site", "out", "assets"}
	imageExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".webp": true, ".svg": true, ".bmp": true, ".tiff": true,
	}

	skipDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		"cpresources":  true,
	}

	for _, webRoot := range webRoots {
		rootPath := filepath.Join(rootDir, webRoot)
		if _, err := os.Stat(rootPath); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if !imageExts[ext] {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			if info.Size() > threshold {
				relPath := relPath(rootDir, path)
				images = append(images, largeImage{path: relPath, size: info.Size()})
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
