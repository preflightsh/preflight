package checks

import (
	"os"
	"path/filepath"
	"strings"
)

type LicenseCheck struct{}

func (c LicenseCheck) ID() string {
	return "license"
}

func (c LicenseCheck) Title() string {
	return "LICENSE file"
}

func (c LicenseCheck) Run(ctx Context) (CheckResult, error) {
	licenseNames := []string{
		"LICENSE",
		"LICENSE.md",
		"LICENSE.txt",
		"LICENCE",
		"LICENCE.md",
		"license",
		"license.md",
		"license.txt",
	}

	// Check current directory and parent directories up to git root or filesystem root
	dirsToCheck := getDirectoriesToCheck(ctx.RootDir)

	for _, dir := range dirsToCheck {
		for _, name := range licenseNames {
			fullPath := filepath.Join(dir, name)
			if content, err := os.ReadFile(fullPath); err == nil {
				contentStr := strings.TrimSpace(string(content))
				if len(contentStr) > 0 {
					// Try to detect license type
					licenseType := detectLicenseType(contentStr)
					message := "LICENSE file found"
					if licenseType != "" {
						message = licenseType + " license found"
					}
					// Show location if not in root dir
					if dir != ctx.RootDir {
						relPath := relPath(ctx.RootDir, fullPath)
						message += " (at " + relPath + ")"
					}
					return CheckResult{
						ID:       c.ID(),
						Title:    c.Title(),
						Severity: SeverityInfo,
						Passed:   true,
						Message:  message,
					}, nil
				}
			}
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "No LICENSE file found",
		Suggestions: []string{
			"Add a LICENSE file to your project",
			"Choose a license at https://choosealicense.com",
		},
	}, nil
}

// getDirectoriesToCheck returns the current directory and parent directories
// up to the git root (if in a git repo) or up to 3 levels up
func getDirectoriesToCheck(rootDir string) []string {
	dirs := []string{rootDir}

	current := rootDir
	maxLevels := 5 // Safety limit

	for i := 0; i < maxLevels; i++ {
		parent := filepath.Dir(current)
		if parent == current {
			// Reached filesystem root
			break
		}

		// Check if we've found a git root (parent has .git)
		gitPath := filepath.Join(parent, ".git")
		if _, err := os.Stat(gitPath); err == nil {
			// Found git root, add it and stop
			dirs = append(dirs, parent)
			break
		}

		// Check if parent itself is a reasonable root (has common project files)
		if hasProjectMarker(parent) {
			dirs = append(dirs, parent)
		}

		current = parent
	}

	return dirs
}

// hasProjectMarker checks if a directory looks like a project root
func hasProjectMarker(dir string) bool {
	markers := []string{
		".git",
		"package.json",
		"go.mod",
		"Cargo.toml",
		"pyproject.toml",
		"Gemfile",
		"composer.json",
		"pom.xml",
		"build.gradle",
	}

	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

func detectLicenseType(content string) string {
	contentLower := strings.ToLower(content)

	if strings.Contains(contentLower, "mit license") ||
		strings.Contains(contentLower, "permission is hereby granted, free of charge") {
		return "MIT"
	}

	if strings.Contains(contentLower, "apache license") &&
		strings.Contains(contentLower, "version 2.0") {
		return "Apache 2.0"
	}

	if strings.Contains(contentLower, "gnu affero general public license") {
		if strings.Contains(contentLower, "version 3") {
			return "AGPL-3.0"
		}
		return "AGPL"
	}

	if strings.Contains(contentLower, "gnu general public license") {
		if strings.Contains(contentLower, "version 3") {
			return "GPL-3.0"
		}
		if strings.Contains(contentLower, "version 2") {
			return "GPL-2.0"
		}
		return "GPL"
	}

	if strings.Contains(contentLower, "bsd") {
		if strings.Contains(contentLower, "3-clause") || strings.Contains(contentLower, "three-clause") {
			return "BSD-3-Clause"
		}
		if strings.Contains(contentLower, "2-clause") || strings.Contains(contentLower, "two-clause") {
			return "BSD-2-Clause"
		}
		return "BSD"
	}

	if strings.Contains(contentLower, "isc license") {
		return "ISC"
	}

	if strings.Contains(contentLower, "mozilla public license") {
		return "MPL-2.0"
	}

	if strings.Contains(contentLower, "unlicense") ||
		strings.Contains(contentLower, "this is free and unencumbered") {
		return "Unlicense"
	}

	if strings.Contains(contentLower, "creative commons") {
		return "Creative Commons"
	}

	if strings.Contains(contentLower, "proprietary") ||
		strings.Contains(contentLower, "all rights reserved") {
		return "Proprietary"
	}

	return ""
}
