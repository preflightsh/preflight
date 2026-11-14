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
	// The project directory first, then its parents up to the root of the
	// repository it belongs to.
	for _, dir := range getDirectoriesToCheck(ctx.RootDir) {
		for _, name := range licenseFilesIn(dir) {
			fullPath := filepath.Join(dir, name)
			content, err := readSourceFile(fullPath)
			if err != nil {
				continue
			}
			contentStr := strings.TrimSpace(string(content))
			if len(contentStr) == 0 {
				continue
			}
			// Try to detect license type
			licenseType := detectLicenseType(contentStr)
			message := "LICENSE file found"
			if licenseType != "" {
				message = licenseType + " license found"
			}
			// Show location if not in root dir
			if dir != ctx.RootDir {
				message += " (at " + relPath(ctx.RootDir, fullPath) + ")"
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

// licenseStems are the names a license file goes by, before any extension
// or suffix: LICENSE, LICENCE.md, COPYING.LESSER, LICENSE-MIT, UNLICENSE.
var licenseStems = []string{"license", "licence", "copying", "unlicense"}

// isLicenseFileName reports whether a file name is one of the conventional
// license names, in any letter case.
func isLicenseFileName(name string) bool {
	lower := strings.ToLower(name)
	for _, stem := range licenseStems {
		rest, ok := strings.CutPrefix(lower, stem)
		if ok && (rest == "" || rest[0] == '.' || rest[0] == '-') {
			return true
		}
	}
	return false
}

// licenseFilesIn lists the license files in dir, in directory order (which
// is sorted by name, so LICENSE comes before LICENSE-APACHE).
func licenseFilesIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isLicenseFileName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names
}

// getDirectoriesToCheck returns the project directory and, when it is a
// subdirectory of a repository (an app in a monorepo), its parents up to the
// repository root. A project that is its own repository, or is in no
// repository at all, is checked on its own: a LICENSE in some unrelated
// parent directory says nothing about it.
func getDirectoriesToCheck(rootDir string) []string {
	dirs := []string{rootDir}
	if isRepoRoot(rootDir) {
		return dirs
	}

	var parents []string
	current := rootDir
	for i := 0; i < 5; i++ {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		parents = append(parents, parent)
		if isRepoRoot(parent) {
			return append(dirs, parents...)
		}
		current = parent
	}
	return dirs
}

// isRepoRoot reports whether dir holds a .git entry: a directory, or the
// file a worktree or submodule uses.
func isRepoRoot(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
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

	if strings.Contains(contentLower, "gnu lesser general public license") {
		return "LGPL"
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
