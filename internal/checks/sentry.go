package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SentryCheck struct{}

func (c SentryCheck) ID() string {
	return "sentry"
}

func (c SentryCheck) Title() string {
	return "Sentry"
}

func (c SentryCheck) Run(ctx Context) (CheckResult, error) {
	// Check if Sentry is declared
	sentryService, declared := ctx.Config.Services["sentry"]
	if !declared || !sentryService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Sentry not declared, skipping",
		}, nil
	}

	// Patterns to search for Sentry initialization
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Sentry\.init`),
		regexp.MustCompile(`sentry\.init`),
		regexp.MustCompile(`@sentry/`),
		regexp.MustCompile(`require\s*\(\s*['"]@sentry`),
		regexp.MustCompile(`import.*from\s+['"]@sentry`),
		regexp.MustCompile(`Sentry::init`),           // Ruby
		regexp.MustCompile(`sentry_sdk\.init`),       // Python
		regexp.MustCompile(`\bsentry-laravel\b`),     // Laravel
	}

	// Check for Next.js Sentry config files at root first
	nextjsSentryFiles := []string{
		"sentry.client.config.ts",
		"sentry.client.config.js",
		"sentry.server.config.ts",
		"sentry.server.config.js",
		"sentry.edge.config.ts",
		"sentry.edge.config.js",
	}

	for _, file := range nextjsSentryFiles {
		path := filepath.Join(ctx.RootDir, file)
		if _, err := os.Stat(path); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sentry initialization found",
			}, nil
		}
	}

	// Check monorepo structures for Sentry config
	monorepoRoots := []string{"apps", "packages", "services"}
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(ctx.RootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, file := range nextjsSentryFiles {
				path := filepath.Join(monoDir, entry.Name(), file)
				if _, err := os.Stat(path); err == nil {
					return CheckResult{
						ID:       c.ID(),
						Title:    c.Title(),
						Severity: SeverityInfo,
						Passed:   true,
						Message:  "Sentry initialization found",
					}, nil
				}
			}
		}
	}

	// Directories to search
	searchDirs := []string{
		"src",
		"app",
		"lib",
		"config",
		"config/initializers",
	}

	// Also add monorepo src directories
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(ctx.RootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			searchDirs = append(searchDirs,
				filepath.Join(monoRoot, entry.Name(), "src"),
				filepath.Join(monoRoot, entry.Name(), "app"),
				filepath.Join(monoRoot, entry.Name(), "lib"),
			)
		}
	}

	// File extensions to check
	extensions := []string{".js", ".ts", ".tsx", ".jsx", ".rb", ".py", ".php"}

	found := false

	for _, dir := range searchDirs {
		dirPath := filepath.Join(ctx.RootDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Skip node_modules and vendor
			if strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
				return nil
			}

			// Check extension
			ext := filepath.Ext(path)
			validExt := false
			for _, e := range extensions {
				if ext == e {
					validExt = true
					break
				}
			}
			if !validExt {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			for _, pattern := range patterns {
				if pattern.Match(content) {
					found = true
					return filepath.SkipAll
				}
			}

			return nil
		})

		if err != nil {
			continue
		}

		if found {
			break
		}
	}

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Sentry initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Sentry is declared but initialization not found",
		Suggestions: []string{
			"Add Sentry.init() to your application entry point",
			"Check Sentry documentation for your framework",
		},
	}, nil
}
