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
	return "Sentry is initialized"
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

	// Directories to search
	searchDirs := []string{
		"src",
		"app",
		"lib",
		"config",
		"config/initializers",
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
