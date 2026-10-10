package checks

import (
	"os"
	"path/filepath"
	"regexp"
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

	// Check for Next.js Sentry config files at root first
	nextjsSentryFiles := []string{
		"sentry.client.config.ts",
		"sentry.client.config.js",
		"sentry.server.config.ts",
		"sentry.server.config.js",
		"sentry.edge.config.ts",
		"sentry.edge.config.js",
	}

	found := false
	for _, file := range nextjsSentryFiles {
		if _, err := os.Stat(filepath.Join(ctx.RootDir, file)); err == nil {
			found = true
		}
	}

	// Check monorepo structures for Sentry config
	for _, monoRoot := range []string{"apps", "packages", "services"} {
		entries, err := os.ReadDir(filepath.Join(ctx.RootDir, monoRoot))
		if err != nil || found {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, file := range nextjsSentryFiles {
				if _, err := os.Stat(filepath.Join(ctx.RootDir, monoRoot, entry.Name(), file)); err == nil {
					found = true
				}
			}
		}
	}

	found = found || sentrySDKFound(ctx.RootDir)

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

// sentryDependencyPatterns match a Sentry SDK declared in a package manifest.
var sentryDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"@sentry/[\w-]+"\s*:`),                 // package.json
	regexp.MustCompile(`github\.com/getsentry/sentry-go`),      // go.mod
	regexp.MustCompile(`sentry/sentry(?:-laravel|-symfony)?"`), // composer.json
	regexp.MustCompile(`gem ['"]sentry-(?:ruby|rails)['"]`),    // Gemfile
	regexp.MustCompile(`(?i)\bsentry-sdk\b`),                   // requirements.txt, pyproject, Pipfile
}

// sentryCodePatterns match Sentry being initialized in source. Case is
// ignored so Go's sentry.Init and Python's sentry_sdk.init both count.
var sentryCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsentry(?:_sdk)?(?:\.|::)init\b`),
	regexp.MustCompile(`require\s*\(\s*['"]@sentry`),
	regexp.MustCompile(`import.*from\s+['"]@sentry`),
	regexp.MustCompile(`\bsentry-laravel\b`),
}

// sentrySDKFound reports whether a Sentry SDK is a declared dependency or is
// initialized anywhere in the project's source, comments excluded.
func sentrySDKFound(rootDir string) bool {
	for _, name := range dependencyManifests {
		content, err := readSourceFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}
		deps := stripComments(string(content))
		for _, p := range sentryDependencyPatterns {
			if p.MatchString(deps) {
				return true
			}
		}
	}
	return walkSourceFiles(rootDir, func(path string, content []byte) bool {
		code := stripCodeComments(string(content))
		if ext := filepath.Ext(path); ext == ".rb" || ext == ".py" {
			code = stripComments(code)
		}
		for _, p := range sentryCodePatterns {
			if p.MatchString(code) {
				return true
			}
		}
		return false
	})
}
