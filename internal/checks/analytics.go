package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FathomCheck verifies Fathom Analytics is properly set up
type FathomCheck struct{}

func (c FathomCheck) ID() string {
	return "fathom"
}

func (c FathomCheck) Title() string {
	return "Fathom Analytics"
}

func (c FathomCheck) Run(ctx Context) (CheckResult, error) {
	fathomService, declared := ctx.Config.Services["fathom"]
	if !declared || !fathomService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fathom not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`usefathom\.com`),
		regexp.MustCompile(`cdn\.usefathom\.com`),
		regexp.MustCompile(`fathom\.trackPageview`),
		regexp.MustCompile(`data-site=`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fathom Analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Fathom is declared but script not found in templates",
		Suggestions: []string{
			"Add the Fathom script tag to your main layout",
			"Example: <script src=\"https://cdn.usefathom.com/script.js\" data-site=\"XXXXX\" defer></script>",
		},
	}, nil
}

// GoogleAnalyticsCheck verifies Google Analytics is properly set up
type GoogleAnalyticsCheck struct{}

func (c GoogleAnalyticsCheck) ID() string {
	return "googleAnalytics"
}

func (c GoogleAnalyticsCheck) Title() string {
	return "Google Analytics"
}

func (c GoogleAnalyticsCheck) Run(ctx Context) (CheckResult, error) {
	gaService, declared := ctx.Config.Services["google_analytics"]
	if !declared || !gaService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Google Analytics not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`googletagmanager\.com`),
		regexp.MustCompile(`google-analytics\.com`),
		regexp.MustCompile(`gtag\(`),
		regexp.MustCompile(`ga\(`),
		regexp.MustCompile(`GoogleAnalyticsObject`),
		regexp.MustCompile(`G-[A-Z0-9]+`), // GA4 measurement ID
		regexp.MustCompile(`UA-[0-9]+-[0-9]+`), // Universal Analytics
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Google Analytics configuration found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Google Analytics is declared but not found in templates",
		Suggestions: []string{
			"Add Google Analytics/GTM script to your main layout",
			"Consider using GA4 with gtag.js for modern tracking",
		},
	}, nil
}

// RedisCheck verifies Redis connection is configured
type RedisCheck struct{}

func (c RedisCheck) ID() string {
	return "redis"
}

func (c RedisCheck) Title() string {
	return "Redis"
}

func (c RedisCheck) Run(ctx Context) (CheckResult, error) {
	redisService, declared := ctx.Config.Services["redis"]
	if !declared || !redisService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Redis not declared, skipping",
		}, nil
	}

	// Check for Redis configuration in common locations
	configPatterns := []*regexp.Regexp{
		regexp.MustCompile(`redis://`),
		regexp.MustCompile(`Redis\.new`),
		regexp.MustCompile(`Redis\.current`),
		regexp.MustCompile(`createClient.*redis`),
		regexp.MustCompile(`new Redis\(`),
		regexp.MustCompile(`ioredis`),
		regexp.MustCompile(`@upstash/redis`),
		regexp.MustCompile(`Upstash`),
	}

	configFiles := []string{
		"config/redis.yml",
		"config/cable.yml",
		"config/sidekiq.yml",
		"config/initializers/redis.rb",
		"config/initializers/sidekiq.rb",
		"src/config/redis.ts",
		"src/lib/redis.ts",
		"src/redis.ts",
		"lib/redis.js",
		"lib/redis.ts",
	}

	// Also check monorepo structures
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
			// Add monorepo paths
			configFiles = append(configFiles,
				filepath.Join(monoRoot, entry.Name(), "src", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "src", "lib", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "src", "config", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "lib", "redis.ts"),
				filepath.Join(monoRoot, entry.Name(), "lib", "redis.js"),
			)
		}
	}

	for _, file := range configFiles {
		path := filepath.Join(ctx.RootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, pattern := range configPatterns {
			if pattern.Match(content) {
				return CheckResult{
					ID:       c.ID(),
					Title:    c.Title(),
					Severity: SeverityInfo,
					Passed:   true,
					Message:  "Redis configuration found",
				}, nil
			}
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Redis is declared but configuration not found",
		Suggestions: []string{
			"Ensure REDIS_URL is set in your environment",
			"Add Redis initializer or configuration file",
		},
	}, nil
}

// SidekiqCheck verifies Sidekiq is configured (Rails)
type SidekiqCheck struct{}

func (c SidekiqCheck) ID() string {
	return "sidekiq"
}

func (c SidekiqCheck) Title() string {
	return "Sidekiq"
}

func (c SidekiqCheck) Run(ctx Context) (CheckResult, error) {
	sidekiqService, declared := ctx.Config.Services["sidekiq"]
	if !declared || !sidekiqService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Sidekiq not declared, skipping",
		}, nil
	}

	configFiles := []string{
		"config/sidekiq.yml",
		"config/initializers/sidekiq.rb",
	}

	for _, file := range configFiles {
		path := filepath.Join(ctx.RootDir, file)
		if _, err := os.Stat(path); err == nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Sidekiq configuration found",
			}, nil
		}
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Sidekiq is declared but configuration not found",
		Suggestions: []string{
			"Create config/sidekiq.yml with queue configuration",
			"Add Sidekiq initializer for Redis connection",
		},
	}, nil
}

// Helper function to search for patterns in layout files
func searchForPatterns(rootDir, stack string, patterns []*regexp.Regexp) bool {
	layoutFiles := getLayoutFilesForStack(stack)

	for _, file := range layoutFiles {
		path := filepath.Join(rootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, pattern := range patterns {
			if pattern.Match(content) {
				return true
			}
		}
	}

	// Also search in src/ and app/ directories
	searchDirs := []string{"src", "app", "components", "pages"}
	extensions := []string{".tsx", ".jsx", ".js", ".ts", ".erb", ".html"}

	for _, dir := range searchDirs {
		dirPath := filepath.Join(rootDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		found := false
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || found {
				return nil
			}

			if strings.Contains(path, "node_modules") {
				return filepath.SkipDir
			}

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

		if found {
			return true
		}
	}

	return false
}

func getLayoutFilesForStack(stack string) []string {
	layouts := map[string][]string{
		"rails":   {"app/views/layouts/application.html.erb", "app/views/layouts/application.html.haml"},
		"next":    {"app/layout.tsx", "app/layout.js", "pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js"},
		"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs"},
		"laravel": {"resources/views/layouts/app.blade.php"},
		"static":  {"index.html", "public/index.html"},
	}

	if files, ok := layouts[stack]; ok {
		return files
	}
	return []string{"index.html", "public/index.html"}
}
