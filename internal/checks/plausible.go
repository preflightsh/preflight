package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type PlausibleCheck struct{}

func (c PlausibleCheck) ID() string {
	return "plausible"
}

func (c PlausibleCheck) Title() string {
	return "Plausible Analytics"
}

func (c PlausibleCheck) Run(ctx Context) (CheckResult, error) {
	// Check if Plausible is declared
	plausibleService, declared := ctx.Config.Services["plausible"]
	if !declared || !plausibleService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Plausible not declared, skipping",
		}, nil
	}

	// Patterns to search for Plausible script
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`plausible\.io/js/`),
		regexp.MustCompile(`data-domain=`),
		regexp.MustCompile(`plausible-analytics`),
		regexp.MustCompile(`@plausible/tracker`),
	}

	// Templates and layouts to check based on stack
	filesToCheck := getLayoutFiles(ctx.Config.Stack)

	// Also check common locations
	filesToCheck = append(filesToCheck,
		"index.html",
		"public/index.html",
		"src/index.html",
	)

	found := false
	var checkedFiles []string

	for _, file := range filesToCheck {
		path := filepath.Join(ctx.RootDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		checkedFiles = append(checkedFiles, file)

		for _, pattern := range patterns {
			if pattern.Match(content) {
				found = true
				break
			}
		}

		if found {
			break
		}
	}

	// Also search in src/ and app/ directories for React/Next apps
	if !found {
		searchDirs := []string{"src", "app", "components"}
		extensions := []string{".tsx", ".jsx", ".js", ".ts"}

		for _, dir := range searchDirs {
			dirPath := filepath.Join(ctx.RootDir, dir)
			if _, err := os.Stat(dirPath); os.IsNotExist(err) {
				continue
			}

			_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
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
				break
			}
		}
	}

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Plausible analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Plausible is declared but script not found in templates",
		Suggestions: []string{
			"Add the Plausible script tag to your main layout",
			"Example: <script defer data-domain=\"yourdomain.com\" src=\"https://plausible.io/js/script.js\"></script>",
		},
	}, nil
}

func getLayoutFiles(stack string) []string {
	layouts := map[string][]string{
		"rails":   {"app/views/layouts/application.html.erb", "app/views/layouts/application.html.haml"},
		"next":    {"app/layout.tsx", "app/layout.js", "pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js"},
		"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs", "views/layouts/main.handlebars"},
		"laravel": {"resources/views/layouts/app.blade.php", "resources/views/app.blade.php"},
		"static":  {"index.html"},
	}

	if files, ok := layouts[stack]; ok {
		return files
	}
	return []string{}
}
