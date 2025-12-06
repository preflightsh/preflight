package config

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DetectStack determines the project stack based on files present
func DetectStack(rootDir string) string {
	// Check for Rails
	if fileExists(rootDir, "Gemfile") && fileExists(rootDir, "config/routes.rb") {
		return "rails"
	}

	// Check for Next.js
	if fileExists(rootDir, "next.config.js") || fileExists(rootDir, "next.config.mjs") || fileExists(rootDir, "next.config.ts") {
		return "next"
	}

	// Check for Laravel
	if fileExists(rootDir, "artisan") && fileExists(rootDir, "composer.json") {
		return "laravel"
	}

	// Check for Node.js
	if fileExists(rootDir, "package.json") {
		return "node"
	}

	// Check for static site
	if fileExists(rootDir, "index.html") {
		return "static"
	}

	return "unknown"
}

// DetectServices scans the project for known service integrations
func DetectServices(rootDir string) map[string]bool {
	services := map[string]bool{
		"stripe":    false,
		"sentry":    false,
		"postmark":  false,
		"plausible": false,
	}

	// Check package.json
	if pkgJSON, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
		content := string(pkgJSON)
		if strings.Contains(content, "stripe") {
			services["stripe"] = true
		}
		if strings.Contains(content, "@sentry") || strings.Contains(content, "sentry") {
			services["sentry"] = true
		}
		if strings.Contains(content, "postmark") {
			services["postmark"] = true
		}
	}

	// Check Gemfile
	if gemfile, err := os.ReadFile(filepath.Join(rootDir, "Gemfile")); err == nil {
		content := string(gemfile)
		if strings.Contains(content, "stripe") {
			services["stripe"] = true
		}
		if strings.Contains(content, "sentry") {
			services["sentry"] = true
		}
		if strings.Contains(content, "postmark") {
			services["postmark"] = true
		}
	}

	// Check composer.json for Laravel
	if composer, err := os.ReadFile(filepath.Join(rootDir, "composer.json")); err == nil {
		content := string(composer)
		if strings.Contains(content, "stripe") {
			services["stripe"] = true
		}
		if strings.Contains(content, "sentry") {
			services["sentry"] = true
		}
		if strings.Contains(content, "postmark") {
			services["postmark"] = true
		}
	}

	// Check for env keys
	services = detectServicesFromEnv(rootDir, services)

	// Check for Plausible script in HTML files
	if containsPlausibleScript(rootDir) {
		services["plausible"] = true
	}

	return services
}

func detectServicesFromEnv(rootDir string, services map[string]bool) map[string]bool {
	envFiles := []string{".env", ".env.example", ".env.local"}

	envPatterns := map[string][]string{
		"stripe":    {"STRIPE_", "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY"},
		"sentry":    {"SENTRY_DSN", "SENTRY_"},
		"postmark":  {"POSTMARK_", "POSTMARK_API_TOKEN"},
		"plausible": {"PLAUSIBLE_", "NEXT_PUBLIC_PLAUSIBLE"},
	}

	for _, envFile := range envFiles {
		path := filepath.Join(rootDir, envFile)
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			for service, patterns := range envPatterns {
				for _, pattern := range patterns {
					if strings.HasPrefix(line, pattern) {
						services[service] = true
					}
				}
			}
		}
	}

	return services
}

func containsPlausibleScript(rootDir string) bool {
	plausiblePattern := regexp.MustCompile(`plausible\.io/js/`)

	htmlFiles := []string{
		"index.html",
		"public/index.html",
		"app/views/layouts/application.html.erb",
		"resources/views/layouts/app.blade.php",
	}

	for _, htmlFile := range htmlFiles {
		path := filepath.Join(rootDir, htmlFile)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if plausiblePattern.Match(content) {
			return true
		}
	}

	return false
}

func fileExists(rootDir, relativePath string) bool {
	path := filepath.Join(rootDir, relativePath)
	_, err := os.Stat(path)
	return err == nil
}
