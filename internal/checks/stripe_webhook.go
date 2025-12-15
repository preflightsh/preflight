package checks

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type StripeWebhookCheck struct{}

func (c StripeWebhookCheck) ID() string {
	return "stripe"
}

func (c StripeWebhookCheck) Title() string {
	return "Stripe"
}

func (c StripeWebhookCheck) Run(ctx Context) (CheckResult, error) {
	// Check if Stripe is declared
	stripeService, declared := ctx.Config.Services["stripe"]
	if !declared || !stripeService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Stripe not declared, skipping",
		}, nil
	}

	var issues []string
	var suggestions []string

	// Check for required env vars in .env.example or .env
	envFiles := []string{".env.example", ".env", ".env.local"}
	requiredKeys := []string{"STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY"}
	webhookKey := "STRIPE_WEBHOOK_SECRET"

	foundKeys := make(map[string]bool)
	for _, envFile := range envFiles {
		path := filepath.Join(ctx.RootDir, envFile)
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.ToUpper(scanner.Text())
			for _, key := range append(requiredKeys, webhookKey) {
				if strings.HasPrefix(line, key) {
					foundKeys[key] = true
				}
			}
		}
	}

	// Check required keys
	for _, key := range requiredKeys {
		if !foundKeys[key] {
			issues = append(issues, key+" not found in env files")
			suggestions = append(suggestions, "Add "+key+" to .env.example")
		}
	}

	// Check webhook secret (warn but don't fail)
	hasWebhookSecret := foundKeys[webhookKey]

	// Check for Stripe initialization in code
	initPatterns := []*regexp.Regexp{
		regexp.MustCompile(`Stripe\.api_key`),              // Ruby
		regexp.MustCompile(`stripe\.Key`),                  // Go
		regexp.MustCompile(`new Stripe\(`),                 // Node
		regexp.MustCompile(`Stripe\(`),                     // Node alt
		regexp.MustCompile(`stripe\.setApiKey`),            // Node alt
		regexp.MustCompile(`STRIPE_SECRET_KEY`),            // Generic env usage
		regexp.MustCompile(`stripe/stripe-php`),            // PHP
		regexp.MustCompile(`gem ['"]stripe['"]`),           // Ruby Gemfile
		regexp.MustCompile(`"stripe":`),                    // package.json
	}

	initFound := false
	searchDirs := []string{"config", "config/initializers", "src", "app", "lib"}

	for _, dir := range searchDirs {
		dirPath := filepath.Join(ctx.RootDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || initFound {
				return nil
			}

			if strings.Contains(path, "node_modules") || strings.Contains(path, "vendor") {
				return filepath.SkipDir
			}

			ext := filepath.Ext(path)
			if ext != ".rb" && ext != ".js" && ext != ".ts" && ext != ".go" && ext != ".php" {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			for _, pattern := range initPatterns {
				if pattern.Match(content) {
					initFound = true
					return filepath.SkipAll
				}
			}

			return nil
		})

		if initFound {
			break
		}
	}

	// Also check Gemfile and package.json
	for _, depFile := range []string{"Gemfile", "Gemfile.lock", "package.json"} {
		path := filepath.Join(ctx.RootDir, depFile)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, pattern := range initPatterns {
			if pattern.Match(content) {
				initFound = true
				break
			}
		}
	}

	if !initFound {
		issues = append(issues, "Stripe initialization not found")
		suggestions = append(suggestions, "Ensure Stripe is initialized in your application")
	}

	// Build result
	if len(issues) == 0 {
		message := "Stripe keys configured"
		if hasWebhookSecret {
			message += ", webhook secret present"
		} else {
			message += " (webhook secret not found - needed for webhooks)"
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  message,
		}, nil
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     strings.Join(issues, "; "),
		Suggestions: suggestions,
	}, nil
}
