package cmd

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/preflightsh/preflight/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize preflight configuration for your project",
	Long: `Initialize preflight by detecting your stack and services,
then generating a preflight.yml configuration file.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	CheckForUpdates()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("🚀 Initializing Preflight...")
	fmt.Println()

	// Get current directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Detect stack
	fmt.Print("Detecting stack... ")
	stack := config.DetectStack(cwd)
	stackDisplay := formatStackName(stack)
	if version := detectStackVersion(cwd, stack); version != "" {
		stackDisplay += " " + version
	}
	fmt.Printf("detected: %s\n", stackDisplay)

	// Detect services
	fmt.Println("Detecting services...")
	services := config.DetectServices(cwd)

	// Collect and sort detected services
	var detectedServices []string
	for name, detected := range services {
		if detected {
			detectedServices = append(detectedServices, name)
		}
	}
	sort.Strings(detectedServices)

	for _, name := range detectedServices {
		fmt.Printf("  ✓ %s detected\n", formatServiceName(name))
	}
	fmt.Println()

	// Get project name
	projectName := promptWithDefault(reader, "Project name", getDefaultProjectName(cwd))

	// Get URLs
	fmt.Println()
	stagingURL := normalizeURL(promptOptional(reader, "Staging URL (optional)"))
	productionURL := normalizeURL(promptOptional(reader, "Production URL (optional)"))

	// Confirm services
	fmt.Println()
	fmt.Println("Confirm detected services (y/n for each):")
	confirmedServices := make(map[string]config.ServiceConfig)
	for _, name := range detectedServices {
		confirm := promptYesNo(reader, fmt.Sprintf("  Use %s?", formatServiceName(name)), true)
		if confirm {
			confirmedServices[name] = config.ServiceConfig{Declared: true}
		}
	}

	// Ask about additional services not detected
	fmt.Println()
	fmt.Println("Any other services to check for?")
	fmt.Println("  1. Skip (use only detected services)")
	fmt.Println("  2. Go through full list (recommended for first setup)")
	choice := promptWithDefault(reader, "  Choose", "1")
	if choice == "2" {
		fmt.Println()
		for _, svc := range config.AllServices {
			if _, exists := confirmedServices[svc]; !exists {
				if promptYesNo(reader, fmt.Sprintf("  Use %s?", formatServiceName(svc)), false) {
					confirmedServices[svc] = config.ServiceConfig{Declared: true}
				}
			}
		}
	}

	// Ask about license file
	fmt.Println()
	hasLicense := promptYesNo(reader, "Does this project have a LICENSE file (e.g., MIT, Apache, GPL)?", false)

	// Ask about ads
	hasAds := promptYesNo(reader, "Does this site serve ads or advertisements?", false)

	// Ask about email authentication
	checkEmailAuth := promptYesNo(reader, "Check email deliverability on prod (SPF/DMARC records)?", false)

	// Ask about humans.txt
	checkHumansTxt := promptYesNo(reader, "Got a humans.txt crediting the team?", false)

	// Handle IndexNow - user already confirmed/declined in services section
	var indexNowKey string
	indexNowConfirmed := confirmedServices["indexnow"].Declared

	if indexNowConfirmed {
		// Try to extract key from .env files
		indexNowKey = detectIndexNowKey(cwd)
		if indexNowKey != "" {
			fmt.Printf("IndexNow key found: %s\n", indexNowKey)
		} else {
			fmt.Println("IndexNow enabled but no key found in .env files or web root")
			fmt.Println("  1. Paste existing key")
			fmt.Println("  2. Generate new key")
			choice := promptWithDefault(reader, "  Choose", "2")
			if choice == "1" {
				indexNowKey = promptOptional(reader, "  Paste your IndexNow key")
			} else {
				indexNowKey = generateIndexNowKey()
				fmt.Printf("  Generated key: %s\n", indexNowKey)

				// Create the key file in the web root
				webRoot := detectWebRoot(cwd, stack)
				keyFilePath := filepath.Join(cwd, webRoot, indexNowKey+".txt")
				if err := os.MkdirAll(filepath.Dir(keyFilePath), 0755); err != nil {
					fmt.Printf("  ⚠️  Could not create directory: %v\n", err)
					fmt.Printf("     Create %s/%s.txt containing: %s\n", webRoot, indexNowKey, indexNowKey)
				} else if err := os.WriteFile(keyFilePath, []byte(indexNowKey+"\n"), 0644); err == nil {
					fmt.Printf("  ✅ Created %s/%s.txt\n", webRoot, indexNowKey)
				} else {
					fmt.Printf("  ⚠️  Could not create key file: %v\n", err)
					fmt.Printf("     Create %s/%s.txt containing: %s\n", webRoot, indexNowKey, indexNowKey)
				}
			}
		}
		// Remove from confirmedServices since we handle it separately
		delete(confirmedServices, "indexnow")
	}

	// Build full services map with all services (declared: true or false)
	allServices := make(map[string]config.ServiceConfig)
	for _, svc := range config.AllServices {
		if svc == "indexnow" {
			continue // handled in checks.indexNow
		}
		if _, confirmed := confirmedServices[svc]; confirmed {
			allServices[svc] = config.ServiceConfig{Declared: true}
		} else {
			allServices[svc] = config.ServiceConfig{Declared: false}
		}
	}

	// Build config
	cfg := config.PreflightConfig{
		ProjectName: projectName,
		Stack:       stack,
		URLs: config.URLConfig{
			Staging:    stagingURL,
			Production: productionURL,
		},
		Services: allServices,
		Checks:   buildDefaultChecks(cwd, stack, allServices, productionURL, hasLicense, hasAds, indexNowKey, checkEmailAuth, checkHumansTxt),
	}

	// Write config file
	configPath := "preflight.yml"
	if err := writeConfig(configPath, &cfg); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Println()
	fmt.Printf("✅ Created %s\n", configPath)

	// Check and update .gitignore
	gitignorePath := filepath.Join(cwd, ".gitignore")
	gitignoreUpdated := false
	if content, err := os.ReadFile(gitignorePath); err == nil {
		// .gitignore exists, check if preflight.yml is already in it
		if !strings.Contains(string(content), "preflight.yml") {
			if promptYesNo(reader, "Add preflight.yml to .gitignore?", true) {
				// Append to .gitignore
				f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_WRONLY, 0644)
				if err == nil {
					writeErr := false
					if len(content) > 0 && content[len(content)-1] != '\n' {
						if _, err := f.WriteString("\n"); err != nil {
							writeErr = true
						}
					}
					if !writeErr {
						if _, err := f.WriteString("preflight.yml\n"); err != nil {
							writeErr = true
						}
					}
					if err := f.Close(); err != nil {
						writeErr = true
					}
					if writeErr {
						fmt.Fprintln(os.Stderr, "⚠️  Could not update .gitignore")
					} else {
						gitignoreUpdated = true
						fmt.Println("✅ Added preflight.yml to .gitignore")
					}
				}
			}
		}
	} else if os.IsNotExist(err) {
		// No .gitignore exists, offer to create one
		if promptYesNo(reader, "Create .gitignore with preflight.yml?", true) {
			if err := os.WriteFile(gitignorePath, []byte("preflight.yml\n"), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Could not create .gitignore: %v\n", err)
			} else {
				gitignoreUpdated = true
				fmt.Println("✅ Created .gitignore with preflight.yml")
			}
		}
	}

	if !gitignoreUpdated {
		fmt.Println()
		fmt.Println("⚠️  Remember: preflight.yml may contain sensitive URLs.")
		fmt.Println("   Consider adding it to your .gitignore")
	}

	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Review and customize preflight.yml")
	fmt.Println("  2. Run 'preflight scan' to check your project")
	fmt.Println()

	// Show star message on first init
	if isFirstRun("init_done") {
		showStarMessage()
		markFirstRunComplete("init_done")
	}

	return nil
}

func promptWithDefault(reader *bufio.Reader, prompt, defaultVal string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultVal)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultVal
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

func promptOptional(reader *bufio.Reader, prompt string) string {
	fmt.Printf("%s: ", prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
}

func normalizeURL(url string) string {
	if url == "" {
		return ""
	}

	// Already has a protocol
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}

	// Localhost gets http://
	if strings.HasPrefix(url, "localhost") || strings.HasPrefix(url, "127.0.0.1") {
		return "http://" + url
	}

	// Everything else gets https://
	return "https://" + url
}

func promptYesNo(reader *bufio.Reader, prompt string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, defaultStr)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	input = strings.ToLower(strings.TrimSpace(input))

	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

func getDefaultProjectName(cwd string) string {
	parts := strings.Split(cwd, string(os.PathSeparator))
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "my-project"
}

func buildDefaultChecks(cwd, stack string, services map[string]config.ServiceConfig, productionURL string, hasLicense bool, hasAds bool, indexNowKey string, checkEmailAuth bool, checkHumansTxt bool) config.ChecksConfig {
	checks := config.ChecksConfig{
		EnvParity: &config.EnvParityConfig{
			Enabled:     true,
			EnvFile:     ".env",
			ExampleFile: ".env.example",
		},
		HealthEndpoint: &config.HealthEndpointConfig{
			Enabled: stackNeedsHealthEndpoint(stack),
			Path:    "/health",
		},
		Security: &config.SecurityConfig{
			Enabled: productionURL != "",
		},
		Secrets: &config.SecretsConfig{
			Enabled: true,
		},
		License: &config.LicenseConfig{
			Enabled: hasLicense,
		},
		AdsTxt: &config.AdsTxtConfig{
			Enabled: hasAds,
		},
		IndexNow: &config.IndexNowConfig{
			Enabled: indexNowKey != "",
			Key:     indexNowKey,
		},
		EmailAuth: &config.EmailAuthConfig{
			Enabled: checkEmailAuth,
		},
		HumansTxt: &config.HumansTxtConfig{
			Enabled: checkHumansTxt,
		},
	}

	// Configure Stripe webhook if Stripe is declared
	if services["stripe"].Declared {
		checks.StripeWebhook = &config.StripeWebhookConfig{
			Enabled: true,
			URL:     "", // User must configure
		}
	}

	// Configure SEO check based on stack
	mainLayout := detectMainLayout(cwd, stack)
	if mainLayout != "" {
		checks.SEOMeta = &config.SEOMetaConfig{
			Enabled:    true,
			MainLayout: mainLayout,
		}
	}

	return checks
}

func detectMainLayout(cwd, stack string) string {
	// Stack-specific layouts (checked first)
	stackLayouts := map[string][]string{
		// Frameworks
		"rails":   {"app/views/layouts/application.html.erb"},
		"next":    {"app/layout.tsx", "app/layout.js", "pages/_document.tsx", "pages/_document.js"},
		"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs"},
		"laravel": {"resources/views/layouts/app.blade.php", "resources/views/layout.blade.php"},
		"django":  {"templates/base.html", "templates/layout.html"},
		"static":  {"index.html"},

		// Traditional CMS
		"wordpress": {"wp-content/themes/theme/header.php", "wp-content/themes/theme/functions.php"},
		"craft":     {"templates/_layout.twig", "templates/_layout.html"},
		"drupal":    {"themes/custom/theme/templates/html.html.twig"},
		"ghost":     {"content/themes/casper/default.hbs"},

		// Static Site Generators
		"hugo":     {"layouts/_default/baseof.html", "themes/theme/layouts/_default/baseof.html"},
		"jekyll":   {"_layouts/default.html", "_includes/head.html"},
		"gatsby":   {"src/components/layout.js", "src/components/layout.tsx", "src/templates/page.js"},
		"eleventy": {"_includes/layout.njk", "_includes/base.njk", "_includes/layout.liquid"},
		"astro":    {"src/layouts/Layout.astro", "src/layouts/BaseLayout.astro"},

		// Headless CMS (frontend usually in Next.js, etc.)
		"strapi":     {"src/admin/app.js"},
		"sanity":     {"schemas/schema.js"},
		"contentful": {"src/templates/page.js"},
		"prismic":    {"src/components/Layout.js"},
	}

	// Check stack-specific paths first
	if paths, ok := stackLayouts[stack]; ok {
		for _, path := range paths {
			if _, err := os.Stat(filepath.Join(cwd, path)); err == nil {
				return path
			}
		}
	}

	// Universal layout patterns (checked for all stacks)
	// These cover common conventions across frameworks
	universalLayouts := []string{
		// PHP common patterns
		"partials/header.php",
		"includes/header.php",
		"inc/header.php",
		"templates/header.php",
		"views/partials/header.php",
		"views/includes/header.php",
		"app/views/header.php",
		"resources/views/partials/header.php",
		"public/index.php",
		"index.php",

		// HTML/Static
		"index.html",
		"public/index.html",
		"src/index.html",

		// Node/Express
		"views/layout.ejs",
		"views/layout.pug",
		"views/layout.hbs",
		"views/layouts/main.hbs",
		"views/layouts/main.ejs",

		// React/Vue/Svelte
		"src/App.tsx",
		"src/App.jsx",
		"src/App.js",
		"src/App.vue",
		"src/App.svelte",
		"src/main.tsx",
		"src/main.jsx",
		"src/main.js",
		"app/layout.tsx",
		"app/layout.jsx",
		"app/layout.js",
		"pages/_app.tsx",
		"pages/_app.jsx",
		"pages/_app.js",
		"pages/_document.tsx",
		"pages/_document.jsx",
		"pages/_document.js",

		// Twig (Symfony, Craft, etc.)
		"templates/base.twig",
		"templates/_layout.twig",
		"templates/layout.twig",
		"templates/base.html.twig",

		// Blade (Laravel)
		"resources/views/layouts/app.blade.php",
		"resources/views/layout.blade.php",
		"resources/views/layouts/main.blade.php",

		// Ruby/Rails
		"app/views/layouts/application.html.erb",

		// Python/Django/Flask
		"templates/base.html",
		"templates/layout.html",

		// Go
		"templates/base.html",
		"templates/layout.html",
		"views/base.html",
		"views/layout.html",

		// Static site generators
		"_layouts/default.html",
		"_includes/head.html",
		"layouts/_default/baseof.html",
		"src/layouts/Layout.astro",
		"_includes/layout.njk",
	}

	for _, path := range universalLayouts {
		if _, err := os.Stat(filepath.Join(cwd, path)); err == nil {
			return path
		}
	}

	return ""
}

func writeConfig(path string, cfg *config.PreflightConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func formatServiceName(svc string) string {
	names := map[string]string{
		// Payments
		"stripe":       "Stripe",
		"paypal":       "PayPal",
		"braintree":    "Braintree",
		"paddle":       "Paddle",
		"lemonsqueezy": "LemonSqueezy",

		// Error Tracking & Monitoring
		"sentry":      "Sentry",
		"bugsnag":     "Bugsnag",
		"rollbar":     "Rollbar",
		"honeybadger": "Honeybadger",
		"datadog":     "Datadog",
		"newrelic":    "New Relic",
		"logrocket":   "LogRocket",

		// Email
		"postmark":        "Postmark",
		"sendgrid":        "SendGrid",
		"mailgun":         "Mailgun",
		"aws_ses":         "AWS SES",
		"resend":          "Resend",
		"mailchimp":       "Mailchimp",
		"convertkit":      "Kit",
		"beehiiv":         "Beehiiv",
		"aweber":          "AWeber",
		"activecampaign":  "ActiveCampaign",
		"campaignmonitor": "Campaign Monitor",
		"drip":            "Drip",
		"klaviyo":         "Klaviyo",
		"buttondown":      "Buttondown",

		// Analytics
		"plausible":        "Plausible Analytics",
		"fathom":           "Fathom Analytics",
		"fullres":          "Fullres Analytics",
		"datafast":         "Datafa.st Analytics",
		"google_analytics": "Google Analytics",
		"posthog":          "PostHog",
		"mixpanel":         "Mixpanel",
		"amplitude":        "Amplitude",
		"segment":          "Segment",
		"hotjar":           "Hotjar",

		// Auth
		"auth0":    "Auth0",
		"clerk":    "Clerk",
		"workos":   "WorkOS",
		"firebase": "Firebase",
		"supabase": "Supabase",

		// Communication
		"twilio":   "Twilio",
		"slack":    "Slack",
		"discord":  "Discord",
		"intercom": "Intercom",
		"crisp":    "Crisp",

		// Infrastructure
		"redis":         "Redis",
		"sidekiq":       "Sidekiq",
		"rabbitmq":      "RabbitMQ",
		"elasticsearch": "Elasticsearch",
		"convex":        "Convex",

		// Storage & CDN
		"aws_s3":     "AWS S3",
		"cloudinary": "Cloudinary",
		"cloudflare": "Cloudflare",

		// Search
		"algolia": "Algolia",

		// AI
		"openai":      "OpenAI",
		"anthropic":   "Anthropic Claude",
		"google_ai":   "Google AI (Gemini)",
		"mistral":     "Mistral AI",
		"cohere":      "Cohere",
		"replicate":   "Replicate",
		"huggingface": "Hugging Face",
		"grok":        "Grok (X/Twitter)",
		"perplexity":  "Perplexity",
		"together_ai": "Together AI",

		// SEO
		"indexnow": "IndexNow",

		// Cookie Consent
		"cookieconsent": "CookieConsent",
		"cookiebot":     "Cookiebot",
		"onetrust":      "OneTrust",
		"termly":        "Termly",
		"cookieyes":     "CookieYes",
		"iubenda":       "Iubenda",
	}
	if name, ok := names[svc]; ok {
		return name
	}
	return svc
}

func formatStackName(stack string) string {
	names := map[string]string{
		// Frameworks
		"rails":   "Ruby on Rails",
		"next":    "Next.js",
		"node":    "Node.js",
		"react":   "React",
		"vue":     "Vue.js",
		"vite":    "Vite",
		"svelte":  "Svelte",
		"angular": "Angular",
		"laravel": "Laravel",
		"django":  "Django",
		"python":  "Python",
		"go":      "Go",
		"rust":    "Rust",
		"static":  "Static Site",

		// Traditional CMS
		"wordpress": "WordPress",
		"craft":     "Craft CMS",
		"drupal":    "Drupal",
		"ghost":     "Ghost",

		// Static Site Generators
		"hugo":     "Hugo",
		"jekyll":   "Jekyll",
		"gatsby":   "Gatsby",
		"eleventy": "Eleventy (11ty)",
		"astro":    "Astro",

		// Headless CMS
		"strapi":     "Strapi",
		"sanity":     "Sanity",
		"contentful": "Contentful",
		"prismic":    "Prismic",
	}
	if name, ok := names[stack]; ok {
		return name
	}
	return stack
}

func detectStackVersion(cwd, stack string) string {
	switch stack {
	case "craft":
		return detectComposerVersion(cwd, "craftcms/cms")
	case "laravel":
		return detectComposerVersion(cwd, "laravel/framework")
	case "drupal":
		return detectComposerVersion(cwd, "drupal/core")
	case "wordpress":
		// Check wp-includes/version.php for WordPress version
		versionFile := cwd + "/wp-includes/version.php"
		if content, err := os.ReadFile(versionFile); err == nil {
			re := regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
			if matches := re.FindStringSubmatch(string(content)); len(matches) > 1 {
				return matches[1]
			}
		}
	case "next":
		return detectNpmVersion(cwd, "next")
	case "gatsby":
		return detectNpmVersion(cwd, "gatsby")
	case "astro":
		return detectNpmVersion(cwd, "astro")
	case "eleventy":
		return detectNpmVersion(cwd, "@11ty/eleventy")
	case "hugo":
		// Check hugo.toml or config.toml for version info (usually not present)
		// Hugo version is CLI-based, not project-based
		return ""
	case "jekyll":
		return detectGemVersion(cwd, "jekyll")
	case "rails":
		return detectGemVersion(cwd, "rails")
	case "ghost":
		return detectNpmVersion(cwd, "ghost")
	case "strapi":
		return detectNpmVersion(cwd, "@strapi/strapi")
	case "sanity":
		return detectNpmVersion(cwd, "sanity")
	}
	return ""
}

func detectComposerVersion(cwd, pkg string) string {
	composerLock := cwd + "/composer.lock"
	if content, err := os.ReadFile(composerLock); err == nil {
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(content, &lock) == nil {
			for _, p := range lock.Packages {
				if p.Name == pkg {
					return strings.TrimPrefix(p.Version, "v")
				}
			}
		}
	}
	// Fallback to composer.json
	composerJSON := cwd + "/composer.json"
	if content, err := os.ReadFile(composerJSON); err == nil {
		var composer struct {
			Require map[string]string `json:"require"`
		}
		if json.Unmarshal(content, &composer) == nil {
			if version, ok := composer.Require[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
		}
	}
	return ""
}

func detectNpmVersion(cwd, pkg string) string {
	packageLock := cwd + "/package-lock.json"
	if content, err := os.ReadFile(packageLock); err == nil {
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
			Dependencies map[string]struct {
				Version string `json:"version"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(content, &lock) == nil {
			// Check packages (npm v7+)
			if p, ok := lock.Packages["node_modules/"+pkg]; ok {
				return p.Version
			}
			// Check dependencies (npm v6)
			if d, ok := lock.Dependencies[pkg]; ok {
				return d.Version
			}
		}
	}
	// Fallback to package.json
	packageJSON := cwd + "/package.json"
	if content, err := os.ReadFile(packageJSON); err == nil {
		var pkg2 struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(content, &pkg2) == nil {
			if version, ok := pkg2.Dependencies[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
			if version, ok := pkg2.DevDependencies[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
		}
	}
	return ""
}

func detectGemVersion(cwd, gem string) string {
	gemfileLock := cwd + "/Gemfile.lock"
	if content, err := os.ReadFile(gemfileLock); err == nil {
		// Parse Gemfile.lock for gem version
		re := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(gem) + ` \(([^)]+)\)`)
		if matches := re.FindStringSubmatch(string(content)); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func generateIndexNowKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Could not generate random key: %v\n", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}

func detectIndexNowKey(cwd string) string {
	// First check .env files
	envFiles := []string{".env", ".env.example", ".env.local", ".env.development"}
	keyPatterns := []string{"INDEXNOW_API_KEY=", "INDEXNOW_KEY=", "INDEX_NOW_KEY="}

	for _, envFile := range envFiles {
		path := filepath.Join(cwd, envFile)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			for _, pattern := range keyPatterns {
				if strings.HasPrefix(strings.ToUpper(line), pattern) {
					// Extract the value after the =
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[1])
						// Remove quotes if present
						key = strings.Trim(key, "\"'")
						if key != "" && key != "your_key_here" {
							return key
						}
					}
				}
			}
		}
	}

	// Also check for existing key files in web root (32-char hex filename.txt)
	webRoots := []string{"public", "web", "static", "_site", "dist", ""}
	hexPattern := regexp.MustCompile(`^[a-f0-9]{32}\.txt$`)

	for _, root := range webRoots {
		dir := filepath.Join(cwd, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && hexPattern.MatchString(entry.Name()) {
				// Found a key file, extract the key from filename
				key := strings.TrimSuffix(entry.Name(), ".txt")
				// Verify file content matches the key
				content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err == nil && strings.TrimSpace(string(content)) == key {
					return key
				}
			}
		}
	}

	return ""
}

func detectWebRoot(cwd, stack string) string {
	// Stack-specific web roots
	stackRoots := map[string]string{
		"rails":     "public",
		"laravel":   "public",
		"next":      "public",
		"node":      "public",
		"craft":     "web",
		"symfony":   "public",
		"django":    "static",
		"hugo":      "static",
		"jekyll":    "_site",
		"gatsby":    "public",
		"astro":     "public",
		"eleventy":  "_site",
		"wordpress": "",
		"drupal":    "web",
		"ghost":     "content",
	}

	if root, ok := stackRoots[stack]; ok && root != "" {
		return root
	}

	// Check for common web root directories
	commonRoots := []string{"public", "static", "web", "www", "dist", "build", "_site", "out"}
	for _, root := range commonRoots {
		if info, err := os.Stat(filepath.Join(cwd, root)); err == nil && info.IsDir() {
			return root
		}
	}

	// Default to public
	return "public"
}

// stackNeedsHealthEndpoint returns true for application stacks that typically have health endpoints
// CMS and static sites don't need dedicated health endpoints
func stackNeedsHealthEndpoint(stack string) bool {
	appStacks := map[string]bool{
		"rails":   true,
		"node":    true,
		"next":    true,
		"laravel": true,
		"django":  true,
		"python":  true,
		"go":      true,
		"rust":    true,
	}
	return appStacks[stack]
}
