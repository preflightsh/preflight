package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/phillips-jon/preflight/internal/config"
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
	fmt.Printf("detected: %s\n", stack)

	// Detect services
	fmt.Println("Detecting services...")
	services := config.DetectServices(cwd)
	for name, detected := range services {
		if detected {
			fmt.Printf("  ✓ %s detected\n", name)
		}
	}
	fmt.Println()

	// Get project name
	projectName := promptWithDefault(reader, "Project name", getDefaultProjectName(cwd))

	// Get URLs
	fmt.Println()
	stagingURL := promptOptional(reader, "Staging URL (include https://, optional)")
	productionURL := promptOptional(reader, "Production URL (include https://, optional)")

	// Confirm services
	fmt.Println()
	fmt.Println("Confirm detected services (y/n for each):")
	confirmedServices := make(map[string]config.ServiceConfig)
	for name, detected := range services {
		if detected {
			confirm := promptYesNo(reader, fmt.Sprintf("  Use %s?", name), true)
			if confirm {
				confirmedServices[name] = config.ServiceConfig{Declared: true}
			}
		}
	}

	// Ask about additional services not detected
	fmt.Println()
	fmt.Println("Any other services? (y/n for each):")
	for _, svc := range config.AllServices {
		if _, exists := confirmedServices[svc]; !exists {
			if promptYesNo(reader, fmt.Sprintf("  Use %s?", formatServiceName(svc)), false) {
				confirmedServices[svc] = config.ServiceConfig{Declared: true}
			}
		}
	}

	// Ask about license file
	fmt.Println()
	hasLicense := promptYesNo(reader, "Does this project have a LICENSE file (e.g., MIT, Apache, GPL)?", false)

	// Build config
	cfg := config.PreflightConfig{
		ProjectName: projectName,
		Stack:       stack,
		URLs: config.URLConfig{
			Staging:    stagingURL,
			Production: productionURL,
		},
		Services: confirmedServices,
		Checks:   buildDefaultChecks(cwd, stack, confirmedServices, productionURL, hasLicense),
	}

	// Write config file
	configPath := "preflight.yml"
	if err := writeConfig(configPath, &cfg); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Println()
	fmt.Printf("✅ Created %s\n", configPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Review and customize preflight.yml")
	fmt.Println("  2. Run 'preflight scan' to check your project")
	fmt.Println()

	return nil
}

func promptWithDefault(reader *bufio.Reader, prompt, defaultVal string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultVal)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

func promptOptional(reader *bufio.Reader, prompt string) string {
	fmt.Printf("%s: ", prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptYesNo(reader *bufio.Reader, prompt string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, defaultStr)
	input, _ := reader.ReadString('\n')
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

func buildDefaultChecks(cwd, stack string, services map[string]config.ServiceConfig, productionURL string, hasLicense bool) config.ChecksConfig {
	checks := config.ChecksConfig{
		EnvParity: &config.EnvParityConfig{
			Enabled:     true,
			EnvFile:     ".env",
			ExampleFile: ".env.example",
		},
		HealthEndpoint: &config.HealthEndpointConfig{
			Enabled: true,
			Path:    "/health",
		},
		Sentry: &config.SentryConfig{
			Enabled: services["sentry"].Declared,
		},
		Plausible: &config.PlausibleConfig{
			Enabled: services["plausible"].Declared,
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
	layouts := map[string][]string{
		// Frameworks
		"rails":   {"app/views/layouts/application.html.erb"},
		"next":    {"app/layout.tsx", "app/layout.js", "pages/_document.tsx", "pages/_document.js"},
		"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs"},
		"laravel": {"resources/views/layouts/app.blade.php"},
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

	if paths, ok := layouts[stack]; ok {
		for _, path := range paths {
			if _, err := os.Stat(cwd + "/" + path); err == nil {
				return path
			}
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
		"postmark":   "Postmark",
		"sendgrid":   "SendGrid",
		"mailgun":    "Mailgun",
		"aws_ses":    "AWS SES",
		"resend":     "Resend",
		"mailchimp":  "Mailchimp",
		"convertkit": "ConvertKit",

		// Analytics
		"plausible":        "Plausible Analytics",
		"fathom":           "Fathom Analytics",
		"fullres":          "Fullres",
		"datafast":         "Datafast",
		"google_analytics": "Google Analytics",
		"mixpanel":         "Mixpanel",
		"amplitude":        "Amplitude",
		"segment":          "Segment",
		"hotjar":           "Hotjar",

		// Auth
		"auth0":    "Auth0",
		"clerk":    "Clerk",
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
	}
	if name, ok := names[svc]; ok {
		return name
	}
	return svc
}
