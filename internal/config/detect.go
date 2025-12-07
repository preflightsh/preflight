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

	// === Traditional CMS ===

	// Check for WordPress
	if fileExists(rootDir, "wp-config.php") || fileExists(rootDir, "wp-content/themes") {
		return "wordpress"
	}

	// Check for Craft CMS
	if fileExists(rootDir, "craft") || fileContains(rootDir, "composer.json", "craftcms/cms") {
		return "craft"
	}

	// Check for Drupal
	if fileExists(rootDir, "core/lib/Drupal.php") || (fileExists(rootDir, "sites/default") && fileExists(rootDir, "core")) {
		return "drupal"
	}

	// Check for Ghost (before generic Node.js check)
	if fileContains(rootDir, "package.json", "\"ghost\"") || fileExists(rootDir, "content/themes") {
		return "ghost"
	}

	// === Static Site Generators ===

	// Check for Hugo
	if fileExists(rootDir, "hugo.toml") || fileExists(rootDir, "hugo.yaml") || fileExists(rootDir, "hugo.json") ||
		(fileExists(rootDir, "config.toml") && fileExists(rootDir, "content") && fileExists(rootDir, "themes")) {
		return "hugo"
	}

	// Check for Jekyll
	if fileExists(rootDir, "_config.yml") && (fileExists(rootDir, "_posts") || fileExists(rootDir, "_layouts")) {
		return "jekyll"
	}

	// Check for Gatsby
	if fileExists(rootDir, "gatsby-config.js") || fileExists(rootDir, "gatsby-config.ts") || fileExists(rootDir, "gatsby-config.mjs") {
		return "gatsby"
	}

	// Check for Eleventy (11ty)
	if fileExists(rootDir, ".eleventy.js") || fileExists(rootDir, "eleventy.config.js") || fileExists(rootDir, "eleventy.config.mjs") ||
		fileContains(rootDir, "package.json", "@11ty/eleventy") {
		return "eleventy"
	}

	// Check for Astro
	if fileExists(rootDir, "astro.config.mjs") || fileExists(rootDir, "astro.config.ts") || fileExists(rootDir, "astro.config.js") {
		return "astro"
	}

	// === Headless CMS ===

	// Check for Strapi
	if fileContains(rootDir, "package.json", "@strapi/strapi") || fileExists(rootDir, "src/api") && fileExists(rootDir, "config/database.js") {
		return "strapi"
	}

	// Check for Sanity
	if fileExists(rootDir, "sanity.json") || fileExists(rootDir, "sanity.config.ts") || fileExists(rootDir, "sanity.config.js") ||
		fileContains(rootDir, "package.json", "sanity") {
		return "sanity"
	}

	// Check for Contentful (usually detected via env vars, but check for config)
	if fileContains(rootDir, "package.json", "contentful") {
		return "contentful"
	}

	// Check for Prismic
	if fileExists(rootDir, "prismicio.js") || fileExists(rootDir, "slicemachine.config.json") ||
		fileContains(rootDir, "package.json", "@prismicio") {
		return "prismic"
	}

	// === General Stacks ===

	// Check for Go
	if fileExists(rootDir, "go.mod") {
		return "go"
	}

	// Check for Python (Django/Flask)
	if fileExists(rootDir, "requirements.txt") || fileExists(rootDir, "pyproject.toml") || fileExists(rootDir, "Pipfile") {
		if fileExists(rootDir, "manage.py") {
			return "django"
		}
		return "python"
	}

	// Check for Rust
	if fileExists(rootDir, "Cargo.toml") {
		return "rust"
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

// fileContains checks if a file exists and contains a specific string
func fileContains(rootDir, relativePath, search string) bool {
	path := filepath.Join(rootDir, relativePath)
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), search)
}

// AllServices returns the list of all supported services
var AllServices = []string{
	// Payments
	"stripe",
	"paypal",
	"braintree",
	"paddle",
	"lemonsqueezy",

	// Error Tracking & Monitoring
	"sentry",
	"bugsnag",
	"rollbar",
	"honeybadger",
	"datadog",
	"newrelic",
	"logrocket",

	// Email
	"postmark",
	"sendgrid",
	"mailgun",
	"aws_ses",
	"resend",
	"mailchimp",
	"convertkit",

	// Analytics
	"plausible",
	"fathom",
	"fullres",
	"datafast",
	"google_analytics",
	"mixpanel",
	"amplitude",
	"segment",
	"hotjar",

	// Auth
	"auth0",
	"clerk",
	"firebase",
	"supabase",

	// Communication
	"twilio",
	"slack",
	"discord",
	"intercom",
	"crisp",

	// Infrastructure
	"redis",
	"sidekiq",
	"rabbitmq",
	"elasticsearch",

	// Storage & CDN
	"aws_s3",
	"cloudinary",
	"cloudflare",

	// Search
	"algolia",

	// AI
	"openai",
	"anthropic",
	"google_ai",
	"mistral",
	"cohere",
	"replicate",
	"huggingface",
	"grok",
	"perplexity",
	"together_ai",
}

// DetectServices scans the project for known service integrations
func DetectServices(rootDir string) map[string]bool {
	services := make(map[string]bool)
	for _, svc := range AllServices {
		services[svc] = false
	}

	// Check package.json
	if pkgJSON, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
		content := strings.ToLower(string(pkgJSON))
		detectServicesFromContent(content, services, "node")
	}

	// Check Gemfile
	if gemfile, err := os.ReadFile(filepath.Join(rootDir, "Gemfile")); err == nil {
		content := strings.ToLower(string(gemfile))
		detectServicesFromContent(content, services, "ruby")
	}

	// Check Gemfile.lock for more precise detection
	if gemfileLock, err := os.ReadFile(filepath.Join(rootDir, "Gemfile.lock")); err == nil {
		content := strings.ToLower(string(gemfileLock))
		detectServicesFromContent(content, services, "ruby")
	}

	// Check composer.json for Laravel
	if composer, err := os.ReadFile(filepath.Join(rootDir, "composer.json")); err == nil {
		content := strings.ToLower(string(composer))
		detectServicesFromContent(content, services, "php")
	}

	// Check for env keys
	services = detectServicesFromEnv(rootDir, services)

	// Check for analytics scripts in HTML files
	detectAnalyticsScripts(rootDir, services)

	return services
}

func detectServicesFromContent(content string, services map[string]bool, lang string) {
	// Payments
	if strings.Contains(content, "stripe") {
		services["stripe"] = true
	}
	if strings.Contains(content, "paypal") || strings.Contains(content, "@paypal") {
		services["paypal"] = true
	}
	if strings.Contains(content, "braintree") {
		services["braintree"] = true
	}
	if strings.Contains(content, "paddle") || strings.Contains(content, "@paddle") {
		services["paddle"] = true
	}
	if strings.Contains(content, "lemonsqueezy") || strings.Contains(content, "lemon-squeezy") {
		services["lemonsqueezy"] = true
	}

	// Error Tracking & Monitoring
	if strings.Contains(content, "sentry") || strings.Contains(content, "@sentry") {
		services["sentry"] = true
	}
	if strings.Contains(content, "bugsnag") {
		services["bugsnag"] = true
	}
	if strings.Contains(content, "rollbar") {
		services["rollbar"] = true
	}
	if strings.Contains(content, "honeybadger") {
		services["honeybadger"] = true
	}
	if strings.Contains(content, "datadog") || strings.Contains(content, "dd-trace") {
		services["datadog"] = true
	}
	if strings.Contains(content, "newrelic") || strings.Contains(content, "new-relic") {
		services["newrelic"] = true
	}
	if strings.Contains(content, "logrocket") {
		services["logrocket"] = true
	}

	// Email
	if strings.Contains(content, "postmark") {
		services["postmark"] = true
	}
	if strings.Contains(content, "sendgrid") || strings.Contains(content, "@sendgrid") {
		services["sendgrid"] = true
	}
	if strings.Contains(content, "mailgun") {
		services["mailgun"] = true
	}
	if strings.Contains(content, "aws-sdk-ses") || strings.Contains(content, "@aws-sdk/client-ses") {
		services["aws_ses"] = true
	}
	if strings.Contains(content, "resend") && !strings.Contains(content, "resend(") {
		services["resend"] = true
	}
	if strings.Contains(content, "mailchimp") || strings.Contains(content, "@mailchimp") {
		services["mailchimp"] = true
	}
	if strings.Contains(content, "convertkit") {
		services["convertkit"] = true
	}

	// Analytics
	if strings.Contains(content, "fathom") {
		services["fathom"] = true
	}
	if strings.Contains(content, "fullres") {
		services["fullres"] = true
	}
	if strings.Contains(content, "datafast") || strings.Contains(content, "datafa.st") {
		services["datafast"] = true
	}
	if strings.Contains(content, "mixpanel") {
		services["mixpanel"] = true
	}
	if strings.Contains(content, "amplitude") {
		services["amplitude"] = true
	}
	if strings.Contains(content, "segment") || strings.Contains(content, "@segment") {
		services["segment"] = true
	}
	if strings.Contains(content, "hotjar") {
		services["hotjar"] = true
	}
	if strings.Contains(content, "react-ga") || strings.Contains(content, "vue-gtag") {
		services["google_analytics"] = true
	}

	// Auth
	if strings.Contains(content, "auth0") || strings.Contains(content, "@auth0") {
		services["auth0"] = true
	}
	if strings.Contains(content, "@clerk") || strings.Contains(content, "clerk-sdk") {
		services["clerk"] = true
	}
	if strings.Contains(content, "firebase") {
		services["firebase"] = true
	}
	if strings.Contains(content, "supabase") || strings.Contains(content, "@supabase") {
		services["supabase"] = true
	}

	// Communication
	if strings.Contains(content, "twilio") {
		services["twilio"] = true
	}
	if strings.Contains(content, "@slack/") || strings.Contains(content, "slack-ruby") {
		services["slack"] = true
	}
	if strings.Contains(content, "discord.js") || strings.Contains(content, "discordrb") {
		services["discord"] = true
	}
	if strings.Contains(content, "intercom") {
		services["intercom"] = true
	}
	if strings.Contains(content, "crisp") {
		services["crisp"] = true
	}

	// Infrastructure
	if strings.Contains(content, "redis") || strings.Contains(content, "ioredis") {
		services["redis"] = true
	}
	if strings.Contains(content, "sidekiq") {
		services["sidekiq"] = true
	}
	if strings.Contains(content, "amqplib") || strings.Contains(content, "bunny") || strings.Contains(content, "rabbitmq") {
		services["rabbitmq"] = true
	}
	if strings.Contains(content, "elasticsearch") || strings.Contains(content, "@elastic") {
		services["elasticsearch"] = true
	}

	// Storage & CDN
	if strings.Contains(content, "aws-sdk-s3") || strings.Contains(content, "@aws-sdk/client-s3") || strings.Contains(content, "aws-sdk/s3") {
		services["aws_s3"] = true
	}
	if strings.Contains(content, "cloudinary") {
		services["cloudinary"] = true
	}

	// Search
	if strings.Contains(content, "algoliasearch") || strings.Contains(content, "algolia") {
		services["algolia"] = true
	}

	// AI
	if strings.Contains(content, "openai") {
		services["openai"] = true
	}
	if strings.Contains(content, "anthropic") || strings.Contains(content, "@anthropic") {
		services["anthropic"] = true
	}
	if strings.Contains(content, "@google/generative-ai") || strings.Contains(content, "google-generativeai") || strings.Contains(content, "gemini") {
		services["google_ai"] = true
	}
	if strings.Contains(content, "mistralai") || strings.Contains(content, "@mistralai") {
		services["mistral"] = true
	}
	if strings.Contains(content, "cohere") {
		services["cohere"] = true
	}
	if strings.Contains(content, "replicate") {
		services["replicate"] = true
	}
	if strings.Contains(content, "huggingface") || strings.Contains(content, "@huggingface") || strings.Contains(content, "transformers") {
		services["huggingface"] = true
	}
	if strings.Contains(content, "grok") || strings.Contains(content, "x.ai") {
		services["grok"] = true
	}
	if strings.Contains(content, "perplexity") {
		services["perplexity"] = true
	}
	if strings.Contains(content, "together") && strings.Contains(content, "ai") {
		services["together_ai"] = true
	}
}

func detectServicesFromEnv(rootDir string, services map[string]bool) map[string]bool {
	envFiles := []string{".env", ".env.example", ".env.local", ".env.development"}

	envPatterns := map[string][]string{
		// Payments
		"stripe":       {"STRIPE_"},
		"paypal":       {"PAYPAL_"},
		"braintree":    {"BRAINTREE_"},
		"paddle":       {"PADDLE_"},
		"lemonsqueezy": {"LEMONSQUEEZY_", "LEMON_SQUEEZY_"},

		// Error Tracking & Monitoring
		"sentry":      {"SENTRY_DSN", "SENTRY_"},
		"bugsnag":     {"BUGSNAG_"},
		"rollbar":     {"ROLLBAR_"},
		"honeybadger": {"HONEYBADGER_"},
		"datadog":     {"DD_", "DATADOG_"},
		"newrelic":    {"NEW_RELIC_", "NEWRELIC_"},
		"logrocket":   {"LOGROCKET_"},

		// Email
		"postmark":   {"POSTMARK_"},
		"sendgrid":   {"SENDGRID_"},
		"mailgun":    {"MAILGUN_"},
		"aws_ses":    {"AWS_SES_", "SES_REGION"},
		"resend":     {"RESEND_"},
		"mailchimp":  {"MAILCHIMP_"},
		"convertkit": {"CONVERTKIT_"},

		// Analytics
		"plausible":        {"PLAUSIBLE_", "NEXT_PUBLIC_PLAUSIBLE"},
		"fathom":           {"FATHOM_", "NEXT_PUBLIC_FATHOM"},
		"fullres":          {"FULLRES_", "NEXT_PUBLIC_FULLRES"},
		"datafast":         {"DATAFAST_", "NEXT_PUBLIC_DATAFAST"},
		"google_analytics": {"GA_TRACKING_ID", "GOOGLE_ANALYTICS", "NEXT_PUBLIC_GA", "GA_MEASUREMENT_ID", "GTM_"},
		"mixpanel":         {"MIXPANEL_"},
		"amplitude":        {"AMPLITUDE_"},
		"segment":          {"SEGMENT_"},
		"hotjar":           {"HOTJAR_"},

		// Auth
		"auth0":    {"AUTH0_"},
		"clerk":    {"CLERK_", "NEXT_PUBLIC_CLERK"},
		"firebase": {"FIREBASE_", "NEXT_PUBLIC_FIREBASE"},
		"supabase": {"SUPABASE_", "NEXT_PUBLIC_SUPABASE"},

		// Communication
		"twilio":   {"TWILIO_"},
		"slack":    {"SLACK_"},
		"discord":  {"DISCORD_"},
		"intercom": {"INTERCOM_"},
		"crisp":    {"CRISP_"},

		// Infrastructure
		"redis":         {"REDIS_URL", "REDIS_HOST", "REDISCLOUD_URL"},
		"sidekiq":       {"SIDEKIQ_"},
		"rabbitmq":      {"RABBITMQ_", "AMQP_URL", "CLOUDAMQP_URL"},
		"elasticsearch": {"ELASTICSEARCH_", "ELASTIC_"},

		// Storage & CDN
		"aws_s3":     {"AWS_S3_", "S3_BUCKET", "AWS_BUCKET"},
		"cloudinary": {"CLOUDINARY_"},
		"cloudflare": {"CLOUDFLARE_"},

		// Search
		"algolia": {"ALGOLIA_"},

		// AI
		"openai":      {"OPENAI_"},
		"anthropic":   {"ANTHROPIC_", "CLAUDE_"},
		"google_ai":   {"GOOGLE_AI_", "GEMINI_", "GOOGLE_GENERATIVE_"},
		"mistral":     {"MISTRAL_"},
		"cohere":      {"COHERE_", "CO_API_KEY"},
		"replicate":   {"REPLICATE_"},
		"huggingface": {"HUGGINGFACE_", "HF_TOKEN", "HF_API_"},
		"grok":        {"GROK_", "XAI_"},
		"perplexity":  {"PERPLEXITY_", "PPLX_"},
		"together_ai": {"TOGETHER_", "TOGETHER_AI_"},
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
			line := strings.ToUpper(scanner.Text())
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

func detectAnalyticsScripts(rootDir string, services map[string]bool) {
	patterns := map[string]*regexp.Regexp{
		"plausible":        regexp.MustCompile(`plausible\.io/js/`),
		"fathom":           regexp.MustCompile(`(usefathom\.com|cdn\.usefathom\.com)`),
		"fullres":          regexp.MustCompile(`fullres\.com`),
		"datafast":         regexp.MustCompile(`datafa\.st`),
		"google_analytics": regexp.MustCompile(`(googletagmanager\.com|google-analytics\.com|gtag\(|ga\()`),
		"hotjar":           regexp.MustCompile(`hotjar\.com`),
		"intercom":         regexp.MustCompile(`intercom`),
		"crisp":            regexp.MustCompile(`crisp\.chat`),
		"mixpanel":         regexp.MustCompile(`mixpanel`),
		"segment":          regexp.MustCompile(`segment\.com|analytics\.js`),
	}

	htmlFiles := []string{
		"index.html",
		"public/index.html",
		"app/views/layouts/application.html.erb",
		"resources/views/layouts/app.blade.php",
		"app/layout.tsx",
		"app/layout.js",
		"pages/_app.tsx",
		"pages/_app.js",
		"pages/_document.tsx",
		"pages/_document.js",
	}

	for _, htmlFile := range htmlFiles {
		path := filepath.Join(rootDir, htmlFile)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for service, pattern := range patterns {
			if pattern.Match(content) {
				services[service] = true
			}
		}
	}
}

func fileExists(rootDir, relativePath string) bool {
	path := filepath.Join(rootDir, relativePath)
	_, err := os.Stat(path)
	return err == nil
}
