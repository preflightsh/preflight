package config

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DetectStack determines the project stack based on files present
func DetectStack(rootDir string) string {
	// Check for Rails
	if fileExists(rootDir, "Gemfile") && fileExists(rootDir, "config/routes.rb") {
		return "rails"
	}

	// Check for Next.js (including monorepo structures)
	if fileExists(rootDir, "next.config.js") || fileExists(rootDir, "next.config.mjs") || fileExists(rootDir, "next.config.ts") {
		return "next"
	}
	// Check monorepo structures for Next.js
	if hasMonorepoFramework(rootDir, []string{"next.config.js", "next.config.mjs", "next.config.ts"}) {
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

	// Check for basic PHP site (before Node.js, since PHP sites often use Node for build tools)
	if fileExists(rootDir, "public/index.php") || fileExists(rootDir, "index.php") {
		// Not a known PHP framework, just a plain PHP site
		return "php"
	}

	// Check for Node.js frameworks
	if fileExists(rootDir, "package.json") {
		// Check for Vite
		if fileExists(rootDir, "vite.config.js") || fileExists(rootDir, "vite.config.ts") || fileExists(rootDir, "vite.config.mjs") {
			return "vite"
		}

		// Check for specific frameworks in package.json
		if pkgJSON, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
			content := string(pkgJSON)
			// Check for React
			if strings.Contains(content, "\"react\"") {
				return "react"
			}
			// Check for Vue
			if strings.Contains(content, "\"vue\"") {
				return "vue"
			}
			// Check for Svelte
			if strings.Contains(content, "\"svelte\"") {
				return "svelte"
			}
			// Check for Angular
			if strings.Contains(content, "\"@angular/core\"") {
				return "angular"
			}
		}

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

// hasMonorepoFramework checks if any monorepo subdirectory contains the specified files
func hasMonorepoFramework(rootDir string, files []string) bool {
	monorepoRoots := []string{"apps", "packages", "services"}
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, file := range files {
				if fileExists(filepath.Join(monoDir, entry.Name()), file) {
					return true
				}
			}
		}
	}
	return false
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
	"beehiiv",
	"aweber",
	"activecampaign",
	"campaignmonitor",
	"drip",
	"klaviyo",
	"buttondown",

	// Analytics
	"plausible",
	"fathom",
	"fullres",
	"datafast",
	"google_analytics",
	"posthog",
	"mixpanel",
	"amplitude",
	"segment",
	"hotjar",

	// Auth
	"auth0",
	"clerk",
	"workos",
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
	"convex",

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

	// SEO
	"indexnow",

	// Cookie Consent
	"cookieconsent",
	"cookiebot",
	"onetrust",
	"termly",
	"cookieyes",
	"iubenda",
}

// DetectServices scans the project for known service integrations
func DetectServices(rootDir string) map[string]bool {
	services := make(map[string]bool)
	for _, svc := range AllServices {
		services[svc] = false
	}

	// Check package.json at root
	if pkgJSON, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
		content := strings.ToLower(string(pkgJSON))
		detectServicesFromContent(content, services, "node")
	}

	// Check monorepo package.json files (apps/*, packages/*)
	monorepoRoots := []string{"apps", "packages", "services"}
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgPath := filepath.Join(monoDir, entry.Name(), "package.json")
			if pkgJSON, err := os.ReadFile(pkgPath); err == nil {
				content := strings.ToLower(string(pkgJSON))
				detectServicesFromContent(content, services, "node")
			}
		}
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

	// Check for IndexNow key files in web roots
	detectIndexNowKeyFile(rootDir, services)

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
	// Braintree Payments SDK patterns (not braintree.com AI company)
	if strings.Contains(content, "braintree/braintree") || // composer package
		strings.Contains(content, "Braintree\\Gateway") || // PHP namespace
		strings.Contains(content, "Braintree::") || // Ruby module
		strings.Contains(content, "braintree.BraintreeGateway") || // Node SDK
		strings.Contains(content, "braintree.Environment") || // Python/Node SDK
		strings.Contains(content, "braintreepayments") || // domain
		strings.Contains(content, "BRAINTREE_MERCHANT_ID") ||
		strings.Contains(content, "BRAINTREE_PUBLIC_KEY") ||
		strings.Contains(content, "BRAINTREE_PRIVATE_KEY") {
		services["braintree"] = true
	}
	// Paddle - be specific to avoid matching sports/game paddle
	if strings.Contains(content, "@paddle/") || strings.Contains(content, "paddle-node") ||
		strings.Contains(content, "paddle.com") || strings.Contains(content, "\"paddle\":") {
		services["paddle"] = true
	}
	if strings.Contains(content, "@lemonsqueezy") || strings.Contains(content, "lemonsqueezy/") {
		services["lemonsqueezy"] = true
	}

	// Error Tracking & Monitoring
	// Sentry - be specific to avoid matching the word "sentry" (guard)
	if strings.Contains(content, "@sentry/") || strings.Contains(content, "sentry-") ||
		strings.Contains(content, "sentry.io") || strings.Contains(content, "\"sentry\":") {
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
	// Postmark - be specific to avoid matching "postmark" (stamp mark)
	if strings.Contains(content, "postmarkapp") || strings.Contains(content, "postmark-") ||
		strings.Contains(content, "\"postmark\":") || strings.Contains(content, "@wildbit/postmark") {
		services["postmark"] = true
	}
	if strings.Contains(content, "sendgrid") || strings.Contains(content, "@sendgrid") {
		services["sendgrid"] = true
	}
	if strings.Contains(content, "mailgun") {
		services["mailgun"] = true
	}
	if strings.Contains(content, "aws-sdk-ses") || strings.Contains(content, "@aws-sdk/client-ses") ||
		strings.Contains(content, "craft-amazon-ses") || strings.Contains(content, "amazon-ses") {
		services["aws_ses"] = true
	}
	// Resend - be specific to avoid matching the common word "resend"
	if strings.Contains(content, "resend.com") || strings.Contains(content, "\"resend\":") ||
		strings.Contains(content, "@resend/") || strings.Contains(content, "from resend") {
		services["resend"] = true
	}
	if strings.Contains(content, "mailchimp") || strings.Contains(content, "@mailchimp") {
		services["mailchimp"] = true
	}
	if strings.Contains(content, "convertkit") || strings.Contains(content, "app.kit.com") {
		services["convertkit"] = true
	}
	if strings.Contains(content, "beehiiv") {
		services["beehiiv"] = true
	}
	if strings.Contains(content, "aweber") {
		services["aweber"] = true
	}
	if strings.Contains(content, "activecampaign") {
		services["activecampaign"] = true
	}
	if strings.Contains(content, "campaignmonitor") || strings.Contains(content, "campaign-monitor") || strings.Contains(content, "createsend") {
		services["campaignmonitor"] = true
	}
	if strings.Contains(content, "getdrip") || strings.Contains(content, "drip.com") {
		services["drip"] = true
	}
	if strings.Contains(content, "klaviyo") {
		services["klaviyo"] = true
	}
	if strings.Contains(content, "buttondown") {
		services["buttondown"] = true
	}

	// Analytics
	// Plausible
	if strings.Contains(content, "plausible-tracker") || strings.Contains(content, "plausible.io") {
		services["plausible"] = true
	}
	// Fathom - be specific to avoid matching the common word "fathom" (understand/depth)
	if strings.Contains(content, "usefathom") || strings.Contains(content, "fathom-client") ||
		strings.Contains(content, "\"fathom\":") {
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
	// Amplitude - be specific to avoid matching the physics/math term
	if strings.Contains(content, "@amplitude/") || strings.Contains(content, "amplitude-js") ||
		strings.Contains(content, "amplitude.com") || strings.Contains(content, "\"amplitude\":") {
		services["amplitude"] = true
	}
	// Segment - be specific to avoid matching the common word "segment"
	if strings.Contains(content, "@segment/") || strings.Contains(content, "segment.com") ||
		strings.Contains(content, "analytics-node") || strings.Contains(content, "\"@segment") {
		services["segment"] = true
	}
	if strings.Contains(content, "hotjar") {
		services["hotjar"] = true
	}
	if strings.Contains(content, "react-ga") || strings.Contains(content, "vue-gtag") {
		services["google_analytics"] = true
	}
	if strings.Contains(content, "posthog") {
		services["posthog"] = true
	}

	// Auth
	if strings.Contains(content, "auth0") || strings.Contains(content, "@auth0/") {
		services["auth0"] = true
	}
	// Clerk - be specific to avoid matching the common word "clerk" (office worker)
	if strings.Contains(content, "@clerk/") || strings.Contains(content, "clerk-sdk") ||
		strings.Contains(content, "clerk.com") || strings.Contains(content, "\"@clerk") {
		services["clerk"] = true
	}
	if strings.Contains(content, "workos") || strings.Contains(content, "@workos") {
		services["workos"] = true
	}
	if strings.Contains(content, "firebase") {
		services["firebase"] = true
	}
	if strings.Contains(content, "supabase") || strings.Contains(content, "@supabase") {
		services["supabase"] = true
	}

	// Communication
	// Twilio - add more SDK patterns
	if strings.Contains(content, "twilio") || strings.Contains(content, "@twilio/") {
		services["twilio"] = true
	}
	// Slack - require SDK package patterns
	if strings.Contains(content, "@slack/") || strings.Contains(content, "slack-ruby") ||
		strings.Contains(content, "slack-notify") || strings.Contains(content, "\"slack\":") {
		services["slack"] = true
	}
	// Discord - add Python SDK patterns
	if strings.Contains(content, "discord.js") || strings.Contains(content, "discordrb") ||
		strings.Contains(content, "discord.py") || strings.Contains(content, "disnake") ||
		strings.Contains(content, "pycord") || strings.Contains(content, "\"discord\":") {
		services["discord"] = true
	}
	// Intercom - be specific to avoid matching building intercom systems
	if strings.Contains(content, "intercom.io") || strings.Contains(content, "@intercom/") ||
		strings.Contains(content, "intercom-client") || strings.Contains(content, "\"intercom\":") {
		services["intercom"] = true
	}
	// Crisp - be specific to avoid matching the common word "crisp" (food texture)
	if strings.Contains(content, "crisp.chat") || strings.Contains(content, "crisp-sdk") ||
		strings.Contains(content, "\"crisp\":") || strings.Contains(content, "crisp_website_id") {
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
	// Elasticsearch - be specific with @elastic to avoid false positives
	if strings.Contains(content, "elasticsearch") || strings.Contains(content, "@elastic/") {
		services["elasticsearch"] = true
	}
	// Convex - be specific to avoid matching the math term "convex"
	if strings.Contains(content, "@convex/") || strings.Contains(content, "convex.dev") ||
		strings.Contains(content, "convex/_generated") || strings.Contains(content, "\"convex\":") {
		services["convex"] = true
	}

	// Storage & CDN
	if strings.Contains(content, "aws-sdk-s3") || strings.Contains(content, "@aws-sdk/client-s3") || strings.Contains(content, "aws-sdk/s3") {
		services["aws_s3"] = true
	}
	if strings.Contains(content, "cloudinary") {
		services["cloudinary"] = true
	}
	if strings.Contains(content, "@cloudflare/") || strings.Contains(content, "cloudflare-workers") ||
		strings.Contains(content, "wrangler") {
		services["cloudflare"] = true
	}

	// Search
	if strings.Contains(content, "algoliasearch") || strings.Contains(content, "algolia") {
		services["algolia"] = true
	}

	// AI
	if strings.Contains(content, "openai") {
		services["openai"] = true
	}
	if strings.Contains(content, "anthropic") || strings.Contains(content, "@anthropic/") {
		services["anthropic"] = true
	}
	// Google AI - be specific to avoid matching "gemini" (zodiac sign)
	if strings.Contains(content, "@google/generative-ai") || strings.Contains(content, "google-generativeai") ||
		strings.Contains(content, "gemini-pro") || strings.Contains(content, "gemini-1.5") ||
		strings.Contains(content, "generativelanguage.googleapis") {
		services["google_ai"] = true
	}
	if strings.Contains(content, "mistralai") || strings.Contains(content, "@mistralai/") {
		services["mistral"] = true
	}
	// Cohere - be specific to avoid matching the common word "cohere" (stick together)
	if strings.Contains(content, "cohere-ai") || strings.Contains(content, "cohere.com") ||
		strings.Contains(content, "cohere.ai") || strings.Contains(content, "\"cohere\":") {
		services["cohere"] = true
	}
	// Replicate - be specific to avoid matching the common word "replicate"
	if strings.Contains(content, "replicate.com") || strings.Contains(content, "replicate/") ||
		strings.Contains(content, "\"replicate\":") {
		services["replicate"] = true
	}
	// HuggingFace - be specific with transformers to avoid false positives
	if strings.Contains(content, "huggingface") || strings.Contains(content, "@huggingface/") ||
		strings.Contains(content, "huggingface.co") {
		services["huggingface"] = true
	}
	// Grok - be specific to avoid matching the tech slang "grok" (understand)
	if strings.Contains(content, "xai/grok") || strings.Contains(content, "grok-beta") ||
		strings.Contains(content, "api.x.ai") || strings.Contains(content, "\"grok\":") {
		services["grok"] = true
	}
	// Perplexity - be specific to avoid matching the common word (confusion/ML metric)
	if strings.Contains(content, "perplexity.ai") || strings.Contains(content, "pplx-api") ||
		strings.Contains(content, "\"perplexity\":") {
		services["perplexity"] = true
	}
	// Together AI - be specific to avoid false positives
	if strings.Contains(content, "together.ai") || strings.Contains(content, "@together-ai/") ||
		strings.Contains(content, "together-ai") || strings.Contains(content, "\"together\":") {
		services["together_ai"] = true
	}

	// SEO - only detect if using IndexNow SDK/package, not just mentioning it
	if strings.Contains(content, "indexnow-js") || strings.Contains(content, "indexnow-sdk") ||
		strings.Contains(content, "\"indexnow\":") || strings.Contains(content, "'indexnow':") {
		services["indexnow"] = true
	}

	// Cookie Consent
	if strings.Contains(content, "cookieconsent") || strings.Contains(content, "cookie-consent") {
		services["cookieconsent"] = true
	}
	if strings.Contains(content, "cookiebot") {
		services["cookiebot"] = true
	}
	if strings.Contains(content, "onetrust") || strings.Contains(content, "optanon") {
		services["onetrust"] = true
	}
	if strings.Contains(content, "termly") {
		services["termly"] = true
	}
	if strings.Contains(content, "cookieyes") || strings.Contains(content, "cookie-law-info") {
		services["cookieyes"] = true
	}
	if strings.Contains(content, "iubenda") {
		services["iubenda"] = true
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
		"convertkit":      {"CONVERTKIT_", "KIT_API", "KIT_FORM"},
		"beehiiv":         {"BEEHIIV_"},
		"aweber":          {"AWEBER_"},
		"activecampaign":  {"ACTIVECAMPAIGN_", "AC_API"},
		"campaignmonitor": {"CAMPAIGNMONITOR_", "CAMPAIGN_MONITOR_", "CREATESEND_"},
		"drip":            {"DRIP_"},
		"klaviyo":         {"KLAVIYO_"},
		"buttondown":      {"BUTTONDOWN_"},

		// Analytics
		"plausible":        {"PLAUSIBLE_", "NEXT_PUBLIC_PLAUSIBLE"},
		"fathom":           {"FATHOM_", "NEXT_PUBLIC_FATHOM"},
		"fullres":          {"FULLRES_", "NEXT_PUBLIC_FULLRES"},
		"datafast":         {"DATAFAST_", "NEXT_PUBLIC_DATAFAST"},
		"google_analytics": {"GA_TRACKING_ID", "GOOGLE_ANALYTICS", "NEXT_PUBLIC_GA", "GA_MEASUREMENT_ID", "GTM_"},
		"posthog":          {"POSTHOG_", "NEXT_PUBLIC_POSTHOG"},
		"mixpanel":         {"MIXPANEL_"},
		"amplitude":        {"AMPLITUDE_"},
		"segment":          {"SEGMENT_"},
		"hotjar":           {"HOTJAR_"},

		// Auth
		"auth0":    {"AUTH0_"},
		"clerk":    {"CLERK_", "NEXT_PUBLIC_CLERK"},
		"workos":   {"WORKOS_"},
		"firebase": {"FIREBASE_", "NEXT_PUBLIC_FIREBASE"},
		"supabase": {"SUPABASE_", "NEXT_PUBLIC_SUPABASE"},

		// Communication
		"twilio":   {"TWILIO_"},
		"slack":    {"SLACK_"},
		"discord":  {"DISCORD_"},
		"intercom": {"INTERCOM_"},
		"crisp":    {"CRISP_"},

		// Infrastructure
		"redis":         {"REDIS_URL", "REDIS_HOST", "REDISCLOUD_URL", "UPSTASH_REDIS"},
		"sidekiq":       {"SIDEKIQ_"},
		"rabbitmq":      {"RABBITMQ_", "AMQP_URL", "CLOUDAMQP_URL"},
		"elasticsearch": {"ELASTICSEARCH_", "ELASTIC_"},
		"convex":        {"CONVEX_", "NEXT_PUBLIC_CONVEX"},

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

		// SEO
		"indexnow": {"INDEXNOW_", "INDEX_NOW_"},

		// Cookie Consent
		"cookiebot": {"COOKIEBOT_"},
		"onetrust":  {"ONETRUST_"},
		"termly":    {"TERMLY_"},
		"iubenda":   {"IUBENDA_"},
	}

	// Check env files at root
	for _, envFile := range envFiles {
		path := filepath.Join(rootDir, envFile)
		scanEnvFile(path, envPatterns, services)
	}

	// Check env files in monorepo subdirectories
	monorepoRoots := []string{"apps", "packages", "services"}
	for _, monoRoot := range monorepoRoots {
		monoDir := filepath.Join(rootDir, monoRoot)
		entries, err := os.ReadDir(monoDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, envFile := range envFiles {
				path := filepath.Join(monoDir, entry.Name(), envFile)
				scanEnvFile(path, envPatterns, services)
			}
		}
	}

	return services
}

func scanEnvFile(path string, envPatterns map[string][]string, services map[string]bool) {
	file, err := os.Open(path)
	if err != nil {
		return
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

func detectAnalyticsScripts(rootDir string, services map[string]bool) {
	// Patterns for detecting services in code/template content
	// These are intentionally specific to avoid false positives - require URLs, SDK imports, or API calls
	patterns := map[string]*regexp.Regexp{
		// Analytics - look for script URLs or specific SDK patterns
		"plausible":        regexp.MustCompile(`(?i)plausible\.io/js/|plausible\.io/api`),
		"fathom":           regexp.MustCompile(`(?i)cdn\.usefathom\.com|script\.src.*fathom`),
		"fullres":          regexp.MustCompile(`(?i)window\.fullres|var fullres|fullres\.events`),
		"datafast":         regexp.MustCompile(`(?i)datafa\.st/js/`),
		"google_analytics": regexp.MustCompile(`(?i)googletagmanager\.com|google-analytics\.com/|gtag\(['"]|monsterinsights`),
		"posthog":          regexp.MustCompile(`(?i)posthog\.com|us\.i\.posthog\.com|eu\.i\.posthog\.com|posthog\.init`),
		"hotjar":           regexp.MustCompile(`(?i)static\.hotjar\.com|hotjar\.com/`),
		"mixpanel":         regexp.MustCompile(`(?i)cdn\.mxpnl\.com|mixpanel\.com/|mixpanel\.init`),
		"segment":          regexp.MustCompile(`(?i)cdn\.segment\.com|analytics\.load\(`),
		"amplitude":        regexp.MustCompile(`(?i)cdn\.amplitude\.com|amplitude\.getInstance`),

		// Communication - require specific URLs or SDK
		"intercom": regexp.MustCompile(`(?i)widget\.intercom\.io|Intercom\(['"]|intercom-client`),
		"crisp":    regexp.MustCompile(`(?i)client\.crisp\.chat|CRISP_WEBSITE_ID`),
		"twilio":   regexp.MustCompile(`(?i)twilio\.com|@twilio/|twilio-node`),
		"slack":    regexp.MustCompile(`(?i)@slack/|slack-ruby|api\.slack\.com|hooks\.slack\.com`),
		"discord":  regexp.MustCompile(`(?i)discord\.js|discordrb|discord\.py|disnake|discord\.com/api`),

		// Payments - only match SDK imports or API URLs, not the word itself
		"stripe":       regexp.MustCompile(`(?i)js\.stripe\.com|Stripe\(['"]|stripe/stripe-`),
		"paypal":       regexp.MustCompile(`(?i)paypal\.com/sdk|paypalobjects\.com|@paypal/`),
		"paddle":       regexp.MustCompile(`(?i)cdn\.paddle\.com|Paddle\.Setup|paddle\.com/paddlejs`),
		"lemonsqueezy": regexp.MustCompile(`(?i)lemonsqueezy\.com|@lemonsqueezy/`),

		// Error tracking - require DSN patterns or SDK
		"sentry":      regexp.MustCompile(`(?i)@sentry/|sentry\.io/|Sentry\.init|dsn.*sentry`),
		"bugsnag":     regexp.MustCompile(`(?i)bugsnag\.com|@bugsnag/|Bugsnag\.start`),
		"rollbar":     regexp.MustCompile(`(?i)rollbar\.com/js|Rollbar\.init|@rollbar/`),
		"honeybadger": regexp.MustCompile(`(?i)@honeybadger-io/|honeybadger\.io/`),
		"datadog":     regexp.MustCompile(`(?i)datadoghq\.com|dd-trace|@datadog/`),
		"newrelic":    regexp.MustCompile(`(?i)newrelic\.com/|@newrelic/`),
		"logrocket":   regexp.MustCompile(`(?i)cdn\.logrocket\.com|LogRocket\.init`),

		// Email - require SDK or API patterns
		"postmark":   regexp.MustCompile(`(?i)postmarkapp\.com|@postmark/|postmark-client`),
		"sendgrid":   regexp.MustCompile(`(?i)@sendgrid/|sendgrid\.com/`),
		"mailgun":    regexp.MustCompile(`(?i)mailgun\.com/|mailgun-js|@mailgun/`),
		"aws_ses":    regexp.MustCompile(`(?i)ses\.amazonaws\.com|@aws-sdk/client-ses|aws-sdk-ses|craft-amazon-ses`),
		"resend":     regexp.MustCompile(`(?i)api\.resend\.com|@resend/`),
		"mailchimp":  regexp.MustCompile(`(?i)mailchimp\.com/|@mailchimp/|mailchimp-for-wp|mc4wp|list-manage\.com`),
		"convertkit":      regexp.MustCompile(`(?i)convertkit\.com|@convertkit/|app\.kit\.com`),
		"beehiiv":         regexp.MustCompile(`(?i)beehiiv\.com|embeds\.beehiiv\.com`),
		"aweber":          regexp.MustCompile(`(?i)aweber\.com|forms\.aweber\.com`),
		"activecampaign":  regexp.MustCompile(`(?i)activecampaign\.com|trackcmp\.net`),
		"campaignmonitor": regexp.MustCompile(`(?i)campaignmonitor\.com|createsend\.com`),
		"drip":            regexp.MustCompile(`(?i)getdrip\.com|api\.getdrip\.com|tag\.getdrip\.com`),
		"klaviyo":         regexp.MustCompile(`(?i)klaviyo\.com|static\.klaviyo\.com/onsite/js/klaviyo`),
		"buttondown":      regexp.MustCompile(`(?i)buttondown\.email|buttondown\.com`),

		// Auth - require SDK patterns
		"auth0":    regexp.MustCompile(`(?i)@auth0/|auth0\.com/`),
		"clerk":    regexp.MustCompile(`(?i)@clerk/|clerk\.com/`),
		"workos":   regexp.MustCompile(`(?i)@workos/|workos\.com/|api\.workos\.com`),
		"firebase": regexp.MustCompile(`(?i)firebase\.google\.com|firebaseapp\.com|@firebase/`),
		"supabase": regexp.MustCompile(`(?i)supabase\.co|@supabase/`),

		// Infrastructure - require specific connection patterns
		"redis":         regexp.MustCompile(`(?i)redis://|rediss://|Redis\.new|ioredis`),
		"sidekiq":       regexp.MustCompile(`(?i)Sidekiq::Worker|include Sidekiq|sidekiq\.yml`),
		"rabbitmq":      regexp.MustCompile(`(?i)amqp://|amqps://|rabbitmq\.com|@rabbitmq/`),
		"elasticsearch": regexp.MustCompile(`(?i)@elastic/elasticsearch|elasticsearch\.org`),
		"convex":        regexp.MustCompile(`(?i)convex\.dev|@convex/|convex/_generated`),

		// Storage/CDN - require API URLs
		"aws_s3":     regexp.MustCompile(`(?i)s3\.amazonaws\.com|@aws-sdk/client-s3`),
		"cloudinary": regexp.MustCompile(`(?i)cloudinary\.com/|@cloudinary/`),
		"cloudflare": regexp.MustCompile(`(?i)cdn\.cloudflare\.com|@cloudflare/|cloudflare-workers`),

		// Search - require SDK
		"algolia": regexp.MustCompile(`(?i)algolia\.com/|@algolia/|algoliasearch`),

		// AI - require SDK or API patterns
		"openai":      regexp.MustCompile(`(?i)api\.openai\.com|openai\.ChatCompletion|from openai|openai\.create`),
		"anthropic":   regexp.MustCompile(`(?i)api\.anthropic\.com|anthropic\.Anthropic|from anthropic|@anthropic/`),
		"google_ai":   regexp.MustCompile(`(?i)@google/generative-ai|generativelanguage\.googleapis\.com|gemini-pro|gemini-1\.5`),
		"mistral":     regexp.MustCompile(`(?i)api\.mistral\.ai|@mistralai/`),
		"cohere":      regexp.MustCompile(`(?i)api\.cohere\.ai|cohere\.Client|cohere-ai`),
		"replicate":   regexp.MustCompile(`(?i)api\.replicate\.com|replicate\.run`),
		"huggingface": regexp.MustCompile(`(?i)huggingface\.co/|@huggingface/`),
		"grok":        regexp.MustCompile(`(?i)api\.x\.ai|xai/grok|grok-beta`),
		"perplexity":  regexp.MustCompile(`(?i)perplexity\.ai|pplx-api`),
		"together_ai": regexp.MustCompile(`(?i)together\.ai|@together-ai/|api\.together\.xyz`),

		// SEO - require actual API usage, not just the word
		"indexnow": regexp.MustCompile(`(?i)api\.indexnow\.org|indexnow\.org/key|indexnow-js|indexnow-sdk`),

		// Cookie Consent - require script URLs or SDK
		"cookieconsent": regexp.MustCompile(`(?i)cdn\.jsdelivr\.net.*cookieconsent|cookieconsent\.js|osano.*cookieconsent|CookieConsent\.run`),
		"cookiebot":     regexp.MustCompile(`(?i)consent\.cookiebot\.com|Cookiebot|cookiebot\.js`),
		"onetrust":      regexp.MustCompile(`(?i)cdn\.cookielaw\.org|optanon|OneTrust|onetrust\.com`),
		"termly":        regexp.MustCompile(`(?i)app\.termly\.io|termly\.js|Termly\.initialize`),
		"cookieyes":     regexp.MustCompile(`(?i)cdn-cookieyes\.com|cookieyes\.com|CookieYes`),
		"iubenda":       regexp.MustCompile(`(?i)cdn\.iubenda\.com|iubenda\.com/cs|_iub\.csConfiguration`),
	}

	// Regex to find script src URLs
	scriptSrcRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

	// File extensions to scan
	codeExts := map[string]bool{
		// Templates
		".html":   true,
		".htm":    true,
		".erb":    true,
		".twig":   true,
		".blade":  true,
		".vue":    true,
		".svelte": true,
		".astro":  true,
		// Code
		".php":  true,
		".tsx":  true,
		".ts":   true,
		".jsx":  true,
		".js":   true,
		".rb":   true,
		".py":   true,
		".go":   true,
		".rs":   true,
		".java": true,
		".cs":   true,
		// Config
		".yaml": true,
		".yml":  true,
		".toml": true,
	}

	// Directories to skip
	skipDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		"dist":         true,
		"build":        true,
		".next":        true,
		".nuxt":        true,
		"coverage":     true,
		"__pycache__":  true,
		".cache":       true,
		"tmp":          true,
		"log":          true,
		"logs":         true,
		"storage":      true,      // Laravel/Craft CMS storage (backups, logs, etc.)
		"cpresources":  true,      // Craft CMS control panel assets
		"web":          true,      // Common public web root (contains compiled assets)
		"public":       true,      // Common public web root
	}

	// Collect external script URLs to fetch
	var externalScripts []string

	// Walk the entire project directory
	filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files/dirs we can't access
		}

		// Skip ignored directories
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if !codeExts[ext] {
			return nil
		}

		// Skip files larger than 1MB to avoid slowdown
		info, err := d.Info()
		if err != nil || info.Size() > 1024*1024 {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Check content for known patterns
		for service, pattern := range patterns {
			if pattern.Match(content) {
				services[service] = true
			}
		}

		// Extract external script URLs from HTML-like files
		if ext == ".html" || ext == ".htm" || ext == ".erb" || ext == ".twig" ||
			ext == ".php" || ext == ".vue" || ext == ".svelte" || ext == ".astro" ||
			ext == ".tsx" || ext == ".jsx" {
			matches := scriptSrcRe.FindAllSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					src := string(match[1])
					// Only fetch http/https URLs (not relative paths)
					if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
						externalScripts = append(externalScripts, src)
					}
				}
			}
		}

		return nil
	})

	// Fetch and check external scripts (limit to avoid slowdown)
	if len(externalScripts) > 0 {
		// Use a subset of patterns for external scripts (mainly analytics)
		analyticsPatterns := map[string]*regexp.Regexp{
			"plausible":        patterns["plausible"],
			"fathom":           patterns["fathom"],
			"fullres":          patterns["fullres"],
			"datafast":         patterns["datafast"],
			"google_analytics": patterns["google_analytics"],
			"posthog":          patterns["posthog"],
			"hotjar":           patterns["hotjar"],
			"mixpanel":         patterns["mixpanel"],
			"segment":          patterns["segment"],
			"intercom":         patterns["intercom"],
			"crisp":            patterns["crisp"],
		}
		detectServicesFromExternalScripts(externalScripts, services, analyticsPatterns)
	}
}

func detectServicesFromExternalScripts(urls []string, services map[string]bool, patterns map[string]*regexp.Regexp) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Limit to first 10 scripts to avoid slowdown
	maxScripts := 10
	if len(urls) > maxScripts {
		urls = urls[:maxScripts]
	}

	// Overall timeout for all external script checking
	overallDeadline := time.Now().Add(15 * time.Second)

	fmt.Print("Checking external scripts")

	for _, url := range urls {
		// Check if we've exceeded overall timeout
		if time.Now().After(overallDeadline) {
			fmt.Println(" (timeout)")
			return
		}

		fmt.Print(".")

		resp, err := client.Get(url)
		if err != nil {
			// Check if it was a timeout
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
				// Extract domain for cleaner message
				domain := extractDomain(url)
				fmt.Printf("\n  ⚠️  %s timed out", domain)
			}
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}

		// Read up to 100KB of the script
		body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		content := strings.ToLower(string(body))

		// Check for service patterns in the script content
		for service, pattern := range patterns {
			if pattern.MatchString(content) {
				services[service] = true
			}
		}
	}

	fmt.Println(" done")
}

func extractDomain(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	// Get just the domain part
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	return url
}

func fileExists(rootDir, relativePath string) bool {
	path := filepath.Join(rootDir, relativePath)
	_, err := os.Stat(path)
	return err == nil
}

// detectIndexNowKeyFile checks for IndexNow key files (32-char hex .txt files) in web roots
func detectIndexNowKeyFile(rootDir string, services map[string]bool) {
	webRoots := []string{"public", "web", "static", "_site", "dist", ""}
	hexPattern := regexp.MustCompile(`^[a-f0-9]{32}\.txt$`)

	for _, root := range webRoots {
		dir := filepath.Join(rootDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && hexPattern.MatchString(entry.Name()) {
				// Found an IndexNow key file
				services["indexnow"] = true
				return
			}
		}
	}
}
