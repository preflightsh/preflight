package output

import (
	"fmt"
	"strings"

	"github.com/preflightsh/preflight/internal/checks"
)

// Colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

type HumanOutputter struct{}

func (h HumanOutputter) Output(projectName string, results []checks.CheckResult) {
	// Header
	fmt.Println()
	fmt.Printf("%s%s ✈  Preflight Scan Results%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s   Project: %s%s\n", colorGray, projectName, colorReset)
	fmt.Println()

	// Category icons
	categoryIcons := map[string]string{
		"ENV":       "📋",
		"HEALTH":    "💓",
		"PAYMENTS":  "💳",
		"ERRORS":    "🐛",
		"ANALYTICS": "📊",
		"INFRA":     "🔧",
		"JOBS":      "⚡",
		"SEO":       "🔍",
		"SECURITY":  "🔒",
		"SECRETS":   "🔑",
		"AI":        "🤖",
		"EMAIL":     "📧",
		"AUTH":      "🔐",
		"STORAGE":   "📦",
		"SEARCH":    "🔎",
		"CHAT":      "💬",
		"NOTIFY":    "🔔",
		"SOCIAL":    "📱",
		"ICONS":     "🎨",
		"FILES":     "📄",
		"SSL":       "🔐",
		"LICENSE":   "📜",
		"DEPS":      "📦",
		"INDEXNOW":  "🔗",
		"MOBILE":    "📱",
		"LANG":      "🌐",
		"PAGES":     "📃",
		"DEBUG":     "🐞",
		"PERF":      "⚡",
		"LEGAL":     "⚖️ ",
	}

	// Map check IDs to display categories
	categoryMap := map[string]string{
		"envParity":            "ENV",
		"healthEndpoint":       "HEALTH",
		"seoMeta":              "SEO",
		"ogTwitter":            "SOCIAL",
		"securityHeaders":      "SECURITY",
		"ssl":                  "SSL",
		"secrets":              "SECRETS",
		"favicon":              "ICONS",
		"robotsTxt":            "FILES",
		"sitemap":              "FILES",
		"llmsTxt":              "FILES",
		"adsTxt":               "FILES",
		"humansTxt":            "FILES",
		"license":              "LICENSE",
		"vulnerability":        "DEPS",
		"indexNow":             "INDEXNOW",
		"canonical":            "SEO",
		"viewport":             "MOBILE",
		"lang":                 "LANG",
		"error_pages":          "PAGES",
		"debug_statements":     "DEBUG",
		"structured_data":      "SEO",
		"image_optimization":   "PERF",
		"email_auth":           "EMAIL",
		"www_redirect":         "INFRA",
		"legal_pages":          "LEGAL",
	}

	// Service check IDs - these will be grouped separately
	serviceCheckIDs := map[string]bool{
		// Payments
		"stripe": true, "paypal": true, "braintree": true, "paddle": true, "lemonsqueezy": true,
		// Error Tracking
		"sentry": true, "bugsnag": true, "rollbar": true, "honeybadger": true, "datadog": true, "newrelic": true, "logrocket": true,
		// Email
		"postmark": true, "sendgrid": true, "mailgun": true, "aws_ses": true, "resend": true,
		"mailchimp": true, "convertkit": true, "beehiiv": true, "aweber": true, "activecampaign": true,
		"campaignmonitor": true, "drip": true, "klaviyo": true, "buttondown": true,
		// Analytics
		"plausible": true, "fathom": true, "google_analytics": true, "fullres": true, "datafast": true,
		"posthog": true, "mixpanel": true, "amplitude": true, "segment": true, "hotjar": true,
		// Auth
		"auth0": true, "clerk": true, "workos": true, "firebase": true, "supabase": true,
		// Communication
		"twilio": true, "slack": true, "discord": true, "intercom": true, "crisp": true,
		// Infrastructure
		"redis": true, "sidekiq": true, "rabbitmq": true, "elasticsearch": true, "convex": true,
		// Storage & CDN
		"aws_s3": true, "cloudinary": true, "cloudflare": true,
		// Search
		"algolia": true,
		// AI
		"openai": true, "anthropic": true, "google_ai": true, "mistral": true, "cohere": true,
		"replicate": true, "huggingface": true, "grok": true, "perplexity": true, "together_ai": true,
		// Cookie Consent
		"cookieconsent": true, "cookiebot": true, "onetrust": true, "termly": true, "cookieyes": true, "iubenda": true,
		// SEO
		"indexNow": true,
	}

	// Service category mapping
	serviceCategoryMap := map[string]string{
		// Payments
		"stripe": "PAYMENTS", "paypal": "PAYMENTS", "braintree": "PAYMENTS", "paddle": "PAYMENTS", "lemonsqueezy": "PAYMENTS",
		// Error Tracking
		"sentry": "ERRORS", "bugsnag": "ERRORS", "rollbar": "ERRORS", "honeybadger": "ERRORS",
		"datadog": "ERRORS", "newrelic": "ERRORS", "logrocket": "ERRORS",
		// Email
		"postmark": "EMAIL", "sendgrid": "EMAIL", "mailgun": "EMAIL", "aws_ses": "EMAIL", "resend": "EMAIL",
		"mailchimp": "EMAIL", "convertkit": "EMAIL", "beehiiv": "EMAIL", "aweber": "EMAIL",
		"activecampaign": "EMAIL", "campaignmonitor": "EMAIL", "drip": "EMAIL", "klaviyo": "EMAIL", "buttondown": "EMAIL",
		// Analytics
		"plausible": "ANALYTICS", "fathom": "ANALYTICS", "google_analytics": "ANALYTICS", "fullres": "ANALYTICS", "datafast": "ANALYTICS",
		"posthog": "ANALYTICS", "mixpanel": "ANALYTICS", "amplitude": "ANALYTICS", "segment": "ANALYTICS", "hotjar": "ANALYTICS",
		// Auth
		"auth0": "AUTH", "clerk": "AUTH", "workos": "AUTH", "firebase": "AUTH", "supabase": "AUTH",
		// Communication
		"twilio": "NOTIFY", "slack": "NOTIFY", "discord": "NOTIFY", "intercom": "CHAT", "crisp": "CHAT",
		// Infrastructure
		"redis": "INFRA", "sidekiq": "JOBS", "rabbitmq": "JOBS", "elasticsearch": "SEARCH", "convex": "INFRA",
		// Storage & CDN
		"aws_s3": "STORAGE", "cloudinary": "STORAGE", "cloudflare": "INFRA",
		// Search
		"algolia": "SEARCH",
		// AI
		"openai": "AI", "anthropic": "AI", "google_ai": "AI", "mistral": "AI", "cohere": "AI",
		"replicate": "AI", "huggingface": "AI", "grok": "AI", "perplexity": "AI", "together_ai": "AI",
		// Cookie Consent
		"cookieconsent": "LEGAL", "cookiebot": "LEGAL", "onetrust": "LEGAL", "termly": "LEGAL", "cookieyes": "LEGAL", "iubenda": "LEGAL",
		// SEO
		"indexNow": "INDEXNOW",
	}

	// Separate results into non-service checks and service checks
	var coreResults []checks.CheckResult
	var serviceResults []checks.CheckResult
	for _, r := range results {
		if serviceCheckIDs[r.ID] {
			serviceResults = append(serviceResults, r)
		} else {
			coreResults = append(coreResults, r)
		}
	}

	// Helper function to print a check result
	printResult := func(r checks.CheckResult, isLast bool, catMap map[string]string) {
		category := catMap[r.ID]
		if category == "" {
			category = strings.ToUpper(r.ID)
		}

		icon := categoryIcons[category]
		if icon == "" {
			icon = "•"
		}

		status := formatStatus(r)
		categoryLabel := fmt.Sprintf("%s  %-10s", icon, category)

		fmt.Printf("  %s %s%-45s%s %s\n", categoryLabel, colorReset, r.Title, colorReset, status)

		// Show message for failed checks, or for passed checks with useful info
		if r.Message != "" {
			if !r.Passed {
				fmt.Printf("  %s                  └─ %s%s\n", colorGray, r.Message, colorReset)
			} else if hasUsefulPassedMessage(r.Message) {
				fmt.Printf("  %s                  └─ %s%s\n", colorGray, r.Message, colorReset)
			}
		}

		// Add subtle divider between checks (except after the last one)
		if !isLast {
			fmt.Printf("  %s· · · · · · · · · · · · · · · · · · · · · · · · · · · ·%s\n", colorGray, colorReset)
		}
	}

	// Print core check results
	for i, r := range coreResults {
		isLast := i == len(coreResults)-1 && len(serviceResults) == 0
		printResult(r, isLast, categoryMap)
	}

	// Print service check results under a heading
	if len(serviceResults) > 0 {
		if len(coreResults) > 0 {
			fmt.Println()
			fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
		}
		fmt.Println()
		fmt.Printf("%s%s 🔌 Checked Services%s\n", colorBold, colorCyan, colorReset)
		fmt.Println()

		for i, r := range serviceResults {
			isLast := i == len(serviceResults)-1
			printResult(r, isLast, serviceCategoryMap)
		}
	}

	// Summary
	summary := CalculateSummary(results)
	fmt.Println()
	fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Println()

	// Summary with icons
	fmt.Printf("  %s✓ Passed:%s  %s%d%s", colorGreen, colorReset, colorBold, summary.OK, colorReset)
	if summary.Warn > 0 {
		fmt.Printf("    %s⚠ Warnings:%s %s%d%s", colorYellow, colorReset, colorBold, summary.Warn, colorReset)
	}
	if summary.Fail > 0 {
		fmt.Printf("    %s✗ Failed:%s  %s%d%s", colorRed, colorReset, colorBold, summary.Fail, colorReset)
	}
	fmt.Println()
	fmt.Println()

	// Final verdict
	if summary.Fail > 0 {
		fmt.Printf("  %s%s✗ Not ready for launch%s\n", colorBold, colorRed, colorReset)
	} else if summary.Warn > 0 {
		fmt.Printf("  %s%s⚠ Review warnings before launch%s\n", colorBold, colorYellow, colorReset)
	} else {
		fmt.Printf("  %s%s✓ Ready for launch!%s\n", colorBold, colorGreen, colorReset)
	}
	fmt.Println()
}

// hasUsefulPassedMessage returns true if the message contains info worth showing
// even when the check passed (e.g., license type, version info)
func hasUsefulPassedMessage(msg string) bool {
	// Show messages that identify specific types/versions
	usefulPatterns := []string{
		"license found",  // License type detection
		"MIT", "Apache", "GPL", "AGPL", "BSD", "ISC", "MPL",
		"(at ",           // Location info for files found in parent dirs
		"not enabled",    // Check passed because it's disabled/not configured
		"not configured", // Check passed because it's not configured
		"skipped",        // Check was skipped
		"not declared",   // Service not declared
	}

	msgLower := strings.ToLower(msg)
	for _, pattern := range usefulPatterns {
		if strings.Contains(msgLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func formatStatus(r checks.CheckResult) string {
	if r.Passed {
		return fmt.Sprintf("%s%s✓ OK%s", colorBold, colorGreen, colorReset)
	}

	switch r.Severity {
	case checks.SeverityError:
		return fmt.Sprintf("%s%s✗ FAIL%s", colorBold, colorRed, colorReset)
	case checks.SeverityWarn:
		return fmt.Sprintf("%s%s⚠ WARN%s", colorBold, colorYellow, colorReset)
	default:
		return fmt.Sprintf("%s%s⚠ WARN%s", colorBold, colorYellow, colorReset)
	}
}
