// Package catalog is the single source of truth for the IDs Preflight
// exposes to users: every core check and every third-party service, with
// the display name, terminal category and one-line description each one
// needs. Before it existed the same lists were hand-maintained in six
// places (the check registry, the scan runner, config detection, init's
// display names, two maps in the terminal renderer and the `preflight
// checks` listing) and had drifted: umami was scannable but unlisted.
//
// This package deliberately has no dependency on the checks package so
// config can import it too; the checks package maps IDs to their
// implementations and a test there proves the two stay in step.
package catalog

// Check describes a core (non-service) check for listing and rendering.
type Check struct {
	// ID is what `preflight ignore`, `--only` and `--skip` accept.
	ID string
	// Category is the short label the terminal renderer prints, and the
	// key into CategoryIcons.
	Category string
	// Group is the heading `preflight checks` lists the check under.
	Group string
	// OptIn marks checks that only run when enabled in preflight.yml.
	OptIn bool
}

// Service describes a third-party integration Preflight can detect and
// verify.
type Service struct {
	ID          string
	Name        string
	Category    string
	Group       string
	Description string
}

// Checks lists every core check in the order `preflight checks` shows them.
var Checks = []Check{
	{ID: "seoMeta", Category: "SEO", Group: "SEO & Social"},
	{ID: "canonical", Category: "SEO", Group: "SEO & Social"},
	{ID: "structured_data", Category: "SEO", Group: "SEO & Social"},
	{ID: "indexNow", Category: "INDEXNOW", Group: "SEO & Social", OptIn: true},
	{ID: "ogTwitter", Category: "SOCIAL", Group: "SEO & Social"},
	{ID: "viewport", Category: "MOBILE", Group: "SEO & Social"},
	{ID: "lang", Category: "LANG", Group: "SEO & Social"},

	{ID: "securityHeaders", Category: "SECURITY", Group: "Security & Infrastructure"},
	{ID: "ssl", Category: "SSL", Group: "Security & Infrastructure"},
	{ID: "www_redirect", Category: "INFRA", Group: "Security & Infrastructure"},
	{ID: "email_auth", Category: "EMAIL", Group: "Security & Infrastructure", OptIn: true},
	{ID: "secrets", Category: "SECRETS", Group: "Security & Infrastructure"},

	{ID: "envParity", Category: "ENV", Group: "Environment & Health"},
	{ID: "healthEndpoint", Category: "HEALTH", Group: "Environment & Health"},

	{ID: "vulnerability", Category: "DEPS", Group: "Code Quality & Performance"},
	{ID: "debug_statements", Category: "DEBUG", Group: "Code Quality & Performance"},
	{ID: "error_pages", Category: "PAGES", Group: "Code Quality & Performance"},
	{ID: "image_optimization", Category: "PERF", Group: "Code Quality & Performance"},

	{ID: "legal_pages", Category: "LEGAL", Group: "Legal & Compliance"},

	{ID: "favicon", Category: "ICONS", Group: "Web Standard Files"},
	{ID: "robotsTxt", Category: "FILES", Group: "Web Standard Files"},
	{ID: "sitemap", Category: "FILES", Group: "Web Standard Files"},
	{ID: "llmsTxt", Category: "FILES", Group: "Web Standard Files"},
	{ID: "adsTxt", Category: "FILES", Group: "Web Standard Files", OptIn: true},
	{ID: "humansTxt", Category: "FILES", Group: "Web Standard Files", OptIn: true},
	{ID: "license", Category: "LICENSE", Group: "Web Standard Files", OptIn: true},
}

// Services lists every service in detection and report order. "stripe" is
// verified by a check gated on its own config block and "indexnow" by the
// indexNow core check, so neither has an entry in checks.ServiceChecks; the
// rest do.
var Services = []Service{
	// Payments
	{ID: "stripe", Name: "Stripe", Category: "PAYMENTS", Group: "Payments", Description: "Verifies API keys, webhook secret, SDK initialization"},
	{ID: "paypal", Name: "PayPal", Category: "PAYMENTS", Group: "Payments", Description: "Verifies PayPal SDK or API integration"},
	{ID: "braintree", Name: "Braintree", Category: "PAYMENTS", Group: "Payments", Description: "Verifies Braintree SDK initialization"},
	{ID: "paddle", Name: "Paddle", Category: "PAYMENTS", Group: "Payments", Description: "Verifies Paddle.js initialization"},
	{ID: "lemonsqueezy", Name: "LemonSqueezy", Category: "PAYMENTS", Group: "Payments", Description: "Verifies Lemon Squeezy SDK/API"},

	// Error tracking and monitoring
	{ID: "sentry", Name: "Sentry", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies Sentry.init() in application code"},
	{ID: "bugsnag", Name: "Bugsnag", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies Bugsnag.start() initialization"},
	{ID: "rollbar", Name: "Rollbar", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies Rollbar.init() initialization"},
	{ID: "honeybadger", Name: "Honeybadger", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies Honeybadger.configure() initialization"},
	{ID: "datadog", Name: "Datadog", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies Datadog RUM or APM initialization"},
	{ID: "newrelic", Name: "New Relic", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies New Relic browser agent or APM"},
	{ID: "logrocket", Name: "LogRocket", Category: "ERRORS", Group: "Error Tracking & Monitoring", Description: "Verifies LogRocket.init() initialization"},

	// Transactional email
	{ID: "postmark", Name: "Postmark", Category: "EMAIL", Group: "Email (Transactional)", Description: "Verifies API key in env or SDK initialization"},
	{ID: "sendgrid", Name: "SendGrid", Category: "EMAIL", Group: "Email (Transactional)", Description: "Verifies API key in env or SDK initialization"},
	{ID: "mailgun", Name: "Mailgun", Category: "EMAIL", Group: "Email (Transactional)", Description: "Verifies API key in env or SDK initialization"},
	{ID: "aws_ses", Name: "AWS SES", Category: "EMAIL", Group: "Email (Transactional)", Description: "Verifies SES configuration or SDK initialization"},
	{ID: "resend", Name: "Resend", Category: "EMAIL", Group: "Email (Transactional)", Description: "Verifies API key in env or SDK initialization"},

	// Email marketing
	{ID: "mailchimp", Name: "Mailchimp", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Mailchimp API/SDK integration"},
	{ID: "convertkit", Name: "Kit", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Kit (ConvertKit) API/forms"},
	{ID: "beehiiv", Name: "Beehiiv", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Beehiiv API integration"},
	{ID: "aweber", Name: "AWeber", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies AWeber API/forms"},
	{ID: "activecampaign", Name: "ActiveCampaign", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies ActiveCampaign API integration"},
	{ID: "campaignmonitor", Name: "Campaign Monitor", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Campaign Monitor API integration"},
	{ID: "drip", Name: "Drip", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Drip API/widget integration"},
	{ID: "klaviyo", Name: "Klaviyo", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Klaviyo API/forms integration"},
	{ID: "buttondown", Name: "Buttondown", Category: "EMAIL", Group: "Email (Marketing)", Description: "Verifies Buttondown API integration"},

	// Analytics
	{ID: "plausible", Name: "Plausible Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Plausible script tag in templates"},
	{ID: "fathom", Name: "Fathom Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Fathom script tag in templates"},
	{ID: "umami", Name: "Umami Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Umami script tag in templates"},
	{ID: "google_analytics", Name: "Google Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies GA/GTM script in templates"},
	{ID: "fullres", Name: "Fullres Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Fullres script in templates"},
	{ID: "datafast", Name: "Datafa.st Analytics", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Datafa.st script in templates"},
	{ID: "posthog", Name: "PostHog", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies posthog.init() initialization"},
	{ID: "mixpanel", Name: "Mixpanel", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies mixpanel.init() initialization"},
	{ID: "amplitude", Name: "Amplitude", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies amplitude.init() initialization"},
	{ID: "segment", Name: "Segment", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies analytics.load() initialization"},
	{ID: "hotjar", Name: "Hotjar", Category: "ANALYTICS", Group: "Analytics", Description: "Verifies Hotjar tracking code in templates"},

	// Auth
	{ID: "auth0", Name: "Auth0", Category: "AUTH", Group: "Auth", Description: "Verifies Auth0 SDK/API configuration"},
	{ID: "clerk", Name: "Clerk", Category: "AUTH", Group: "Auth", Description: "Verifies Clerk SDK initialization"},
	{ID: "workos", Name: "WorkOS", Category: "AUTH", Group: "Auth", Description: "Verifies WorkOS SDK initialization"},
	{ID: "firebase", Name: "Firebase", Category: "AUTH", Group: "Auth", Description: "Verifies Firebase Auth initialization"},
	{ID: "supabase", Name: "Supabase", Category: "AUTH", Group: "Auth", Description: "Verifies Supabase Auth configuration"},

	// Communication
	{ID: "twilio", Name: "Twilio", Category: "NOTIFY", Group: "Communication", Description: "Verifies Twilio SDK/API configuration"},
	{ID: "slack", Name: "Slack", Category: "NOTIFY", Group: "Communication", Description: "Verifies Slack API/webhook configuration"},
	{ID: "discord", Name: "Discord", Category: "NOTIFY", Group: "Communication", Description: "Verifies Discord webhook/bot configuration"},
	{ID: "intercom", Name: "Intercom", Category: "CHAT", Group: "Communication", Description: "Verifies Intercom widget initialization"},
	{ID: "crisp", Name: "Crisp", Category: "CHAT", Group: "Communication", Description: "Verifies Crisp chat widget initialization"},

	// Infrastructure
	{ID: "redis", Name: "Redis", Category: "INFRA", Group: "Infrastructure", Description: "Verifies Redis connection configuration"},
	{ID: "sidekiq", Name: "Sidekiq", Category: "JOBS", Group: "Infrastructure", Description: "Verifies Sidekiq configuration files"},
	{ID: "rabbitmq", Name: "RabbitMQ", Category: "JOBS", Group: "Infrastructure", Description: "Verifies RabbitMQ connection configuration"},
	{ID: "elasticsearch", Name: "Elasticsearch", Category: "SEARCH", Group: "Infrastructure", Description: "Verifies Elasticsearch client configuration"},
	{ID: "convex", Name: "Convex", Category: "INFRA", Group: "Infrastructure", Description: "Verifies Convex SDK initialization"},

	// Storage and CDN
	{ID: "aws_s3", Name: "AWS S3", Category: "STORAGE", Group: "Storage & CDN", Description: "Verifies AWS S3 SDK/API configuration"},
	{ID: "cloudinary", Name: "Cloudinary", Category: "STORAGE", Group: "Storage & CDN", Description: "Verifies Cloudinary SDK initialization"},
	{ID: "cloudflare", Name: "Cloudflare", Category: "INFRA", Group: "Storage & CDN", Description: "Verifies Cloudflare API configuration"},

	// Search
	{ID: "algolia", Name: "Algolia", Category: "SEARCH", Group: "Search", Description: "Verifies Algolia SDK initialization"},

	// AI
	{ID: "openai", Name: "OpenAI", Category: "AI", Group: "AI", Description: "Verifies OpenAI SDK/API configuration"},
	{ID: "anthropic", Name: "Anthropic Claude", Category: "AI", Group: "AI", Description: "Verifies Anthropic SDK/API configuration"},
	{ID: "google_ai", Name: "Google AI (Gemini)", Category: "AI", Group: "AI", Description: "Verifies Google AI (Gemini) configuration"},
	{ID: "mistral", Name: "Mistral AI", Category: "AI", Group: "AI", Description: "Verifies Mistral AI SDK configuration"},
	{ID: "cohere", Name: "Cohere", Category: "AI", Group: "AI", Description: "Verifies Cohere SDK/API configuration"},
	{ID: "replicate", Name: "Replicate", Category: "AI", Group: "AI", Description: "Verifies Replicate API configuration"},
	{ID: "huggingface", Name: "Hugging Face", Category: "AI", Group: "AI", Description: "Verifies Hugging Face API configuration"},
	{ID: "grok", Name: "Grok (X/Twitter)", Category: "AI", Group: "AI", Description: "Verifies Grok (xAI) API configuration"},
	{ID: "perplexity", Name: "Perplexity", Category: "AI", Group: "AI", Description: "Verifies Perplexity API configuration"},
	{ID: "together_ai", Name: "Together AI", Category: "AI", Group: "AI", Description: "Verifies Together AI API configuration"},

	// SEO
	{ID: "indexnow", Name: "IndexNow", Category: "INDEXNOW", Group: "SEO", Description: "Verifies the IndexNow key file (see the indexNow check)"},

	// Cookie consent
	{ID: "cookieconsent", Name: "CookieConsent", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies CookieConsent.js initialization"},
	{ID: "cookiebot", Name: "Cookiebot", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies Cookiebot script in templates"},
	{ID: "onetrust", Name: "OneTrust", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies OneTrust script in templates"},
	{ID: "termly", Name: "Termly", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies Termly script in templates"},
	{ID: "cookieyes", Name: "CookieYes", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies CookieYes script in templates"},
	{ID: "iubenda", Name: "Iubenda", Category: "LEGAL", Group: "Cookie Consent", Description: "Verifies Iubenda script in templates"},
}

// CategoryIcons maps a Category to the glyph the terminal renderer shows.
var CategoryIcons = map[string]string{
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

var (
	checkByID   = map[string]Check{}
	serviceByID = map[string]Service{}
)

func init() {
	for _, c := range Checks {
		checkByID[c.ID] = c
	}
	for _, s := range Services {
		serviceByID[s.ID] = s
	}
}

// ServiceIDs returns every service ID in Services order.
func ServiceIDs() []string {
	ids := make([]string, 0, len(Services))
	for _, s := range Services {
		ids = append(ids, s.ID)
	}
	return ids
}

// LookupCheck returns the core check with the given ID.
func LookupCheck(id string) (Check, bool) {
	c, ok := checkByID[id]
	return c, ok
}

// LookupService returns the service with the given ID.
func LookupService(id string) (Service, bool) {
	s, ok := serviceByID[id]
	return s, ok
}

// IsService reports whether id names a service rather than a core check.
func IsService(id string) bool {
	_, ok := serviceByID[id]
	return ok
}

// ServiceName returns the display name for a service ID, or the ID itself
// when it is unknown.
func ServiceName(id string) string {
	if s, ok := serviceByID[id]; ok {
		return s.Name
	}
	return id
}

// Category returns the terminal category for a check or service ID, or ""
// for an ID the catalog does not know (the renderer falls back to the
// uppercased ID so a check missing from the catalog still shows something).
func Category(id string) string {
	if c, ok := checkByID[id]; ok {
		return c.Category
	}
	if s, ok := serviceByID[id]; ok {
		return s.Category
	}
	return ""
}
