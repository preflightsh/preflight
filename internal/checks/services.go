package checks

import "github.com/preflightsh/preflight/internal/catalog"

// ServiceChecks maps each service ID in catalog.Services to the check that
// verifies it. Two catalog services deliberately have no entry: "stripe" is
// verified by StripeWebhookCheck, which is gated on its own config block
// rather than a service declaration, and "indexnow" by the indexNow core
// check. TestServiceChecksMatchCatalog enforces that this map and the
// catalog stay in step, so adding a service means touching both.
var ServiceChecks = map[string]Check{
	// Payments
	"paypal":       PayPalCheck,
	"braintree":    BraintreeCheck,
	"paddle":       PaddleCheck,
	"lemonsqueezy": LemonSqueezyCheck,
	// Error tracking and monitoring
	"sentry":      SentryCheck{},
	"bugsnag":     BugsnagCheck,
	"rollbar":     RollbarCheck,
	"honeybadger": HoneybadgerCheck,
	"datadog":     DatadogCheck,
	"newrelic":    NewRelicCheck,
	"logrocket":   LogRocketCheck,
	// Transactional email
	"postmark": PostmarkCheck{},
	"sendgrid": SendGridCheck{},
	"mailgun":  MailgunCheck{},
	"aws_ses":  AWSSESCheck{},
	"resend":   ResendCheck{},
	// Email marketing
	"mailchimp":       MailchimpCheck,
	"convertkit":      ConvertKitCheck,
	"beehiiv":         BeehiivCheck,
	"aweber":          AWeberCheck,
	"activecampaign":  ActiveCampaignCheck,
	"campaignmonitor": CampaignMonitorCheck,
	"drip":            DripCheck,
	"klaviyo":         KlaviyoCheck,
	"buttondown":      ButtondownCheck,
	// Analytics
	"plausible":        PlausibleCheck{},
	"fathom":           FathomCheck{},
	"umami":            UmamiCheck,
	"google_analytics": GoogleAnalyticsCheck{},
	"fullres":          FullresCheck,
	"datafast":         DatafastCheck,
	"posthog":          PostHogCheck,
	"mixpanel":         MixpanelCheck,
	"amplitude":        AmplitudeCheck,
	"segment":          SegmentCheck,
	"hotjar":           HotjarCheck,
	// Auth
	"auth0":    Auth0Check,
	"clerk":    ClerkCheck,
	"workos":   WorkOSCheck,
	"firebase": FirebaseCheck,
	"supabase": SupabaseCheck,
	// Communication
	"twilio":   TwilioCheck,
	"slack":    SlackCheck,
	"discord":  DiscordCheck,
	"intercom": IntercomCheck,
	"crisp":    CrispCheck,
	// Infrastructure
	"redis":         RedisCheck{},
	"sidekiq":       SidekiqCheck{},
	"rabbitmq":      RabbitMQCheck,
	"elasticsearch": ElasticsearchCheck,
	"convex":        ConvexCheck,
	// Storage and CDN
	"aws_s3":     AWSS3Check,
	"cloudinary": CloudinaryCheck,
	"cloudflare": CloudflareCheck,
	// Search
	"algolia": AlgoliaCheck,
	// AI
	"openai":      OpenAICheck,
	"anthropic":   AnthropicCheck,
	"google_ai":   GoogleAICheck,
	"mistral":     MistralCheck,
	"cohere":      CohereCheck,
	"replicate":   ReplicateCheck,
	"huggingface": HuggingFaceCheck,
	"grok":        GrokCheck,
	"perplexity":  PerplexityCheck,
	"together_ai": TogetherAICheck,
	// Cookie consent
	"cookieconsent": CookieConsentJSCheck,
	"cookiebot":     CookiebotCheck{},
	"onetrust":      OneTrustCheck{},
	"termly":        TermlyCheck{},
	"cookieyes":     CookieYesCheck{},
	"iubenda":       IubendaCheck{},
}

// KnownID reports whether id names a registered check, by its current ID
// or a pre-1.0 alias. It is the validation used by --only, --skip and
// `preflight ignore`.
func KnownID(id string) bool {
	id = catalog.Canonical(id)
	for _, c := range Registry {
		if c.ID() == id {
			return true
		}
	}
	return false
}
