package checks

import "strings"

// serviceEnvNames lists meaningful configuration fields rather than accepting
// every string with a service prefix. Values must come from real env files.
var serviceEnvNames = map[string][]string{
	"OPENAI_": {"OPENAI_API_KEY"}, "ANTHROPIC_": {"ANTHROPIC_API_KEY"},
	"GOOGLE_AI_": {"GOOGLE_AI_API_KEY"}, "GEMINI_": {"GEMINI_API_KEY"},
	"MISTRAL_": {"MISTRAL_API_KEY"}, "COHERE_": {"COHERE_API_KEY"},
	"REPLICATE_": {"REPLICATE_API_TOKEN"}, "HUGGINGFACE_": {"HUGGINGFACE_API_TOKEN", "HUGGINGFACE_API_KEY"}, "HF_": {"HF_TOKEN"},
	"XAI_": {"XAI_API_KEY"}, "GROK_": {"GROK_API_KEY"}, "PERPLEXITY_": {"PERPLEXITY_API_KEY"}, "PPLX_": {"PPLX_API_KEY"}, "TOGETHER_": {"TOGETHER_API_KEY"},
	"POSTMARK_": {"POSTMARK_API_TOKEN", "POSTMARK_SERVER_TOKEN"}, "SENDGRID_": {"SENDGRID_API_KEY"}, "MAILGUN_": {"MAILGUN_API_KEY", "MAILGUN_SECRET"}, "RESEND_": {"RESEND_API_KEY"},
	"AWS_SES_": {"AWS_SES_ACCESS_KEY_ID", "AWS_SES_API_KEY", "AWS_SES_REGION"}, "SES_REGION": {"SES_REGION"},
	"AWS_": {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, "S3_": {"S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_ENDPOINT"},
	"PAYPAL_": {"PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET"}, "BRAINTREE_": {"BRAINTREE_MERCHANT_ID", "BRAINTREE_PRIVATE_KEY"}, "PADDLE_": {"PADDLE_API_KEY", "PADDLE_VENDOR_ID", "PADDLE_CLIENT_TOKEN"},
	"LEMONSQUEEZY_": {"LEMONSQUEEZY_API_KEY"}, "LEMON_SQUEEZY_": {"LEMON_SQUEEZY_API_KEY"},
	"AUTH0_": {"AUTH0_DOMAIN", "AUTH0_CLIENT_ID"}, "CLERK_": {"CLERK_SECRET_KEY", "CLERK_PUBLISHABLE_KEY"}, "NEXT_PUBLIC_CLERK": {"CLERK_PUBLISHABLE_KEY"},
	"WORKOS_": {"WORKOS_API_KEY", "WORKOS_CLIENT_ID"}, "FIREBASE_": {"FIREBASE_API_KEY", "FIREBASE_PROJECT_ID"}, "NEXT_PUBLIC_FIREBASE": {"FIREBASE_API_KEY", "FIREBASE_PROJECT_ID"},
	"SUPABASE_": {"SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"}, "NEXT_PUBLIC_SUPABASE": {"SUPABASE_URL", "SUPABASE_ANON_KEY"},
	"TWILIO_": {"TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"}, "SLACK_": {"SLACK_WEBHOOK_URL", "SLACK_TOKEN", "SLACK_BOT_TOKEN"}, "DISCORD_": {"DISCORD_TOKEN", "DISCORD_WEBHOOK_URL"},
	"INTERCOM_": {"INTERCOM_APP_ID"}, "CRISP_": {"CRISP_WEBSITE_ID"}, "RABBITMQ_": {"RABBITMQ_URL"}, "AMQP_": {"AMQP_URL"}, "CLOUDAMQP_": {"CLOUDAMQP_URL"},
	"ELASTICSEARCH_": {"ELASTICSEARCH_URL", "ELASTICSEARCH_HOST"}, "ELASTIC_": {"ELASTIC_URL", "ELASTIC_CLOUD_ID", "ELASTIC_API_KEY"},
	"CONVEX_": {"CONVEX_URL", "CONVEX_DEPLOYMENT"}, "NEXT_PUBLIC_CONVEX": {"CONVEX_URL"}, "CLOUDINARY_": {"CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME"},
	"CLOUDFLARE_": {"CLOUDFLARE_API_TOKEN"}, "CF_": {"CF_API_TOKEN"}, "ALGOLIA_": {"ALGOLIA_APP_ID", "ALGOLIA_API_KEY"},
	"MAILCHIMP_": {"MAILCHIMP_API_KEY"}, "CONVERTKIT_": {"CONVERTKIT_API_KEY"}, "KIT_": {"KIT_API_KEY"}, "BEEHIIV_": {"BEEHIIV_API_KEY"}, "AWEBER_": {"AWEBER_CLIENT_ID", "AWEBER_ACCESS_TOKEN"},
	"ACTIVECAMPAIGN_": {"ACTIVECAMPAIGN_API_KEY"}, "AC_API": {"AC_API_KEY", "AC_API_URL"}, "CAMPAIGNMONITOR_": {"CAMPAIGNMONITOR_API_KEY"}, "CREATESEND_": {"CREATESEND_API_KEY"},
	"DRIP_": {"DRIP_API_TOKEN", "DRIP_API_KEY"}, "KLAVIYO_": {"KLAVIYO_API_KEY"}, "BUTTONDOWN_": {"BUTTONDOWN_API_KEY"},
	"COOKIEBOT_": {"COOKIEBOT_CBID"}, "ONETRUST_": {"ONETRUST_DOMAIN_SCRIPT"}, "TERMLY_": {"TERMLY_WEBSITE_UUID", "TERMLY_ID"}, "COOKIEYES_": {"COOKIEYES_ID"}, "IUBENDA_": {"IUBENDA_SITE_ID"},
}

func envAssignment(line string) (name, value string, ok bool) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
	if strings.HasPrefix(line, "#") {
		return "", "", false
	}
	name, value, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, prefix := range []string{"NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_"} {
		name = strings.TrimPrefix(name, prefix)
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
		quote := value[0]
		if end := strings.IndexByte(value[1:], quote); end >= 0 {
			value = value[1 : end+1]
		} else {
			return "", "", false
		}
	} else {
		if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
	}
	return name, value, name != ""
}

func meaningfulEnvValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, hint := range []string{"your_", "your-", "placeholder", "changeme", "replace_me", "${"} {
		if strings.Contains(lower, hint) {
			return false
		}
	}
	return true
}
