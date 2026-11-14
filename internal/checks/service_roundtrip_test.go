package checks

import (
	"sort"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// runDeclaredService runs the check for one service against root, with only
// that service declared and no URLs configured.
func runDeclaredService(t *testing.T, root, id, stack string) CheckResult {
	t.Helper()
	check := ServiceChecks[id]
	if id == "stripe" {
		check = StripeWebhookCheck{}
	}
	if check == nil {
		t.Fatalf("no check for service %q", id)
	}
	res, err := check.Run(Context{
		RootDir: root,
		Config: &config.PreflightConfig{
			Stack:    stack,
			Services: map[string]config.ServiceConfig{id: {Declared: true}},
		},
	})
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return res
}

// roundTripEnv: env names `preflight init` declares each service from
// (detectServicesFromEnv), written the way a project would.
var roundTripEnv = map[string][]string{
	"paypal": {"PAYPAL_CLIENT_ID"}, "braintree": {"BRAINTREE_MERCHANT_ID"}, "paddle": {"PADDLE_API_KEY"},
	"lemonsqueezy": {"LEMONSQUEEZY_API_KEY", "LEMON_SQUEEZY_API_KEY"},
	"sentry":       {"SENTRY_DSN"}, "bugsnag": {"BUGSNAG_API_KEY"}, "rollbar": {"ROLLBAR_ACCESS_TOKEN"},
	"honeybadger": {"HONEYBADGER_API_KEY"}, "datadog": {"DD_API_KEY", "DATADOG_API_KEY"},
	"newrelic": {"NEW_RELIC_LICENSE_KEY", "NEWRELIC_KEY"}, "logrocket": {"LOGROCKET_APP_ID"},
	"postmark": {"POSTMARK_API_TOKEN"}, "sendgrid": {"SENDGRID_API_KEY"}, "mailgun": {"MAILGUN_DOMAIN"},
	"aws_ses": {"AWS_SES_REGION", "SES_REGION"}, "resend": {"RESEND_API_KEY"},
	"mailchimp": {"MAILCHIMP_API_KEY"}, "convertkit": {"CONVERTKIT_API_KEY", "KIT_API_KEY", "KIT_FORM_ID"},
	"beehiiv": {"BEEHIIV_API_KEY"}, "aweber": {"AWEBER_CLIENT_ID"}, "activecampaign": {"ACTIVECAMPAIGN_URL", "AC_API_KEY"},
	"campaignmonitor": {"CAMPAIGNMONITOR_API_KEY", "CAMPAIGN_MONITOR_API_KEY", "CREATESEND_API_KEY"},
	"drip":            {"DRIP_API_TOKEN"}, "klaviyo": {"KLAVIYO_API_KEY"}, "buttondown": {"BUTTONDOWN_API_KEY"},
	"plausible": {"PLAUSIBLE_DOMAIN", "NEXT_PUBLIC_PLAUSIBLE_DOMAIN"}, "fathom": {"FATHOM_SITE_ID", "NEXT_PUBLIC_FATHOM_ID"},
	"umami": {"UMAMI_WEBSITE_ID", "NEXT_PUBLIC_UMAMI_ID"}, "fullres": {"FULLRES_ID"}, "datafast": {"DATAFAST_ID"},
	"google_analytics": {"GA_TRACKING_ID", "GOOGLE_ANALYTICS_ID", "NEXT_PUBLIC_GA_ID", "GA_MEASUREMENT_ID", "GTM_ID"},
	"posthog":          {"POSTHOG_KEY", "NEXT_PUBLIC_POSTHOG_KEY"}, "mixpanel": {"MIXPANEL_TOKEN"},
	"amplitude": {"AMPLITUDE_API_KEY"}, "segment": {"SEGMENT_WRITE_KEY"}, "hotjar": {"HOTJAR_ID"},
	"auth0": {"AUTH0_DOMAIN"}, "clerk": {"CLERK_SECRET_KEY", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"},
	"workos": {"WORKOS_API_KEY"}, "firebase": {"FIREBASE_API_KEY", "NEXT_PUBLIC_FIREBASE_API_KEY"},
	"supabase": {"SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL"},
	"twilio":   {"TWILIO_ACCOUNT_SID"}, "slack": {"SLACK_WEBHOOK_URL"}, "discord": {"DISCORD_TOKEN"},
	"intercom": {"INTERCOM_APP_ID"}, "crisp": {"CRISP_WEBSITE_ID"},
	"redis":   {"REDIS_URL", "REDIS_HOST", "REDISCLOUD_URL", "UPSTASH_REDIS_REST_URL"},
	"sidekiq": {"SIDEKIQ_CONCURRENCY"}, "rabbitmq": {"RABBITMQ_URL", "AMQP_URL", "CLOUDAMQP_URL"},
	"elasticsearch": {"ELASTICSEARCH_URL", "ELASTIC_CLOUD_ID"}, "convex": {"CONVEX_DEPLOYMENT", "NEXT_PUBLIC_CONVEX_URL"},
	"aws_s3": {"AWS_S3_BUCKET", "S3_BUCKET", "AWS_BUCKET"}, "cloudinary": {"CLOUDINARY_URL"},
	"cloudflare": {"CLOUDFLARE_API_TOKEN"}, "algolia": {"ALGOLIA_APP_ID"},
	"openai": {"OPENAI_API_KEY"}, "anthropic": {"ANTHROPIC_API_KEY", "CLAUDE_API_KEY"},
	"google_ai": {"GOOGLE_AI_API_KEY", "GEMINI_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"},
	"mistral":   {"MISTRAL_API_KEY"}, "cohere": {"COHERE_API_KEY", "CO_API_KEY"}, "replicate": {"REPLICATE_API_TOKEN"},
	"huggingface": {"HUGGINGFACE_API_KEY", "HF_TOKEN", "HF_API_TOKEN"}, "grok": {"GROK_API_KEY", "XAI_API_KEY"},
	"perplexity": {"PERPLEXITY_API_KEY", "PPLX_API_KEY"}, "together_ai": {"TOGETHER_API_KEY", "TOGETHER_AI_KEY"},
	"cookiebot": {"COOKIEBOT_CBID"}, "onetrust": {"ONETRUST_DOMAIN_SCRIPT"}, "termly": {"TERMLY_ID"}, "iubenda": {"IUBENDA_SITE_ID"},
}

func pkgJSON(dep string) [2]string {
	return [2]string{"package.json", `{"name":"app","dependencies":{"` + dep + `":"^1.0.0"}}`}
}

func composerJSON(dep string) [2]string {
	return [2]string{"composer.json", `{"name":"acme/app","require":{"` + dep + `":"^1.0"}}`}
}

func gemfile(gem string) [2]string {
	return [2]string{"Gemfile", "source \"https://rubygems.org\"\ngem \"" + gem + "\"\n"}
}

// roundTripDeps: a dependency `preflight init` declares each service from
// (detectServicesFromContent), as the manifest and its content.
var roundTripDeps = map[string][2]string{
	"paypal": pkgJSON("@paypal/react-paypal-js"), "braintree": pkgJSON("braintree"), "paddle": pkgJSON("@paddle/paddle-js"),
	"lemonsqueezy": pkgJSON("@lemonsqueezy/lemonsqueezy.js"),
	"sentry":       pkgJSON("@sentry/nextjs"), "bugsnag": gemfile("bugsnag"), "rollbar": pkgJSON("rollbar"),
	"honeybadger": gemfile("honeybadger"), "datadog": gemfile("datadog"), "newrelic": gemfile("newrelic_rpm"),
	"logrocket": pkgJSON("logrocket"),
	"postmark":  composerJSON("wildbit/postmark-php"), "sendgrid": pkgJSON("@sendgrid/mail"),
	"mailgun": composerJSON("mailgun/mailgun-php"), "aws_ses": composerJSON("putyourlightson/craft-amazon-ses"),
	"resend": pkgJSON("resend"), "mailchimp": pkgJSON("@mailchimp/mailchimp_marketing"),
	"convertkit": pkgJSON("convertkit-react"), "beehiiv": pkgJSON("@beehiiv/sdk"), "aweber": pkgJSON("aweber-api"),
	"activecampaign": pkgJSON("activecampaign"), "campaignmonitor": gemfile("createsend"), "drip": gemfile("getdrip"),
	"klaviyo": pkgJSON("klaviyo-api"), "buttondown": pkgJSON("buttondown"),
	"plausible": pkgJSON("plausible-tracker"), "fathom": pkgJSON("fathom-client"), "umami": pkgJSON("@umami/node"),
	"fullres": pkgJSON("fullres"), "datafast": pkgJSON("datafast"), "google_analytics": pkgJSON("react-ga4"),
	"posthog": pkgJSON("posthog-js"), "mixpanel": pkgJSON("mixpanel-browser"),
	"amplitude": pkgJSON("@amplitude/analytics-browser"), "segment": pkgJSON("@segment/analytics-next"),
	"hotjar": pkgJSON("@hotjar/browser"),
	"auth0":  pkgJSON("@auth0/nextjs-auth0"), "clerk": pkgJSON("@clerk/nextjs"), "workos": pkgJSON("@workos-inc/node"),
	"firebase": pkgJSON("firebase"), "supabase": pkgJSON("@supabase/supabase-js"),
	"twilio": pkgJSON("twilio"), "slack": pkgJSON("@slack/web-api"), "discord": pkgJSON("discord.js"),
	"intercom": pkgJSON("intercom-client"), "crisp": pkgJSON("crisp-sdk-web"),
	"redis": composerJSON("predis/predis"), "sidekiq": gemfile("sidekiq"), "rabbitmq": pkgJSON("amqplib"),
	"elasticsearch": pkgJSON("@elastic/elasticsearch"), "convex": pkgJSON("convex"),
	"aws_s3": pkgJSON("@aws-sdk/client-s3"), "cloudinary": pkgJSON("cloudinary"), "cloudflare": pkgJSON("wrangler"),
	"algolia": pkgJSON("algoliasearch"),
	"openai":  pkgJSON("openai"), "anthropic": pkgJSON("@anthropic-ai/sdk"), "google_ai": pkgJSON("@google/generative-ai"),
	"mistral": pkgJSON("@mistralai/mistralai"), "cohere": pkgJSON("cohere-ai"), "replicate": pkgJSON("replicate"),
	"huggingface": pkgJSON("@huggingface/inference"), "grok": pkgJSON("grok"), "perplexity": pkgJSON("perplexity"),
	"together_ai": pkgJSON("together-ai"),
}

// roundTripCode: source that `preflight init` declares each service from
// (analyticsServicePatterns), as a file and its content. Script tags are
// protocol-relative so detection does not go and fetch them.
var roundTripCode = map[string][2]string{
	"plausible":        {"templates/_layout.twig", `<script defer data-domain="example.com" src="//plausible.io/js/script.js"></script>`},
	"fathom":           {"index.html", `<script src="//cdn.usefathom.com/script.js" data-site="ABCDEFGH" defer></script>`},
	"umami":            {"index.html", `<script defer src="//cloud.umami.is/script.js" data-website-id="abc"></script>`},
	"fullres":          {"src/app.js", `window.fullres ||= { events: [] }`},
	"datafast":         {"index.html", `<script defer src="//datafa.st/js/script.js"></script>`},
	"google_analytics": {"index.html", `<script async src="//www.googletagmanager.com/gtag/js?id=G-ABCDEFGH12"></script>`},
	"posthog":          {"src/app.js", `posthog.init('phc_x', { api_host: 'https://us.i.posthog.com' })`},
	"hotjar":           {"index.html", `<script src="//static.hotjar.com/c/hotjar-1.js"></script>`},
	"mixpanel":         {"src/app.js", `mixpanel.init("token")`},
	"segment":          {"src/app.js", `analytics.load("WRITE_KEY")`},
	"amplitude":        {"src/app.js", `amplitude.getInstance().init("key")`},
	"intercom":         {"index.html", `<script src="//widget.intercom.io/widget/abc"></script>`},
	"crisp":            {"index.html", `<script src="//client.crisp.chat/l.js"></script>`},
	"twilio":           {"src/sms.js", `const url = "https://api.twilio.com/2010-04-01/Accounts"`},
	"slack":            {"src/notify.js", `fetch("https://hooks.slack.com/services/T/B/x")`},
	"discord":          {"src/notify.js", `fetch("https://discord.com/api/webhooks/1/x")`},
	"paypal":           {"index.html", `<script src="//www.paypal.com/sdk/js?client-id=x"></script>`},
	"paddle":           {"index.html", `<script src="//cdn.paddle.com/paddle/v2/paddle.js"></script>`},
	"lemonsqueezy":     {"index.html", `<a href="https://shop.lemonsqueezy.com/buy/x">Buy</a>`},
	"sentry":           {"src/app.js", `Sentry.init({ dsn: "https://x@o1.ingest.sentry.io/1" })`},
	"bugsnag":          {"src/app.js", `Bugsnag.start({ apiKey: 'x' })`},
	"rollbar":          {"src/app.js", `const rollbar = new Rollbar({ accessToken: 'x' })` + "\n" + `Rollbar.init({ accessToken: 'x' })`},
	"honeybadger":      {"index.html", `<script src="//js.honeybadger.io/v6.9/honeybadger.min.js"></script>`},
	"datadog":          {"src/app.js", `datadogRum.init({ site: 'datadoghq.com' })`},
	"newrelic":         {"index.html", `<script src="//js-agent.newrelic.com/nr-loader.js"></script>`},
	"logrocket":        {"src/app.js", `LogRocket.init('a/b')`},
	"postmark":         {"src/mail.js", `fetch("https://api.postmarkapp.com/email")`},
	"sendgrid":         {"src/mail.js", `fetch("https://api.sendgrid.com/v3/mail/send")`},
	"mailgun":          {"src/mail.js", `fetch("https://app.mailgun.com/v3/messages")`},
	"aws_ses":          {"src/mail.js", `const host = "email.ses.amazonaws.com"`},
	"resend":           {"src/mail.js", `fetch("https://api.resend.com/emails")`},
	"mailchimp":        {"index.html", `<form action="//acme.us1.list-manage.com/subscribe/post"></form>`},
	"convertkit":       {"index.html", `<script src="//f.convertkit.com/x.js"></script>`},
	"beehiiv":          {"index.html", `<iframe src="//embeds.beehiiv.com/x"></iframe>`},
	"aweber":           {"index.html", `<form action="//www.aweber.com/scripts/addlead.pl"></form>`},
	"activecampaign":   {"index.html", `<script src="//trackcmp.net/visit?actid=1"></script>`},
	"campaignmonitor":  {"index.html", `<form action="//acme.createsend.com/t/x"></form>`},
	"drip":             {"index.html", `<script src="//tag.getdrip.com/1.js"></script>`},
	"klaviyo":          {"index.html", `<script src="//static.klaviyo.com/onsite/js/klaviyo.js"></script>`},
	"buttondown":       {"index.html", `<form action="//buttondown.com/api/emails/embed-subscribe/x"></form>`},
	"auth0":            {"src/auth.js", `const domain = "https://acme.us.auth0.com/"`},
	"clerk":            {"src/app.tsx", `import { ClerkProvider } from '@clerk/nextjs'`},
	"workos":           {"src/auth.js", `fetch("https://api.workos.com/sso/authorize")`},
	"firebase":         {"src/fb.js", `const firebaseConfig = { authDomain: "acme.firebaseapp.com" }`},
	"supabase":         {"src/db.js", `const db = createClient("https://acme.supabase.co", key)`},
	"redis":            {"src/cache.js", `const redis = new Redis("redis://localhost:6379")`},
	"sidekiq":          {"app/jobs/mail_job.rb", "class MailJob\n  include Sidekiq::Worker\nend\n"},
	"rabbitmq":         {"src/queue.js", `amqp.connect("amqp://localhost")`},
	"elasticsearch":    {"src/search.ts", `import { Client } from '@elastic/elasticsearch'`},
	"convex":           {"src/app.tsx", `import { api } from "../convex/_generated/api"`},
	"aws_s3":           {"src/files.js", `const url = "https://bucket.s3.amazonaws.com/key"`},
	"cloudinary":       {"index.html", `<img src="//res.cloudinary.com/acme/image/upload/x.jpg">`},
	"cloudflare":       {"index.html", `<script src="//cdn.cloudflare.com/x.js"></script>`},
	"algolia":          {"src/search.js", `import algoliasearch from 'algoliasearch'`},
	"openai":           {"app/ai.py", "from openai import OpenAI\nclient = OpenAI()\n"},
	"anthropic":        {"app/ai.py", "from anthropic import Anthropic\nclient = Anthropic()\n"},
	"google_ai":        {"src/ai.ts", `import { GoogleGenerativeAI } from "@google/generative-ai"`},
	"mistral":          {"src/ai.js", `fetch("https://api.mistral.ai/v1/chat/completions")`},
	"cohere":           {"src/ai.js", `fetch("https://api.cohere.ai/v1/chat")`},
	"replicate":        {"src/ai.js", `const out = await replicate.run("owner/model")`},
	"huggingface":      {"src/ai.js", `fetch("https://huggingface.co/api/models")`},
	"grok":             {"src/ai.js", `fetch("https://api.x.ai/v1/chat/completions")`},
	"perplexity":       {"src/ai.js", `fetch("https://api.perplexity.ai/chat/completions")`},
	"together_ai":      {"src/ai.js", `fetch("https://api.together.xyz/v1/chat/completions")`},
	"cookieconsent":    {"src/consent.js", `CookieConsent.run({})`},
	"cookiebot":        {"index.html", `<script src="//consent.cookiebot.com/uc.js" data-cbid="x"></script>`},
	"onetrust":         {"index.html", `<script src="//cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>`},
	"termly":           {"index.html", `<script src="//app.termly.io/embed.min.js"></script>`},
	"cookieyes":        {"index.html", `<script src="//cdn-cookieyes.com/client_data/x/script.js"></script>`},
	"iubenda":          {"index.html", `<script src="//cdn.iubenda.com/cs/iubenda_cs.js"></script>`},
}

// TestServiceDetectionRoundTrip: whatever makes `preflight init` declare a
// service must also satisfy that service's check. The two used to keep
// separate lists, so a project was told "Redis is declared but configuration
// not found" about the REDIS_HOST line that declared it.
func TestServiceDetectionRoundTrip(t *testing.T) {
	ids := make([]string, 0, len(ServiceChecks))
	for id := range ServiceChecks {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	try := func(t *testing.T, id, file, content string) {
		t.Helper()
		root := t.TempDir()
		writeFixture(t, root, file, content)
		if !config.DetectServices(root)[id] {
			t.Errorf("fixture %s (%s) does not make init declare %s; fix the fixture", file, strings.TrimSpace(content), id)
			return
		}
		if res := runDeclaredService(t, root, id, ""); !res.Passed {
			t.Errorf("init declares %s from %s (%s), but the check says: %s", id, file, strings.TrimSpace(content), res.Message)
		}
	}

	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			for _, name := range roundTripEnv[id] {
				try(t, id, ".env.example", name+"=\n")
			}
			if dep, ok := roundTripDeps[id]; ok {
				try(t, id, dep[0], dep[1])
			}
			if code, ok := roundTripCode[id]; ok {
				try(t, id, code[0], code[1])
			}
			if len(roundTripEnv[id]) == 0 && roundTripDeps[id][0] == "" && roundTripCode[id][0] == "" {
				t.Errorf("no round-trip fixture for %s", id)
			}
		})
	}
}

// TestServiceChecksPassOnStandardSetups: setups the service checks used to
// warn about.
func TestServiceChecksPassOnStandardSetups(t *testing.T) {
	cases := []struct {
		name, id, stack string
		files           map[string]string
	}{
		{"stock Laravel Redis", "redis", "laravel", map[string]string{
			".env.example":        "REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n",
			"composer.json":       `{"require":{"laravel/framework":"^11.0"}}`,
			"config/database.php": "<?php\nreturn ['redis' => ['client' => env('REDIS_CLIENT', 'phpredis')]];\n",
		}},
		{"Redis in Python", "redis", "python", map[string]string{"app/cache.py": "import redis\nr = redis.Redis(host='localhost')\n"}},
		{"Laravel Cashier", "stripe", "laravel", map[string]string{
			".env.example":  "STRIPE_KEY=\nSTRIPE_SECRET=\n",
			"composer.json": `{"require":{"laravel/cashier":"^15.0"}}`,
		}},
		{"Plausible in a Craft layout", "plausible", "craft", map[string]string{
			"templates/_layout.twig": `<script defer data-domain="example.com" src="https://plausible.io/js/script.js"></script>`,
		}},
		{"next-plausible", "plausible", "next", map[string]string{
			"app/layout.tsx": "import PlausibleProvider from 'next-plausible'\nexport default function L({children}) { return <PlausibleProvider domain=\"x.com\">{children}</PlausibleProvider> }\n",
		}},
		{"fathom-client", "fathom", "next", map[string]string{
			"src/app/fathom.tsx": "import * as Fathom from 'fathom-client'\nFathom.load('ABCDEFGH')\nFathom.trackPageview()\n",
		}},
		{"OpenAI in Python", "openai", "python", map[string]string{"app/ai.py": "from openai import OpenAI\nclient = OpenAI()\n"}},
		{"Anthropic in Python", "anthropic", "python", map[string]string{"app/ai.py": "from anthropic import Anthropic\n"}},
		{"Google AI env name", "google_ai", "next", map[string]string{".env.example": "GOOGLE_GENERATIVE_AI_API_KEY=\n"}},
		{"google-genai", "google_ai", "python", map[string]string{"app/ai.py": "from google import genai\nclient = genai.Client()\n"}},
		{"current Gemini model", "google_ai", "next", map[string]string{"src/ai.ts": "const model = 'gemini-2.5-flash'\n"}},
		{"Rollbar constructor", "rollbar", "node", map[string]string{"src/log.js": "const rollbar = new Rollbar({ accessToken: 'x' })\n"}},
		{"Honeybadger gem", "honeybadger", "rails", map[string]string{"Gemfile": "gem \"honeybadger\"\n", "config/honeybadger.yml": "api_key: x\n"}},
		{"Datadog gem", "datadog", "rails", map[string]string{"Gemfile": "gem \"datadog\"\n", "config/initializers/datadog.rb": "Datadog.configure { |c| c.service = 'app' }\n"}},
		{"Sentry DSN in env", "sentry", "rails", map[string]string{".env.example": "SENTRY_DSN=\n"}},
		{"Bugsnag key in env", "bugsnag", "rails", map[string]string{".env.example": "BUGSNAG_API_KEY=\n"}},
		{"Campaign Monitor env name", "campaignmonitor", "rails", map[string]string{".env.example": "CAMPAIGN_MONITOR_API_KEY=\n"}},
		{"Claude env name", "anthropic", "next", map[string]string{".env.example": "CLAUDE_API_KEY=\n"}},
		{"Cohere env name", "cohere", "python", map[string]string{".env.example": "CO_API_KEY=\n"}},
		{"Sidekiq without a config file", "sidekiq", "rails", map[string]string{
			"Gemfile":              "gem \"sidekiq\"\n",
			"app/jobs/mail_job.rb": "class MailJob\n  include Sidekiq::Job\nend\n",
		}},
		{"a route glob before the SDK call", "resend", "node", map[string]string{
			"src/server.js": "app.use('/api/*', auth)\nconst resend = new Resend(key)\nexport const other = '*/'\n",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFixture(t, root, name, content)
			}
			if res := runDeclaredService(t, root, tc.id, tc.stack); !res.Passed {
				t.Errorf("%s: want a pass, got: %s", tc.id, res.Message)
			}
		})
	}
}

// TestServiceChecksDoNotPassOnProse: a comment, a description, or an
// ordinary word is not an integration.
func TestServiceChecksDoNotPassOnProse(t *testing.T) {
	cases := []struct {
		name, id, stack string
		files           map[string]string
	}{
		{"Plausible in an HTML comment", "plausible", "static", map[string]string{
			"index.html": "<html><!-- TODO add plausible.io/js/script.js later --><body></body></html>\n",
		}},
		{"Google Analytics in body text", "google_analytics", "static", map[string]string{
			"index.html": "<p>We accept PNG-8 and JPEG-XL images. Read the saga(1) man page.</p>\n",
		}},
		{"Stripe in a package description", "stripe", "node", map[string]string{
			"package.json": `{"name":"shop","description":"a shop that could take payments with stripe one day","dependencies":{}}`,
			".env.example": "STRIPE_SECRET_KEY=\n",
		}},
		{"SendGrid in a package description", "sendgrid", "node", map[string]string{
			"package.json": `{"name":"mailer","description":"SendGrid and Mailgun are not used here","dependencies":{}}`,
		}},
		{"Mailgun in a string", "mailgun", "node", map[string]string{"src/a.js": "const note = 'We left Mailgun last year'\n"}},
		{"a handler named handleResend", "resend", "node", map[string]string{"src/a.js": "function handleResend() { return 1 }\nhandleResend()\n"}},
		{"ngrok", "grok", "node", map[string]string{"src/a.js": "const host = 'abc.ngrok-free.app'\n"}},
		{"BunnyCDN", "rabbitmq", "node", map[string]string{"src/a.js": "const cdn = 'https://x.b-cdn.net' // bunny\nconst bunny = 1\n"}},
		{"a word containing pika", "rabbitmq", "python", map[string]string{"app/a.py": "name = 'pikachu'\n"}},
		{"a wrapper named analytics", "segment", "node", map[string]string{"src/a.js": "analytics.track('signup')\nanalytics.identify(id)\n"}},
		{"a map named kv", "redis", "node", map[string]string{"src/a.js": "const kv = new Map()\nkv.set('a', 1)\nkv.get('a')\n"}},
		{"a commented-out Cookiebot tag", "cookiebot", "static", map[string]string{
			"index.html": "<html><!-- <script src=\"https://consent.cookiebot.com/uc.js\"></script> --></html>\n",
		}},
		{"OpenAI in prose", "openai", "node", map[string]string{"src/a.js": "const label = 'a reply from OpenAI arrives later'\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFixture(t, root, name, content)
			}
			if res := runDeclaredService(t, root, tc.id, tc.stack); res.Passed {
				t.Errorf("%s: want a warning, got a pass: %s", tc.id, res.Message)
			}
		})
	}
}
