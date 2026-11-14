package checks

import (
	"regexp"
	"slices"
	"sync"
)

// serviceSignal lists what `preflight init` accepts as evidence of a service
// (internal/config/detect.go), so that the check for a service passes on
// whatever got the service declared in the first place. Detection and the
// checks used to keep separate lists, and a project could be told "Redis is
// declared but configuration not found" about the REDIS_HOST line that
// declared it.
//
// TestServiceDetectionRoundTrip holds the two together: for each service, a
// fixture that detection declares must pass the check.
type serviceSignal struct {
	// env are env-name prefixes, in addition to the check's own.
	env []string
	// deps are dependency names, matched case-insensitively as substrings
	// of a manifest's dependency list only (never its description).
	deps []string
	// code are source patterns, in addition to the check's own.
	code []*regexp.Regexp
}

func re(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

var serviceSignals = map[string]serviceSignal{
	// Payments
	"paypal":       {deps: []string{"paypal"}},
	"braintree":    {deps: []string{"braintree"}},
	"paddle":       {deps: []string{"@paddle/", "paddle-node", `"paddle":`}, code: re(`paddle\.com/paddlejs`)},
	"lemonsqueezy": {deps: []string{"lemonsqueezy"}},

	// Error tracking and monitoring
	"bugsnag":     {env: []string{"BUGSNAG_"}, deps: []string{"bugsnag"}, code: re(`bugsnag\.com`)},
	"rollbar":     {env: []string{"ROLLBAR_"}, deps: []string{"rollbar"}, code: re(`\bnew Rollbar\(`, `\b[Rr]ollbar\.(?:init|configure|error|log)\b`)},
	"honeybadger": {env: []string{"HONEYBADGER_"}, deps: []string{"honeybadger"}, code: re(`honeybadger\.io/`)},
	"datadog":     {env: []string{"DD_", "DATADOG_"}, deps: []string{"datadog", "dd-trace", "ddtrace"}, code: re(`\bDatadog\.configure\b`, `\bdatadog(?:Rum|Logs)\.init\b`, `\bddtrace\b`)},
	"newrelic":    {env: []string{"NEW_RELIC_", "NEWRELIC_"}, deps: []string{"newrelic", "new-relic"}},
	"logrocket":   {env: []string{"LOGROCKET_"}, deps: []string{"logrocket"}},

	// Transactional email
	"postmark": {deps: []string{"postmark"}, code: re(`@postmark/`)},
	"sendgrid": {deps: []string{"sendgrid"}},
	"mailgun":  {deps: []string{"mailgun"}},
	"aws_ses":  {deps: []string{"aws-sdk-ses", "@aws-sdk/client-ses", "amazon-ses"}, code: re(`ses\.amazonaws\.com`)},
	"resend":   {deps: []string{`"resend":`, "@resend/", "resend/resend", `gem "resend"`, `gem 'resend'`}, code: re(`api\.resend\.com`)},

	// Email marketing
	"mailchimp":       {deps: []string{"mailchimp"}},
	"convertkit":      {env: []string{"KIT_API", "KIT_FORM"}, deps: []string{"convertkit"}},
	"beehiiv":         {deps: []string{"beehiiv"}},
	"aweber":          {deps: []string{"aweber"}},
	"activecampaign":  {deps: []string{"activecampaign"}},
	"campaignmonitor": {env: []string{"CAMPAIGN_MONITOR_"}, deps: []string{"campaignmonitor", "campaign-monitor", "createsend"}},
	"drip":            {deps: []string{"getdrip"}},
	"klaviyo":         {deps: []string{"klaviyo"}},
	"buttondown":      {deps: []string{"buttondown"}},

	// Analytics
	"plausible":        {env: []string{"PLAUSIBLE_"}, deps: []string{"plausible"}},
	"fathom":           {env: []string{"FATHOM_"}, deps: []string{"fathom-client", "usefathom", `"fathom":`}},
	"umami":            {env: []string{"UMAMI_"}, deps: []string{"@umami/", "umami-analytics"}},
	"fullres":          {env: []string{"FULLRES_"}, deps: []string{"fullres"}, code: re(`fullres\.(?:src|async)\b`)},
	"datafast":         {env: []string{"DATAFAST_"}, deps: []string{"datafast"}},
	"google_analytics": {env: []string{"GA_", "GOOGLE_ANALYTICS", "GTM_"}, deps: []string{"react-ga", "vue-gtag", "@next/third-parties", "gtag"}},
	"posthog":          {env: []string{"POSTHOG_"}, deps: []string{"posthog"}, code: re(`posthog\.com`)},
	"mixpanel":         {env: []string{"MIXPANEL_"}, deps: []string{"mixpanel"}, code: re(`mixpanel\.com/`)},
	"amplitude":        {env: []string{"AMPLITUDE_"}, deps: []string{"@amplitude/", "amplitude-js", `"amplitude":`}},
	"segment":          {env: []string{"SEGMENT_"}, deps: []string{"@segment/", "analytics-node"}},
	"hotjar":           {env: []string{"HOTJAR_"}, deps: []string{"hotjar"}},

	// Auth
	"auth0":    {deps: []string{"auth0"}},
	"clerk":    {deps: []string{"@clerk/", "clerk-sdk"}},
	"workos":   {deps: []string{"workos"}, code: re(`@workos/`)},
	"firebase": {deps: []string{"firebase"}, code: re(`firebaseapp\.com`)},
	"supabase": {deps: []string{"supabase"}},

	// Communication
	"twilio":   {deps: []string{"twilio"}},
	"slack":    {deps: []string{"@slack/", "slack-ruby", "slack-notify", `"slack":`}},
	"discord":  {deps: []string{"discord.js", "discordrb", "discord.py", "disnake", "pycord", `"discord":`}, code: re(`\bdisnake\b`)},
	"intercom": {deps: []string{"intercom"}, code: re(`\bintercom-client\b`)},
	"crisp":    {deps: []string{"crisp-sdk", `"crisp":`}},

	// Infrastructure
	"redis":         {env: []string{"REDIS_", "REDISCLOUD_", "UPSTASH_REDIS", "KV_REST_API"}, deps: []string{"redis"}},
	"sidekiq":       {env: []string{"SIDEKIQ_"}, deps: []string{"sidekiq"}},
	"rabbitmq":      {deps: []string{"amqplib", "amqp", "rabbitmq", `gem "bunny"`, `gem 'bunny'`}, code: re(`rabbitmq\.com`, `@rabbitmq/`)},
	"elasticsearch": {deps: []string{"elasticsearch", "@elastic/"}, code: re(`elasticsearch\.org`)},
	"convex":        {deps: []string{`"convex":`, "@convex/"}},

	// Storage and CDN
	"aws_s3":     {deps: []string{"aws-sdk-s3", "@aws-sdk/client-s3", "aws-sdk/s3"}},
	"cloudinary": {deps: []string{"cloudinary"}, code: re(`cloudinary\.com/`)},
	"cloudflare": {deps: []string{"@cloudflare/", "cloudflare-workers", "wrangler"}, code: re(`cdn\.cloudflare\.com`, `\bcloudflare-workers\b`)},

	// Search
	"algolia": {deps: []string{"algolia"}},

	// AI
	"openai":      {deps: []string{"openai"}},
	"anthropic":   {env: []string{"CLAUDE_"}, deps: []string{"anthropic"}},
	"google_ai":   {env: []string{"GOOGLE_GENERATIVE_"}, deps: []string{"@google/generative-ai", "@google/genai", "google-generativeai", "google-genai"}},
	"mistral":     {deps: []string{"mistralai"}},
	"cohere":      {env: []string{"CO_API_KEY"}, deps: []string{"cohere"}},
	"replicate":   {deps: []string{`"replicate":`, "replicate/", "replicate"}},
	"huggingface": {deps: []string{"huggingface", "transformers"}},
	"grok":        {deps: []string{"xai-sdk", "@ai-sdk/xai", `"grok":`}, code: re(`\bxai/grok\b`)},
	"perplexity":  {deps: []string{"perplexity", "pplx-api"}, code: re(`\bpplx-api\b`)},
	"together_ai": {env: []string{"TOGETHER_AI_"}, deps: []string{"together-ai", `"together":`}},

	// Cookie consent
	"cookieconsent": {deps: []string{"cookieconsent"}},
	"cookiebot":     {deps: []string{"cookiebot"}},
	"onetrust":      {deps: []string{"onetrust"}},
	"termly":        {deps: []string{"termly"}},
	"cookieyes":     {deps: []string{"cookieyes"}},
	"iubenda":       {deps: []string{"iubenda"}},
}

// depPatterns turns dependency-name substrings into case-insensitive
// literal patterns.
func depPatterns(names []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(names))
	for i, n := range names {
		out[i] = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(n))
	}
	return out
}

// serviceEnvPrefixes returns the env-name prefixes that configure a service:
// the check's own plus the ones detection declares it from.
func serviceEnvPrefixes(id string, own ...string) []string {
	prefixes := slices.Clone(own)
	for _, p := range serviceSignals[id].env {
		if !slices.Contains(prefixes, p) {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

var (
	serviceGroupsOnce sync.Once
	serviceGroups     map[string]codeGroup
)

// serviceCodeGroups returns the source search for every service: its
// check's code patterns plus the detection signals.
func serviceCodeGroups() map[string]codeGroup {
	serviceGroupsOnce.Do(func() {
		serviceGroups = map[string]codeGroup{
			// Stripe and Sentry read manifests themselves, with patterns per
			// manifest type, and only strip "#" comments where the language
			// has them.
			"stripe": {patterns: stripeCodePatterns, sourceOnly: true, hashByExt: true},
			"sentry": {patterns: sentryCodePatterns, sourceOnly: true, hashByExt: true},
		}
		add := func(id string, patterns []*regexp.Regexp) {
			sig := serviceSignals[id]
			serviceGroups[id] = codeGroup{
				patterns: append(slices.Clone(patterns), sig.code...),
				deps:     depPatterns(sig.deps),
			}
		}
		for id, check := range ServiceChecks {
			if sc, ok := check.(ServiceCheck); ok {
				add(id, sc.CodePatterns)
			}
		}
		for id, patterns := range bespokeCodePatterns {
			add(id, patterns)
		}
	})
	return serviceGroups
}

// bespokeCodePatterns are the source patterns of the service checks that
// are not table-driven ServiceChecks.
var bespokeCodePatterns = map[string][]*regexp.Regexp{
	"plausible": re(
		`plausible\.io/(?:js|api)/`,
		`data-domain=["']`,
		`\bplausible-analytics\b`,
		`@plausible/tracker`,
		`\bplausible-tracker\b`,
		`\bnext-plausible\b`,
		`\bPlausibleProvider\b`,
	),
	"fathom": re(
		`usefathom\.com`,
		`\bfathom-client\b`,
		// Fathom.load() and Fathom.trackPageview() from fathom-client, and
		// the global fathom.trackEvent() the script tag defines.
		`(?i)\bfathom\.(?:load|trackPageview|trackEvent|trackGoal)\b`,
		`data-site=["'][A-Z]{6,12}["']`,
	),
	"google_analytics": re(
		`googletagmanager\.com`,
		`google-analytics\.com`,
		`\bgtag\s*\(`,
		`(?:^|[^\w.])ga\s*\(\s*['"]`,
		`GoogleAnalyticsObject`,
		`\bG-[A-Z0-9]{8,12}\b`,    // GA4 measurement ID
		`\bUA-[0-9]{4,}-[0-9]+\b`, // Universal Analytics
		`\bGTM-[A-Z0-9]{5,9}\b`,   // Tag Manager container
		`(?i)\bmonsterinsights\b`, // WordPress plugin
		`@next/third-parties/google`,
	),
	"redis": re(
		`rediss?://`,
		`\bRedis\.(?:new|current)\b`,
		`\bRedis::`,
		`createClient.*redis`,
		`\bnew Redis\(`,
		`\bioredis\b`,
		`\bpredis\b`,
		`@upstash/redis`,
		`upstash\.io`,
		`@vercel/kv`,
		// Python and Go clients.
		`(?m)^\s*(?:import|from)\s+redis\b`,
		`\bredis\.(?:Redis|StrictRedis|from_url|NewClient)\b`,
		`go-redis`,
		// Framework config: Laravel's database.php and cache.php, Django
		// and Rails cache stores, an env lookup of the connection.
		`['"]redis['"]\s*=>`,
		`\bredis_cache_store\b|django_redis|RedisCache`,
		`\bREDIS_(?:URL|HOST)\b`,
	),
	"sidekiq": re(
		`\bSidekiq::(?:Worker|Job|Web)\b`,
		`\binclude Sidekiq\b`,
		`\bSidekiq\.configure_(?:server|client)\b`,
		`sidekiq\.yml`,
		`:sidekiq\b`, // config.active_job.queue_adapter = :sidekiq
	),
	"postmark": re(
		`postmarkapp`,
		`\bpostmark-client\b`,
		`@wildbit/postmark`,
		`\bpostmark\.ServerClient\b`,
		`\bServerClient\s*\(`,
	),
	"sendgrid": re(
		`@sendgrid/`,
		`\bsendgrid-ruby\b`,
		`sendgrid\.com/`,
		`\bSendGrid\s*(?:::|\\|\.|\()`,
		`\bSendGridAPIClient\b`,
		`(?m)^\s*(?:import|from)\s+sendgrid\b`,
		`\bsgMail\b`,
	),
	"mailgun": re(
		`\bmailgun-js\b`,
		`\bmailgun\.js\b`,
		`@mailgun/`,
		`mailgun\.client`,
		`mailgun\.(?:com|net)/`,
		`\bMailgun\s*(?:::|\\|\.|\()`,
		`\bnew Mailgun\b`,
	),
	"resend": re(
		`resend\.emails\.send`,
		`\bnew Resend\b`,
		`\bResend\(`,
		`from\s+["']resend["']`,
		`require\s*\(\s*["']resend["']\)`,
		`(?m)^\s*import\s+resend\b`,
		`\bresend\.Emails\b`,
	),
	"aws_ses": re(
		`@aws-sdk/client-ses`,
		`\baws-sdk-ses\b`,
		`\bSESClient\b`,
		`\bses\.sendEmail\b`,
		`\bcraft-amazon-ses\b`,
	),
	"cookiebot": re(
		`consent\.cookiebot\.com`,
		`\bCookiebot\b`,
		`\bcookiebot\b`,
	),
	"onetrust": re(
		`cdn\.cookielaw\.org`,
		`\bonetrust\b`,
		`\bOneTrust\b`,
		`\boptanon`,
	),
	"termly": re(
		`app\.termly\.io`,
		`\btermly\b`,
		`\bTermly\.initialize\(`,
	),
	"cookieyes": re(
		`cdn-cookieyes\.com`,
		`\bcookieyes\b`,
		`\bCookieYes\b`,
	),
	"iubenda": re(
		`cdn\.iubenda\.com`,
		`\biubenda\b`,
		`\b_iub\b`,
	),
}

// stackLayoutFiles returns the files where a stack's page shell lives: the
// place a script tag or a provider component is added.
func stackLayoutFiles(stack string) []string {
	if files, ok := layoutFilesByStack[stack]; ok {
		return files
	}
	return []string{"index.html", "public/index.html", "src/index.html"}
}

var layoutFilesByStack = map[string][]string{
	// Backend frameworks
	"rails":   {"app/views/layouts/application.html.erb", "app/views/layouts/application.html.haml"},
	"laravel": {"resources/views/layouts/app.blade.php", "resources/views/app.blade.php"},
	"django":  {"templates/base.html", "templates/layout.html", "templates/index.html"},
	"python":  {"templates/base.html", "templates/layout.html", "templates/index.html"},
	"go":      {"templates/base.html", "templates/layout.html", "views/base.html", "web/templates/base.html"},
	"rust":    {"templates/base.html", "templates/layout.html"},
	"node":    {"views/layout.ejs", "views/layout.pug", "views/layout.hbs", "views/layouts/main.hbs", "views/layouts/main.handlebars"},

	// Frontend frameworks
	"next":    {"app/layout.tsx", "app/layout.js", "pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js", "src/app/layout.tsx"},
	"react":   {"src/App.tsx", "src/App.jsx", "src/App.js", "src/index.tsx", "src/index.jsx", "public/index.html"},
	"vue":     {"src/App.vue", "src/main.ts", "src/main.js", "index.html", "public/index.html"},
	"vite":    {"index.html", "src/App.tsx", "src/App.jsx", "src/App.vue", "src/App.svelte"},
	"svelte":  {"src/App.svelte", "src/routes/+layout.svelte", "src/app.html"},
	"angular": {"src/index.html", "src/app/app.component.ts", "src/app/app.component.html"},

	// Traditional CMS
	"wordpress": {"wp-content/themes/theme/header.php", "wp-content/themes/theme/functions.php", "header.php"},
	"craft":     {"templates/_layout.twig", "templates/_layout.html", "templates/_partials/head.twig"},
	"drupal":    {"themes/custom/theme/templates/html.html.twig", "web/themes/custom/theme/templates/html.html.twig"},
	"ghost":     {"content/themes/casper/default.hbs", "default.hbs"},

	// Static site generators
	"hugo":     {"layouts/_default/baseof.html", "themes/theme/layouts/_default/baseof.html", "layouts/partials/head.html"},
	"jekyll":   {"_layouts/default.html", "_includes/head.html", "_includes/header.html"},
	"gatsby":   {"src/components/layout.js", "src/components/layout.tsx", "src/html.js", "gatsby-browser.js"},
	"eleventy": {"_includes/layout.njk", "_includes/base.njk", "_includes/layout.liquid", "src/_includes/layout.njk"},
	"astro":    {"src/layouts/Layout.astro", "src/layouts/BaseLayout.astro", "src/components/Head.astro"},

	// Headless CMS (frontend detection)
	"strapi":     {"src/index.js", "config/server.js"},
	"sanity":     {"sanity.config.ts", "sanity.config.js"},
	"contentful": {"src/templates/page.js", "src/App.js"},
	"prismic":    {"src/components/Layout.js", "slicemachine.config.json"},

	// Generic PHP
	"php": {"header.php", "includes/header.php", "partials/header.php", "templates/header.php", "inc/header.php"},

	// Static
	"static": {"index.html", "public/index.html", "dist/index.html"},
}
