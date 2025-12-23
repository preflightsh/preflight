package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/output"
	"github.com/spf13/cobra"
)

var (
	ciMode      bool
	formatFlag  string
	verboseFlag bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan your project for launch readiness",
	Long: `Run all enabled checks against your project and report results.
If path is provided, scans that directory. Otherwise scans current directory.
Exits with code 0 for success, 1 for warnings only, 2 for errors.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Run in CI mode (no interactivity)")
	scanCmd.Flags().StringVar(&formatFlag, "format", "human", "Output format: human or json")
	scanCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Show detailed information about each check")
}

func runScan(cmd *cobra.Command, args []string) error {
	if !ciMode {
		CheckForUpdates()
	}

	// Use provided path or current directory
	var projectDir string
	if len(args) > 0 {
		projectDir = args[0]
	} else {
		var err error
		projectDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	// Load config
	cfg, err := config.Load(projectDir)
	if err != nil {
		if !ciMode {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			fmt.Fprintln(os.Stderr, "Run 'preflight init' to create a configuration file.")
		}
		os.Exit(2)
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Create check context
	ctx := checks.Context{
		RootDir: projectDir,
		Config:  cfg,
		Client:  httpClient,
		Verbose: verboseFlag,
	}

	// Build list of enabled checks
	enabledChecks := buildEnabledChecks(cfg, projectDir)

	// Filter out ignored checks
	if len(cfg.Ignore) > 0 {
		ignoreMap := make(map[string]bool)
		for _, id := range cfg.Ignore {
			ignoreMap[id] = true
		}
		var filtered []checks.Check
		for _, check := range enabledChecks {
			if !ignoreMap[check.ID()] {
				filtered = append(filtered, check)
			}
		}
		enabledChecks = filtered
	}

	// Run all checks
	var results []checks.CheckResult
	for _, check := range enabledChecks {
		result, err := check.Run(ctx)
		if err != nil {
			// Convert error to failed check result
			result = checks.CheckResult{
				ID:       check.ID(),
				Title:    check.Title(),
				Severity: checks.SeverityError,
				Passed:   false,
				Message:  fmt.Sprintf("Check failed: %v", err),
			}
		}
		results = append(results, result)
	}

	// Output results
	var outputter output.Outputter
	if formatFlag == "json" {
		outputter = output.JSONOutputter{}
	} else {
		outputter = output.HumanOutputter{Verbose: verboseFlag}
	}

	outputter.Output(cfg.ProjectName, results)

	// Show star message on first scan (only in human format, not JSON)
	if formatFlag != "json" && isFirstRun("scan_done") {
		fmt.Println()
		showStarMessage()
		markFirstRunComplete("scan_done")
	}

	// Determine exit code
	exitCode := determineExitCode(results)
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

func buildEnabledChecks(cfg *config.PreflightConfig, rootDir string) []checks.Check {
	var enabledChecks []checks.Check

	// Build ignore map for quick lookup (includes both check IDs and service IDs)
	ignoreMap := make(map[string]bool)
	for _, id := range cfg.Ignore {
		ignoreMap[id] = true
	}

	// Helper to check if a service should be skipped
	serviceIgnored := func(serviceID string) bool {
		return ignoreMap[serviceID]
	}

	// === SEO & Social ===
	// Auto-enable SEO checks if layout can be detected or explicitly configured
	seoEnabled := (cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled) ||
		canAutoDetectLayout(rootDir, cfg.Stack)
	if seoEnabled {
		enabledChecks = append(enabledChecks, checks.SEOMetadataCheck{})
		enabledChecks = append(enabledChecks, checks.CanonicalURLCheck{})
		enabledChecks = append(enabledChecks, checks.OGTwitterCheck{})
		enabledChecks = append(enabledChecks, checks.ViewportCheck{})
		enabledChecks = append(enabledChecks, checks.LangAttributeCheck{})
	}
	enabledChecks = append(enabledChecks, checks.StructuredDataCheck{})
	if cfg.Checks.IndexNow != nil && cfg.Checks.IndexNow.Enabled {
		enabledChecks = append(enabledChecks, checks.IndexNowCheck{})
	}

	// === Security & Infrastructure ===
	if cfg.Checks.Security != nil && cfg.Checks.Security.Enabled {
		enabledChecks = append(enabledChecks, checks.SecurityHeadersCheck{})
	}
	if cfg.URLs.Production != "" {
		enabledChecks = append(enabledChecks, checks.SSLCheck{})
		enabledChecks = append(enabledChecks, checks.WWWRedirectCheck{})
	}
	if cfg.Checks.EmailAuth != nil && cfg.Checks.EmailAuth.Enabled && cfg.URLs.Production != "" {
		enabledChecks = append(enabledChecks, checks.EmailAuthCheck{})
	}
	if cfg.Checks.Secrets != nil && cfg.Checks.Secrets.Enabled {
		enabledChecks = append(enabledChecks, checks.SecretScanCheck{})
	}

	// === Environment & Health ===
	if cfg.Checks.EnvParity != nil && cfg.Checks.EnvParity.Enabled {
		enabledChecks = append(enabledChecks, checks.EnvParityCheck{})
	}
	// Health check runs if explicitly enabled OR if any URLs are configured
	if (cfg.Checks.HealthEndpoint != nil && cfg.Checks.HealthEndpoint.Enabled) ||
		cfg.URLs.Production != "" || cfg.URLs.Staging != "" {
		enabledChecks = append(enabledChecks, checks.HealthCheck{})
	}

	// === Services ===
	// Service checks are skipped if the service ID is in the ignore list

	// Payments
	if cfg.Checks.StripeWebhook != nil && cfg.Checks.StripeWebhook.Enabled && !serviceIgnored("stripe") {
		enabledChecks = append(enabledChecks, checks.StripeWebhookCheck{})
	}
	if cfg.Services["paypal"].Declared && !serviceIgnored("paypal") {
		enabledChecks = append(enabledChecks, checks.PayPalCheck{})
	}
	if cfg.Services["braintree"].Declared && !serviceIgnored("braintree") {
		enabledChecks = append(enabledChecks, checks.BraintreeCheck{})
	}
	if cfg.Services["paddle"].Declared && !serviceIgnored("paddle") {
		enabledChecks = append(enabledChecks, checks.PaddleCheck{})
	}
	if cfg.Services["lemonsqueezy"].Declared && !serviceIgnored("lemonsqueezy") {
		enabledChecks = append(enabledChecks, checks.LemonSqueezyCheck{})
	}

	// Error Tracking & Monitoring
	if cfg.Services["sentry"].Declared && !serviceIgnored("sentry") {
		enabledChecks = append(enabledChecks, checks.SentryCheck{})
	}
	if cfg.Services["bugsnag"].Declared && !serviceIgnored("bugsnag") {
		enabledChecks = append(enabledChecks, checks.BugsnagCheck{})
	}
	if cfg.Services["rollbar"].Declared && !serviceIgnored("rollbar") {
		enabledChecks = append(enabledChecks, checks.RollbarCheck{})
	}
	if cfg.Services["honeybadger"].Declared && !serviceIgnored("honeybadger") {
		enabledChecks = append(enabledChecks, checks.HoneybadgerCheck{})
	}
	if cfg.Services["datadog"].Declared && !serviceIgnored("datadog") {
		enabledChecks = append(enabledChecks, checks.DatadogCheck{})
	}
	if cfg.Services["newrelic"].Declared && !serviceIgnored("newrelic") {
		enabledChecks = append(enabledChecks, checks.NewRelicCheck{})
	}
	if cfg.Services["logrocket"].Declared && !serviceIgnored("logrocket") {
		enabledChecks = append(enabledChecks, checks.LogRocketCheck{})
	}

	// Email Services
	if cfg.Services["postmark"].Declared && !serviceIgnored("postmark") {
		enabledChecks = append(enabledChecks, checks.PostmarkCheck{})
	}
	if cfg.Services["sendgrid"].Declared && !serviceIgnored("sendgrid") {
		enabledChecks = append(enabledChecks, checks.SendGridCheck{})
	}
	if cfg.Services["mailgun"].Declared && !serviceIgnored("mailgun") {
		enabledChecks = append(enabledChecks, checks.MailgunCheck{})
	}
	if cfg.Services["aws_ses"].Declared && !serviceIgnored("aws_ses") {
		enabledChecks = append(enabledChecks, checks.AWSSESCheck{})
	}
	if cfg.Services["resend"].Declared && !serviceIgnored("resend") {
		enabledChecks = append(enabledChecks, checks.ResendCheck{})
	}

	// Email Marketing
	if cfg.Services["mailchimp"].Declared && !serviceIgnored("mailchimp") {
		enabledChecks = append(enabledChecks, checks.MailchimpCheck{})
	}
	if cfg.Services["convertkit"].Declared && !serviceIgnored("convertkit") {
		enabledChecks = append(enabledChecks, checks.ConvertKitCheck{})
	}
	if cfg.Services["beehiiv"].Declared && !serviceIgnored("beehiiv") {
		enabledChecks = append(enabledChecks, checks.BeehiivCheck{})
	}
	if cfg.Services["aweber"].Declared && !serviceIgnored("aweber") {
		enabledChecks = append(enabledChecks, checks.AWeberCheck{})
	}
	if cfg.Services["activecampaign"].Declared && !serviceIgnored("activecampaign") {
		enabledChecks = append(enabledChecks, checks.ActiveCampaignCheck{})
	}
	if cfg.Services["campaignmonitor"].Declared && !serviceIgnored("campaignmonitor") {
		enabledChecks = append(enabledChecks, checks.CampaignMonitorCheck{})
	}
	if cfg.Services["drip"].Declared && !serviceIgnored("drip") {
		enabledChecks = append(enabledChecks, checks.DripCheck{})
	}
	if cfg.Services["klaviyo"].Declared && !serviceIgnored("klaviyo") {
		enabledChecks = append(enabledChecks, checks.KlaviyoCheck{})
	}
	if cfg.Services["buttondown"].Declared && !serviceIgnored("buttondown") {
		enabledChecks = append(enabledChecks, checks.ButtondownCheck{})
	}

	// Analytics
	if cfg.Services["plausible"].Declared && !serviceIgnored("plausible") {
		enabledChecks = append(enabledChecks, checks.PlausibleCheck{})
	}
	if cfg.Services["fathom"].Declared && !serviceIgnored("fathom") {
		enabledChecks = append(enabledChecks, checks.FathomCheck{})
	}
	if cfg.Services["google_analytics"].Declared && !serviceIgnored("google_analytics") {
		enabledChecks = append(enabledChecks, checks.GoogleAnalyticsCheck{})
	}
	if cfg.Services["fullres"].Declared && !serviceIgnored("fullres") {
		enabledChecks = append(enabledChecks, checks.FullresCheck{})
	}
	if cfg.Services["datafast"].Declared && !serviceIgnored("datafast") {
		enabledChecks = append(enabledChecks, checks.DatafastCheck{})
	}
	if cfg.Services["posthog"].Declared && !serviceIgnored("posthog") {
		enabledChecks = append(enabledChecks, checks.PostHogCheck{})
	}
	if cfg.Services["mixpanel"].Declared && !serviceIgnored("mixpanel") {
		enabledChecks = append(enabledChecks, checks.MixpanelCheck{})
	}
	if cfg.Services["amplitude"].Declared && !serviceIgnored("amplitude") {
		enabledChecks = append(enabledChecks, checks.AmplitudeCheck{})
	}
	if cfg.Services["segment"].Declared && !serviceIgnored("segment") {
		enabledChecks = append(enabledChecks, checks.SegmentCheck{})
	}
	if cfg.Services["hotjar"].Declared && !serviceIgnored("hotjar") {
		enabledChecks = append(enabledChecks, checks.HotjarCheck{})
	}

	// Infrastructure
	if cfg.Services["redis"].Declared && !serviceIgnored("redis") {
		enabledChecks = append(enabledChecks, checks.RedisCheck{})
	}
	if cfg.Services["sidekiq"].Declared && !serviceIgnored("sidekiq") {
		enabledChecks = append(enabledChecks, checks.SidekiqCheck{})
	}
	if cfg.Services["rabbitmq"].Declared && !serviceIgnored("rabbitmq") {
		enabledChecks = append(enabledChecks, checks.RabbitMQCheck{})
	}
	if cfg.Services["elasticsearch"].Declared && !serviceIgnored("elasticsearch") {
		enabledChecks = append(enabledChecks, checks.ElasticsearchCheck{})
	}
	if cfg.Services["convex"].Declared && !serviceIgnored("convex") {
		enabledChecks = append(enabledChecks, checks.ConvexCheck{})
	}

	// Auth Services
	if cfg.Services["auth0"].Declared && !serviceIgnored("auth0") {
		enabledChecks = append(enabledChecks, checks.Auth0Check{})
	}
	if cfg.Services["clerk"].Declared && !serviceIgnored("clerk") {
		enabledChecks = append(enabledChecks, checks.ClerkCheck{})
	}
	if cfg.Services["workos"].Declared && !serviceIgnored("workos") {
		enabledChecks = append(enabledChecks, checks.WorkOSCheck{})
	}
	if cfg.Services["firebase"].Declared && !serviceIgnored("firebase") {
		enabledChecks = append(enabledChecks, checks.FirebaseCheck{})
	}
	if cfg.Services["supabase"].Declared && !serviceIgnored("supabase") {
		enabledChecks = append(enabledChecks, checks.SupabaseCheck{})
	}

	// Communication Services
	if cfg.Services["twilio"].Declared && !serviceIgnored("twilio") {
		enabledChecks = append(enabledChecks, checks.TwilioCheck{})
	}
	if cfg.Services["slack"].Declared && !serviceIgnored("slack") {
		enabledChecks = append(enabledChecks, checks.SlackCheck{})
	}
	if cfg.Services["discord"].Declared && !serviceIgnored("discord") {
		enabledChecks = append(enabledChecks, checks.DiscordCheck{})
	}
	if cfg.Services["intercom"].Declared && !serviceIgnored("intercom") {
		enabledChecks = append(enabledChecks, checks.IntercomCheck{})
	}
	if cfg.Services["crisp"].Declared && !serviceIgnored("crisp") {
		enabledChecks = append(enabledChecks, checks.CrispCheck{})
	}

	// Storage & CDN
	if cfg.Services["aws_s3"].Declared && !serviceIgnored("aws_s3") {
		enabledChecks = append(enabledChecks, checks.AWSS3Check{})
	}
	if cfg.Services["cloudinary"].Declared && !serviceIgnored("cloudinary") {
		enabledChecks = append(enabledChecks, checks.CloudinaryCheck{})
	}
	if cfg.Services["cloudflare"].Declared && !serviceIgnored("cloudflare") {
		enabledChecks = append(enabledChecks, checks.CloudflareCheck{})
	}

	// Search
	if cfg.Services["algolia"].Declared && !serviceIgnored("algolia") {
		enabledChecks = append(enabledChecks, checks.AlgoliaCheck{})
	}

	// AI Services
	if cfg.Services["openai"].Declared && !serviceIgnored("openai") {
		enabledChecks = append(enabledChecks, checks.OpenAICheck{})
	}
	if cfg.Services["anthropic"].Declared && !serviceIgnored("anthropic") {
		enabledChecks = append(enabledChecks, checks.AnthropicCheck{})
	}
	if cfg.Services["google_ai"].Declared && !serviceIgnored("google_ai") {
		enabledChecks = append(enabledChecks, checks.GoogleAICheck{})
	}
	if cfg.Services["mistral"].Declared && !serviceIgnored("mistral") {
		enabledChecks = append(enabledChecks, checks.MistralCheck{})
	}
	if cfg.Services["cohere"].Declared && !serviceIgnored("cohere") {
		enabledChecks = append(enabledChecks, checks.CohereCheck{})
	}
	if cfg.Services["replicate"].Declared && !serviceIgnored("replicate") {
		enabledChecks = append(enabledChecks, checks.ReplicateCheck{})
	}
	if cfg.Services["huggingface"].Declared && !serviceIgnored("huggingface") {
		enabledChecks = append(enabledChecks, checks.HuggingFaceCheck{})
	}
	if cfg.Services["grok"].Declared && !serviceIgnored("grok") {
		enabledChecks = append(enabledChecks, checks.GrokCheck{})
	}
	if cfg.Services["perplexity"].Declared && !serviceIgnored("perplexity") {
		enabledChecks = append(enabledChecks, checks.PerplexityCheck{})
	}
	if cfg.Services["together_ai"].Declared && !serviceIgnored("together_ai") {
		enabledChecks = append(enabledChecks, checks.TogetherAICheck{})
	}

	// Cookie Consent Services
	if cfg.Services["cookieconsent"].Declared && !serviceIgnored("cookieconsent") {
		enabledChecks = append(enabledChecks, checks.CookieConsentJSCheck{})
	}
	if cfg.Services["cookiebot"].Declared && !serviceIgnored("cookiebot") {
		enabledChecks = append(enabledChecks, checks.CookiebotCheck{})
	}
	if cfg.Services["onetrust"].Declared && !serviceIgnored("onetrust") {
		enabledChecks = append(enabledChecks, checks.OneTrustCheck{})
	}
	if cfg.Services["termly"].Declared && !serviceIgnored("termly") {
		enabledChecks = append(enabledChecks, checks.TermlyCheck{})
	}
	if cfg.Services["cookieyes"].Declared && !serviceIgnored("cookieyes") {
		enabledChecks = append(enabledChecks, checks.CookieYesCheck{})
	}
	if cfg.Services["iubenda"].Declared && !serviceIgnored("iubenda") {
		enabledChecks = append(enabledChecks, checks.IubendaCheck{})
	}

	// === Code Quality & Performance ===
	enabledChecks = append(enabledChecks, checks.VulnerabilityCheck{})
	enabledChecks = append(enabledChecks, checks.DebugStatementsCheck{})
	enabledChecks = append(enabledChecks, checks.ErrorPagesCheck{})
	enabledChecks = append(enabledChecks, checks.ImageOptimizationCheck{})

	// === Legal & Compliance ===
	enabledChecks = append(enabledChecks, checks.LegalPagesCheck{})

	// === Web Standard Files ===
	enabledChecks = append(enabledChecks, checks.FaviconCheck{})
	enabledChecks = append(enabledChecks, checks.RobotsTxtCheck{})
	enabledChecks = append(enabledChecks, checks.SitemapCheck{})
	enabledChecks = append(enabledChecks, checks.LLMsTxtCheck{})
	if cfg.Checks.AdsTxt != nil && cfg.Checks.AdsTxt.Enabled {
		enabledChecks = append(enabledChecks, checks.AdsTxtCheck{})
	}
	if cfg.Checks.HumansTxt != nil && cfg.Checks.HumansTxt.Enabled {
		enabledChecks = append(enabledChecks, checks.HumansTxtCheck{})
	}
	if cfg.Checks.License != nil && cfg.Checks.License.Enabled {
		enabledChecks = append(enabledChecks, checks.LicenseCheck{})
	}

	return enabledChecks
}

func determineExitCode(results []checks.CheckResult) int {
	hasError := false
	hasWarning := false

	for _, r := range results {
		if !r.Passed {
			switch r.Severity {
			case checks.SeverityError:
				hasError = true
			case checks.SeverityWarn:
				hasWarning = true
			}
		}
	}

	if hasError {
		return 2
	}
	if hasWarning {
		return 1
	}
	return 0
}

// canAutoDetectLayout checks if a layout file can be auto-detected for SEO checks
func canAutoDetectLayout(rootDir, stack string) bool {
	// Common layout files by stack
	layoutsByStack := map[string][]string{
		"next": {
			"app/layout.tsx", "app/layout.js", "app/layout.jsx",
			"src/app/layout.tsx", "src/app/layout.js", "src/app/layout.jsx",
			"pages/_app.tsx", "pages/_app.js", "pages/_document.tsx", "pages/_document.js",
		},
		"react": {"index.html", "public/index.html", "src/index.html"},
		"vite":  {"index.html", "src/index.html"},
		"vue":   {"index.html", "public/index.html", "src/App.vue"},
		"svelte": {"src/app.html", "index.html"},
		"angular": {"src/index.html"},
		"rails": {
			"app/views/layouts/application.html.erb",
			"app/views/layouts/base.html.erb",
		},
		"laravel": {
			"resources/views/layouts/app.blade.php",
			"resources/views/layouts/main.blade.php",
		},
		"django": {"templates/base.html", "templates/layout.html"},
		"craft": {
			"templates/_layout.twig",
			"templates/_layouts/main.twig",
			"templates/_layouts/base.twig",
		},
		"hugo":     {"layouts/_default/baseof.html"},
		"jekyll":   {"_layouts/default.html", "_layouts/base.html"},
		"gatsby":   {"src/components/layout.js", "src/components/Layout.js"},
		"astro":    {"src/layouts/Layout.astro", "src/layouts/Base.astro"},
		"eleventy": {"_includes/base.njk", "_includes/layout.njk"},
	}

	// Check stack-specific layouts
	if layouts, ok := layoutsByStack[stack]; ok {
		for _, layout := range layouts {
			if _, err := os.Stat(rootDir + "/" + layout); err == nil {
				return true
			}
		}
	}

	// Fallback: try common layouts
	commonLayouts := []string{
		"app/layout.tsx", "app/layout.js",
		"src/app/layout.tsx", "src/app/layout.js",
		"index.html", "public/index.html",
	}
	for _, layout := range commonLayouts {
		if _, err := os.Stat(rootDir + "/" + layout); err == nil {
			return true
		}
	}

	return false
}
