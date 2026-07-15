package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/netutil"
	"github.com/preflightsh/preflight/internal/output"
	"github.com/spf13/cobra"
)

var (
	ciMode      bool
	formatFlag  string
	verboseFlag bool
	publishFlag bool
	onlyFlag    []string
	skipFlag    []string
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
	scanCmd.Flags().BoolVar(&publishFlag, "publish", false, "Publish results to your Preflight dashboard (requires 'preflight auth login')")
	scanCmd.Flags().StringSliceVar(&onlyFlag, "only", nil, "Run only these check/service IDs (comma-separated; see 'preflight checks')")
	scanCmd.Flags().StringSliceVar(&skipFlag, "skip", nil, "Skip these check/service IDs for this run (comma-separated)")
	_ = scanCmd.RegisterFlagCompletionFunc("only", completeCheckIDs)
	_ = scanCmd.RegisterFlagCompletionFunc("skip", completeCheckIDs)
}

// completeCheckIDs offers every known check ID for --only / --skip shell
// completion.
func completeCheckIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	ids := make([]string, 0, len(checks.Registry))
	for _, c := range checks.Registry {
		ids = append(ids, c.ID())
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}

// filterChecksByFlags applies the one-off --only / --skip narrowing on top of
// the config-driven enablement and ignore list. Unknown IDs are an error so a
// typo doesn't silently scan nothing (or everything).
func filterChecksByFlags(enabled []checks.Check, only, skip []string) ([]checks.Check, error) {
	if len(only) == 0 && len(skip) == 0 {
		return enabled, nil
	}

	known := make(map[string]bool, len(checks.Registry))
	for _, c := range checks.Registry {
		known[c.ID()] = true
	}
	for _, id := range append(append([]string(nil), only...), skip...) {
		if !known[id] {
			return nil, fmt.Errorf("unknown check ID %q (run 'preflight checks' to list IDs)", id)
		}
	}

	onlySet := make(map[string]bool, len(only))
	for _, id := range only {
		onlySet[id] = true
	}
	skipSet := make(map[string]bool, len(skip))
	for _, id := range skip {
		skipSet[id] = true
	}

	var filtered []checks.Check
	for _, c := range enabled {
		if len(onlySet) > 0 && !onlySet[c.ID()] {
			continue
		}
		if skipSet[c.ID()] {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(onlySet) > 0 && len(filtered) == 0 {
		return nil, fmt.Errorf("no enabled checks match --only (the checks may not apply to this project's config)")
	}
	return filtered, nil
}

func runScan(cmd *cobra.Command, args []string) error {
	if !ciMode {
		CheckForUpdates()
	}

	// Use provided path or current directory
	var projectDir string
	if len(args) > 0 {
		projectDir = args[0]
		// Validate the provided path
		info, err := os.Stat(projectDir)
		if err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("path does not exist: %s", projectDir)}
		}
		if !info.IsDir() {
			return &ExitError{Code: 2, Err: fmt.Errorf("path is not a directory: %s", projectDir)}
		}
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
		msg := fmt.Sprintf("Error: %v", err)
		if !ciMode {
			msg += "\nRun 'preflight init' to create a configuration file."
		}
		return &ExitError{Code: 2, Err: fmt.Errorf("%s", msg)}
	}

	// Create HTTP client with timeout. SafeHTTPClient refuses to dial
	// private/loopback/metadata IPs so a hostile preflight.yml cannot
	// coerce checks into probing internal services.
	//
	// Configuring a local dev URL (localhost, *.local, *.test,
	// *.ddev.site etc.) is a trusted-config workflow, so we exempt those
	// targets, but only those exact host:port pairs. The scan reaches
	// plenty of URLs the config never vouched for (og:image and
	// twitter:image are taken verbatim from page content), so exempting
	// per-target rather than swapping in a wide-open client keeps a
	// local production URL from also unlocking the metadata endpoint or
	// a Redis port for the rest of the run.
	var localAddrs []string
	for _, raw := range []string{cfg.URLs.Production, cfg.URLs.Staging} {
		if raw == "" || !checks.IsLocalURL(raw) {
			continue
		}
		if addr := netutil.AddrFromURL(raw); addr != "" {
			localAddrs = append(localAddrs, addr)
		}
	}
	httpClient := netutil.SafeHTTPClientAllowing(2*time.Second, localAddrs)

	// Spinner gives the user something to watch while checks run. Off in
	// CI and JSON modes (which expect quiet/structured output) and on
	// non-TTY stdout. The Spinner type handles its own no-op when
	// disabled, so we can call its methods unconditionally below.
	var spinner *output.Spinner
	if !ciMode && formatFlag != "json" {
		spinner = output.NewSpinner()
		spinner.Start("Preparing scan...")
		defer spinner.Stop()
	} else {
		spinner = &output.Spinner{} // no-op
	}

	// Scan-wide cancellation context. SIGINT (Ctrl-C) or SIGTERM cancels
	// the context, which propagates to every in-flight HTTP request via
	// http.NewRequestWithContext and lets checks return promptly instead
	// of leaving the process hung on a long timeout.
	scanCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// Create check context. Pre-fetch the homepage once so checks that
	// need to scan rendered HTML (OG/Twitter and favicon detection for
	// CMS-driven sites) can share a single request.
	ctx := checks.Context{
		Ctx:     scanCtx,
		RootDir: projectDir,
		Config:  cfg,
		Client:  httpClient,
		Verbose: verboseFlag,
	}
	// Fetch staging and production homepage HTML in parallel. Staging
	// uses the chosen httpClient (which is the relaxed client when
	// staging is a local dev URL like *.lndo.site). Production always
	// uses SafeHTTPClient as defense-in-depth, since a typo or hostile
	// preflight.yml could otherwise point production at an internal IP.
	// If the user has only configured production and it's a local URL,
	// reuse the relaxed client for that too.
	if cfg.URLs.Staging != "" || cfg.URLs.Production != "" {
		spinner.Update("Fetching homepages...")
		var wg sync.WaitGroup
		if cfg.URLs.Staging != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx.PageHTMLStaging = checks.FetchPageHTML(scanCtx, httpClient, cfg.URLs.Staging)
			}()
		}
		if cfg.URLs.Production != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				prodClient := netutil.SafeHTTPClient(2 * time.Second)
				if checks.IsLocalURL(cfg.URLs.Production) {
					prodClient = httpClient
				}
				ctx.PageHTMLProduction = checks.FetchPageHTML(scanCtx, prodClient, cfg.URLs.Production)
			}()
		}
		wg.Wait()
		// PageHTML is the first-available rendered HTML, for env-agnostic
		// checks like favicon detection.
		if ctx.PageHTMLStaging != "" {
			ctx.PageHTML = ctx.PageHTMLStaging
		} else {
			ctx.PageHTML = ctx.PageHTMLProduction
		}
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

	// One-off narrowing via --only / --skip.
	enabledChecks, err = filterChecksByFlags(enabledChecks, onlyFlag, skipFlag)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	// Run all checks
	var results []checks.CheckResult
	for i, check := range enabledChecks {
		// Honor Ctrl-C / SIGTERM between checks so a long scan can be
		// stopped cleanly instead of being killed mid-request.
		if scanCtx.Err() != nil {
			spinner.Stop()
			fmt.Fprintln(os.Stderr, "\nScan cancelled.")
			return &ExitError{Code: 130}
		}
		spinner.Update(fmt.Sprintf("Running %s (%d/%d)", check.Title(), i+1, len(enabledChecks)))
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
	spinner.Stop()

	// Output results
	var outputter output.Outputter
	if formatFlag == "json" {
		outputter = output.JSONOutputter{}
	} else {
		outputter = output.HumanOutputter{Verbose: verboseFlag}
	}

	outputter.Output(os.Stdout, cfg.ProjectName, results)

	// Publish to the dashboard if requested. Best-effort: it never changes the
	// scan's exit code and prints to stderr so JSON output stays clean.
	if publishFlag {
		_ = publishScanResults(cfg, projectDir, results)
	}

	// Show star message on first scan (only in human format, not JSON)
	if formatFlag != "json" && isFirstRun("scan_done") {
		fmt.Println()
		showStarMessage()
		markFirstRunComplete("scan_done")
	}

	// Determine exit code
	exitCode := determineExitCode(results)
	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}

	return nil
}

// serviceChecks maps every declared-service check to its service ID, in
// report order (payments, monitoring, email, marketing, analytics,
// infrastructure, auth, communication, storage, search, AI, cookie consent).
// Add new service checks here and in the checks package; nothing else.
var serviceChecks = []struct {
	id    string
	check checks.Check
}{
	// Payments
	{"paypal", checks.PayPalCheck},
	{"braintree", checks.BraintreeCheck},
	{"paddle", checks.PaddleCheck},
	{"lemonsqueezy", checks.LemonSqueezyCheck},
	// Error tracking & monitoring
	{"sentry", checks.SentryCheck{}},
	{"bugsnag", checks.BugsnagCheck},
	{"rollbar", checks.RollbarCheck},
	{"honeybadger", checks.HoneybadgerCheck},
	{"datadog", checks.DatadogCheck},
	{"newrelic", checks.NewRelicCheck},
	{"logrocket", checks.LogRocketCheck},
	// Email services
	{"postmark", checks.PostmarkCheck{}},
	{"sendgrid", checks.SendGridCheck{}},
	{"mailgun", checks.MailgunCheck{}},
	{"aws_ses", checks.AWSSESCheck{}},
	{"resend", checks.ResendCheck{}},
	// Email marketing
	{"mailchimp", checks.MailchimpCheck},
	{"convertkit", checks.ConvertKitCheck},
	{"beehiiv", checks.BeehiivCheck},
	{"aweber", checks.AWeberCheck},
	{"activecampaign", checks.ActiveCampaignCheck},
	{"campaignmonitor", checks.CampaignMonitorCheck},
	{"drip", checks.DripCheck},
	{"klaviyo", checks.KlaviyoCheck},
	{"buttondown", checks.ButtondownCheck},
	// Analytics
	{"plausible", checks.PlausibleCheck{}},
	{"fathom", checks.FathomCheck{}},
	{"umami", checks.UmamiCheck},
	{"google_analytics", checks.GoogleAnalyticsCheck{}},
	{"fullres", checks.FullresCheck},
	{"datafast", checks.DatafastCheck},
	{"posthog", checks.PostHogCheck},
	{"mixpanel", checks.MixpanelCheck},
	{"amplitude", checks.AmplitudeCheck},
	{"segment", checks.SegmentCheck},
	{"hotjar", checks.HotjarCheck},
	// Infrastructure
	{"redis", checks.RedisCheck{}},
	{"sidekiq", checks.SidekiqCheck{}},
	{"rabbitmq", checks.RabbitMQCheck},
	{"elasticsearch", checks.ElasticsearchCheck},
	{"convex", checks.ConvexCheck},
	// Auth
	{"auth0", checks.Auth0Check},
	{"clerk", checks.ClerkCheck},
	{"workos", checks.WorkOSCheck},
	{"firebase", checks.FirebaseCheck},
	{"supabase", checks.SupabaseCheck},
	// Communication
	{"twilio", checks.TwilioCheck},
	{"slack", checks.SlackCheck},
	{"discord", checks.DiscordCheck},
	{"intercom", checks.IntercomCheck},
	{"crisp", checks.CrispCheck},
	// Storage & CDN
	{"aws_s3", checks.AWSS3Check},
	{"cloudinary", checks.CloudinaryCheck},
	{"cloudflare", checks.CloudflareCheck},
	// Search
	{"algolia", checks.AlgoliaCheck},
	// AI
	{"openai", checks.OpenAICheck},
	{"anthropic", checks.AnthropicCheck},
	{"google_ai", checks.GoogleAICheck},
	{"mistral", checks.MistralCheck},
	{"cohere", checks.CohereCheck},
	{"replicate", checks.ReplicateCheck},
	{"huggingface", checks.HuggingFaceCheck},
	{"grok", checks.GrokCheck},
	{"perplexity", checks.PerplexityCheck},
	{"together_ai", checks.TogetherAICheck},
	// Cookie consent
	{"cookieconsent", checks.CookieConsentJSCheck},
	{"cookiebot", checks.CookiebotCheck{}},
	{"onetrust", checks.OneTrustCheck{}},
	{"termly", checks.TermlyCheck{}},
	{"cookieyes", checks.CookieYesCheck{}},
	{"iubenda", checks.IubendaCheck{}},
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
	// A service check runs when its service is declared in preflight.yml and
	// its ID is not in the ignore list. Stripe is the one exception: it is
	// gated on its own config block rather than a service declaration.
	if cfg.Checks.StripeWebhook != nil && cfg.Checks.StripeWebhook.Enabled && !serviceIgnored("stripe") {
		enabledChecks = append(enabledChecks, checks.StripeWebhookCheck{})
	}
	for _, sc := range serviceChecks {
		if cfg.Services[sc.id].Declared && !serviceIgnored(sc.id) {
			enabledChecks = append(enabledChecks, sc.check)
		}
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
		"react":   {"index.html", "public/index.html", "src/index.html"},
		"vite":    {"index.html", "src/index.html"},
		"vue":     {"index.html", "public/index.html", "src/App.vue"},
		"svelte":  {"src/app.html", "index.html"},
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
			if _, err := os.Stat(filepath.Join(rootDir, layout)); err == nil {
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
		if _, err := os.Stat(filepath.Join(rootDir, layout)); err == nil {
			return true
		}
	}

	return false
}
