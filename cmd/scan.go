package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/preflightsh/preflight/internal/catalog"
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

// scanHTTPTimeout bounds each request the scan makes. Two seconds was too
// short: cold starts on Vercel, Render, Fly and Cloud Run routinely take
// longer, and the homepage prefetch is the first request the host sees, so
// a healthy site was reported "unreachable" by every network check at once.
const scanHTTPTimeout = 10 * time.Second

// scanWorkers is how many checks run at once. Most of a scan's wall time is
// network checks waiting on the same host one after another; four in
// flight collapses most of that waiting while keeping the load on the host
// modest.
const scanWorkers = 4

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan your project for launch readiness",
	Long: `Run all enabled checks against your project and report results.
If path is provided, scans that directory. Otherwise scans current directory.
Exits 0 on success, 1 for warnings only, 2 when checks find errors,
and 64 when preflight could not run (bad path or unreadable config).`,
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

	for _, id := range append(append([]string(nil), only...), skip...) {
		if !checks.KnownID(id) {
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

// scanOptions is everything runScan gathers from flags and arguments before
// handing off to executeScan, which does the work against explicit writers
// so a test can drive a whole scan and read the report back.
type scanOptions struct {
	ProjectDir string
	CI         bool
	Format     string
	Verbose    bool
	Publish    bool
	Only       []string
	Skip       []string
	// Quiet disables the progress spinner: CI, JSON output, tests.
	Quiet bool
}

func runScan(cmd *cobra.Command, args []string) error {
	// The update notice is interactive output. It is skipped for JSON so
	// nothing can land in front of the document, and for CI, which has
	// nobody to prompt.
	if !ciMode && formatFlag != "json" {
		CheckForUpdates()
	}

	projectDir, err := resolveProjectDir(args)
	if err != nil {
		return err
	}

	// Scan-wide cancellation context. SIGINT (Ctrl-C) or SIGTERM cancels
	// the context, which propagates to every in-flight HTTP request via
	// http.NewRequestWithContext and lets checks return promptly instead
	// of leaving the process hung on a long timeout.
	scanCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	exitCode, err := executeScan(scanCtx, scanOptions{
		ProjectDir: projectDir,
		CI:         ciMode,
		Format:     formatFlag,
		Verbose:    verboseFlag,
		Publish:    publishFlag,
		Only:       onlyFlag,
		Skip:       skipFlag,
		Quiet:      ciMode || formatFlag == "json",
	}, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}

	// Show star message on first scan (only in human format, not JSON)
	if formatFlag != "json" && isFirstRun("scan_done") {
		fmt.Println()
		showStarMessage()
		markFirstRunComplete("scan_done")
	}

	if exitCode != ExitOK {
		return &ExitError{Code: exitCode}
	}
	return nil
}

// resolveProjectDir validates the optional path argument, defaulting to the
// current directory. A bad path is a usage error, not a failed scan.
func resolveProjectDir(args []string) (string, error) {
	if len(args) == 0 {
		dir, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current directory: %w", err)
		}
		return dir, nil
	}
	dir := args[0]
	info, err := os.Stat(dir)
	if err != nil {
		return "", &ExitError{Code: ExitUsage, Err: fmt.Errorf("path does not exist: %s", dir)}
	}
	if !info.IsDir() {
		return "", &ExitError{Code: ExitUsage, Err: fmt.Errorf("path is not a directory: %s", dir)}
	}
	return dir, nil
}

// executeScan loads the config, runs the enabled checks and writes the
// report to stdout. It returns the exit code the results earn. The error
// is reserved for "preflight could not run" (a usage error) and for
// cancellation; a project that fails its checks is not an error here.
func executeScan(ctx context.Context, opts scanOptions, stdout, stderr io.Writer) (int, error) {
	cfg, err := config.Load(opts.ProjectDir)
	if err != nil {
		msg := fmt.Sprintf("Error: %v", err)
		if !opts.CI {
			msg += "\nRun 'preflight init' to create a configuration file."
		}
		return ExitUsage, &ExitError{Code: ExitUsage, Err: fmt.Errorf("%s", msg)}
	}

	// SafeHTTPClient refuses to dial private/loopback/metadata IPs so a
	// hostile preflight.yml cannot coerce checks into probing internal
	// services.
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
	httpClient := netutil.SafeHTTPClientAllowing(scanHTTPTimeout, localAddrs)

	// The spinner gives the user something to watch while checks run. The
	// zero value is a no-op, so the methods below can be called
	// unconditionally.
	spinner := &output.Spinner{}
	if !opts.Quiet {
		spinner = output.NewSpinner()
		spinner.Start("Preparing scan...")
		defer spinner.Stop()
	}

	cctx := checks.Context{
		Ctx:     ctx,
		RootDir: opts.ProjectDir,
		Config:  cfg,
		Client:  httpClient,
		Verbose: opts.Verbose,
	}
	prefetchHomepages(ctx, &cctx, httpClient, spinner)

	enabledChecks := buildEnabledChecks(cfg, opts.ProjectDir)

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
	enabledChecks, err = filterChecksByFlags(enabledChecks, opts.Only, opts.Skip)
	if err != nil {
		return ExitUsage, &ExitError{Code: ExitUsage, Err: err}
	}

	total := len(enabledChecks)
	results, cancelled := runChecks(ctx, cctx, enabledChecks, scanWorkers, func(done int, title string) {
		spinner.Update(fmt.Sprintf("Running checks (%d/%d), finished %s", done, total, title))
	})
	spinner.Stop()
	if cancelled {
		fmt.Fprintln(stderr, "\nScan cancelled.")
		return ExitCanceled, &ExitError{Code: ExitCanceled}
	}

	var outputter output.Outputter
	if opts.Format == "json" {
		outputter = output.JSONOutputter{}
	} else {
		outputter = output.HumanOutputter{Verbose: opts.Verbose}
	}
	outputter.Output(stdout, cfg.ProjectName, results)

	// Publish to the dashboard if requested. Best-effort: it never changes
	// the scan's exit code and prints to stderr so JSON output stays clean.
	if opts.Publish {
		_ = publishScanResults(cfg, opts.ProjectDir, results)
	}

	return determineExitCode(results), nil
}

// prefetchHomepages fetches each configured environment's homepage once, in
// parallel, so checks that need rendered HTML (OG/Twitter, favicon
// detection for CMS-driven sites) share a single request. Staging uses the
// scan client, which is relaxed for local dev URLs. Production always uses
// SafeHTTPClient as defense in depth, since a typo or hostile preflight.yml
// could otherwise point it at an internal IP, unless production itself is
// a local URL.
func prefetchHomepages(ctx context.Context, cctx *checks.Context, httpClient *http.Client, spinner *output.Spinner) {
	cfg := cctx.Config
	if cfg.URLs.Staging == "" && cfg.URLs.Production == "" {
		return
	}
	spinner.Update("Fetching homepages...")
	var wg sync.WaitGroup
	if cfg.URLs.Staging != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx.PageHTMLStaging, cctx.PageFetchStaging = checks.FetchPage(ctx, httpClient, cfg.URLs.Staging)
		}()
	}
	if cfg.URLs.Production != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prodClient := netutil.SafeHTTPClient(scanHTTPTimeout)
			if checks.IsLocalURL(cfg.URLs.Production) {
				prodClient = httpClient
			}
			cctx.PageHTMLProduction, cctx.PageFetchProduction = checks.FetchPage(ctx, prodClient, cfg.URLs.Production)
		}()
	}
	wg.Wait()
	// PageHTML is the first-available rendered HTML, for env-agnostic
	// checks like favicon detection.
	if cctx.PageHTMLStaging != "" {
		cctx.PageHTML = cctx.PageHTMLStaging
	} else {
		cctx.PageHTML = cctx.PageHTMLProduction
	}
}

// runChecks runs list with up to workers checks in flight and returns the
// results in list order, so the report reads exactly as it did when checks
// ran one at a time. progress is called as each check finishes. Checks not
// yet started when ctx is cancelled are skipped and cancelled reports it;
// the ones in flight finish on their own (their requests carry ctx).
func runChecks(ctx context.Context, cctx checks.Context, list []checks.Check, workers int, progress func(done int, title string)) (results []checks.CheckResult, cancelled bool) {
	results = make([]checks.CheckResult, len(list))
	if workers < 1 {
		workers = 1
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		done int
		sem  = make(chan struct{}, workers)
	)
	for i, check := range list {
		// Checked before the select: when both a free worker slot and a
		// cancelled context are ready, select picks at random, and a scan
		// interrupted before it started must never start a check.
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			cancelled = true
		}
		if cancelled {
			break
		}
		wg.Add(1)
		go func(i int, check checks.Check) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = runOneCheck(cctx, check)
			mu.Lock()
			done++
			n := done
			mu.Unlock()
			progress(n, check.Title())
		}(i, check)
	}
	wg.Wait()
	return results, cancelled
}

// runOneCheck converts a check's error, or a panic, into a failed result so
// one broken check reports itself instead of taking the scan down.
func runOneCheck(cctx checks.Context, check checks.Check) (result checks.CheckResult) {
	failed := func(err any) checks.CheckResult {
		return checks.CheckResult{
			ID:       check.ID(),
			Title:    check.Title(),
			Severity: checks.SeverityError,
			Passed:   false,
			Message:  fmt.Sprintf("Check failed: %v", err),
		}
	}
	defer func() {
		if r := recover(); r != nil {
			result = failed(fmt.Sprintf("panic: %v", r))
		}
	}()
	result, err := check.Run(cctx)
	if err != nil {
		return failed(err)
	}
	return result
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
	for _, svc := range catalog.Services {
		check, ok := checks.ServiceChecks[svc.ID]
		if !ok {
			continue // stripe and indexnow are gated above and below
		}
		if cfg.Services[svc.ID].Declared && !serviceIgnored(svc.ID) {
			enabledChecks = append(enabledChecks, check)
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

// determineExitCode maps results to the documented exit codes. An unknown
// severity on a failed check counts as a warning, matching how
// output.CalculateSummary tallies it, so the summary and the exit code
// cannot disagree.
func determineExitCode(results []checks.CheckResult) int {
	hasError := false
	hasWarning := false

	for _, r := range results {
		if !r.Passed {
			switch r.Severity {
			case checks.SeverityError:
				hasError = true
			default:
				hasWarning = true
			}
		}
	}

	if hasError {
		return ExitFail
	}
	if hasWarning {
		return ExitWarn
	}
	return ExitOK
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
