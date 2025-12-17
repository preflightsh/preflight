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
	ciMode     bool
	formatFlag string
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
	}

	// Build list of enabled checks
	enabledChecks := buildEnabledChecks(cfg)

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
		outputter = output.HumanOutputter{}
	}

	outputter.Output(cfg.ProjectName, results)

	// Determine exit code
	exitCode := determineExitCode(results)
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

func buildEnabledChecks(cfg *config.PreflightConfig) []checks.Check {
	var enabledChecks []checks.Check

	// === SEO & Social ===
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.SEOMetadataCheck{})
		enabledChecks = append(enabledChecks, checks.CanonicalURLCheck{})
	}
	enabledChecks = append(enabledChecks, checks.StructuredDataCheck{})
	if cfg.Checks.IndexNow != nil && cfg.Checks.IndexNow.Enabled {
		enabledChecks = append(enabledChecks, checks.IndexNowCheck{})
	}
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.OGTwitterCheck{})
		enabledChecks = append(enabledChecks, checks.ViewportCheck{})
		enabledChecks = append(enabledChecks, checks.LangAttributeCheck{})
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
	if cfg.Checks.HealthEndpoint != nil && cfg.Checks.HealthEndpoint.Enabled {
		enabledChecks = append(enabledChecks, checks.HealthCheck{})
	}

	// === Services ===
	if cfg.Services["sentry"].Declared {
		enabledChecks = append(enabledChecks, checks.SentryCheck{})
	}
	if cfg.Services["plausible"].Declared {
		enabledChecks = append(enabledChecks, checks.PlausibleCheck{})
	}
	if cfg.Services["fathom"].Declared {
		enabledChecks = append(enabledChecks, checks.FathomCheck{})
	}
	if cfg.Services["google_analytics"].Declared {
		enabledChecks = append(enabledChecks, checks.GoogleAnalyticsCheck{})
	}
	if cfg.Services["redis"].Declared {
		enabledChecks = append(enabledChecks, checks.RedisCheck{})
	}
	if cfg.Services["sidekiq"].Declared {
		enabledChecks = append(enabledChecks, checks.SidekiqCheck{})
	}
	if cfg.Checks.StripeWebhook != nil && cfg.Checks.StripeWebhook.Enabled {
		enabledChecks = append(enabledChecks, checks.StripeWebhookCheck{})
	}

	// === Code Quality & Performance ===
	enabledChecks = append(enabledChecks, checks.VulnerabilityCheck{})
	enabledChecks = append(enabledChecks, checks.DebugStatementsCheck{})
	enabledChecks = append(enabledChecks, checks.ErrorPagesCheck{})
	enabledChecks = append(enabledChecks, checks.ImageOptimizationCheck{})

	// === Legal & Compliance ===
	enabledChecks = append(enabledChecks, checks.LegalPagesCheck{})
	if cfg.Checks.CookieConsent != nil && cfg.Checks.CookieConsent.Enabled {
		enabledChecks = append(enabledChecks, checks.CookieConsentCheck{})
	}

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
