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
	Use:   "scan",
	Short: "Scan your project for launch readiness",
	Long: `Run all enabled checks against your project and report results.
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

	// Get current directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Load config
	cfg, err := config.Load(cwd)
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
		RootDir: cwd,
		Config:  cfg,
		Client:  httpClient,
	}

	// Build list of enabled checks
	enabledChecks := buildEnabledChecks(cfg)

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

	// ENV Parity Check
	if cfg.Checks.EnvParity != nil && cfg.Checks.EnvParity.Enabled {
		enabledChecks = append(enabledChecks, checks.EnvParityCheck{})
	}

	// Health Endpoint Check
	if cfg.Checks.HealthEndpoint != nil && cfg.Checks.HealthEndpoint.Enabled {
		enabledChecks = append(enabledChecks, checks.HealthCheck{})
	}

	// Stripe Webhook Check
	if cfg.Checks.StripeWebhook != nil && cfg.Checks.StripeWebhook.Enabled {
		enabledChecks = append(enabledChecks, checks.StripeWebhookCheck{})
	}

	// Sentry Check - runs if service is declared
	if cfg.Services["sentry"].Declared {
		enabledChecks = append(enabledChecks, checks.SentryCheck{})
	}

	// Plausible Check - runs if service is declared
	if cfg.Services["plausible"].Declared {
		enabledChecks = append(enabledChecks, checks.PlausibleCheck{})
	}

	// Fathom Check - runs if service is declared
	if cfg.Services["fathom"].Declared {
		enabledChecks = append(enabledChecks, checks.FathomCheck{})
	}

	// Google Analytics Check - runs if service is declared
	if cfg.Services["google_analytics"].Declared {
		enabledChecks = append(enabledChecks, checks.GoogleAnalyticsCheck{})
	}

	// Redis Check - runs if service is declared
	if cfg.Services["redis"].Declared {
		enabledChecks = append(enabledChecks, checks.RedisCheck{})
	}

	// Sidekiq Check - runs if service is declared
	if cfg.Services["sidekiq"].Declared {
		enabledChecks = append(enabledChecks, checks.SidekiqCheck{})
	}

	// SEO Meta Check
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.SEOMetadataCheck{})
	}

	// OG & Twitter Cards Check - runs if SEO Meta is configured
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.OGTwitterCheck{})
	}

	// Canonical URL Check - runs if SEO Meta is configured
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.CanonicalURLCheck{})
	}

	// Viewport Meta Check - runs if SEO Meta is configured
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.ViewportCheck{})
	}

	// HTML Lang Attribute Check - runs if SEO Meta is configured
	if cfg.Checks.SEOMeta != nil && cfg.Checks.SEOMeta.Enabled {
		enabledChecks = append(enabledChecks, checks.LangAttributeCheck{})
	}

	// Security Headers Check
	if cfg.Checks.Security != nil && cfg.Checks.Security.Enabled {
		enabledChecks = append(enabledChecks, checks.SecurityHeadersCheck{})
	}

	// SSL Certificate Check - runs if production URL is set
	if cfg.URLs.Production != "" {
		enabledChecks = append(enabledChecks, checks.SSLCheck{})
	}

	// Secrets Check
	if cfg.Checks.Secrets != nil && cfg.Checks.Secrets.Enabled {
		enabledChecks = append(enabledChecks, checks.SecretScanCheck{})
	}

	// Always run these checks - they're universal best practices
	enabledChecks = append(enabledChecks, checks.FaviconCheck{})
	enabledChecks = append(enabledChecks, checks.RobotsTxtCheck{})
	enabledChecks = append(enabledChecks, checks.SitemapCheck{})
	enabledChecks = append(enabledChecks, checks.LLMsTxtCheck{})
	enabledChecks = append(enabledChecks, checks.VulnerabilityCheck{})
	enabledChecks = append(enabledChecks, checks.ErrorPagesCheck{})

	// License Check - only if enabled (opt-in for open source projects)
	if cfg.Checks.License != nil && cfg.Checks.License.Enabled {
		enabledChecks = append(enabledChecks, checks.LicenseCheck{})
	}

	// Ads.txt Check - only if explicitly enabled
	if cfg.Checks.AdsTxt != nil && cfg.Checks.AdsTxt.Enabled {
		enabledChecks = append(enabledChecks, checks.AdsTxtCheck{})
	}

	// IndexNow Check - only if explicitly enabled
	if cfg.Checks.IndexNow != nil && cfg.Checks.IndexNow.Enabled {
		enabledChecks = append(enabledChecks, checks.IndexNowCheck{})
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
