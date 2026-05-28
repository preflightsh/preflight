package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/preflightsh/preflight/internal/output"
	"gopkg.in/yaml.v3"
)

// publishScanResults sends a scan to the user's dashboard. It is best-effort:
// when the user is not logged in it prints a hint and returns nil so a normal
// scan never fails just because publishing wasn't set up.
func publishScanResults(cfg *config.PreflightConfig, projectDir string, results []checks.CheckResult) error {
	creds, err := dashboard.LoadCredentials()
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nCould not read credentials:", err)
		return nil
	}
	if creds == nil || creds.Token == "" {
		fmt.Fprintln(os.Stderr, "\nNot logged in. Run 'preflight auth login' to publish results to your dashboard.")
		return nil
	}

	req := &dashboard.PublishRequest{
		ProjectKey:    projectKey(projectDir, cfg.ProjectName),
		ProjectName:   cfg.ProjectName,
		Stack:         cfg.Stack,
		PreflightYAML: redactedConfigYAML(cfg),
		Result: dashboard.PublishResult{
			Summary: publishSummary(results),
			Checks:  redactChecks(results),
		},
	}

	client := dashboard.NewClient()
	resp, err := client.PublishRun(creds.Token, req)
	if err != nil {
		if errors.Is(err, dashboard.ErrQuotaExceeded) {
			fmt.Fprintln(os.Stderr, "\n"+strings.TrimPrefix(err.Error(), "free run quota exceeded: "))
			fmt.Fprintf(os.Stderr, "Upgrade or add your own API key at %s/billing\n", creds.APIURL)
			return nil
		}
		fmt.Fprintln(os.Stderr, "\nCould not publish run:", err)
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n📡 View this run: %s\n", resp.URL)
	return nil
}

// publishSummary tallies results for the dashboard payload.
func publishSummary(results []checks.CheckResult) dashboard.PublishSummary {
	s := output.CalculateSummary(results)
	return dashboard.PublishSummary{OK: s.OK, Warn: s.Warn, Fail: s.Fail}
}

// redactChecks converts results to the publish shape, stripping sensitive
// content from the secrets check (file paths, line numbers, secret types) so it
// never leaves the machine.
func redactChecks(results []checks.CheckResult) []dashboard.PublishCheck {
	out := make([]dashboard.PublishCheck, 0, len(results))
	for _, r := range results {
		msg := r.Message
		if r.ID == "secrets" && !r.Passed {
			msg = "Potential secrets detected in your codebase. Details are hidden for privacy; run `preflight scan` locally to see them."
		}
		out = append(out, dashboard.PublishCheck{
			ID:       r.ID,
			Title:    r.Title,
			Passed:   r.Passed,
			Severity: string(r.Severity),
			Message:  msg,
		})
	}
	return out
}

// redactedConfigYAML re-marshals the config with secret-bearing fields cleared:
// the IndexNow key, the Stripe webhook URL, and the secrets allowlist (which
// contains file paths and fingerprints). Service declarations, stack, and
// public URLs are kept because they give the dashboard's AI useful context.
func redactedConfigYAML(cfg *config.PreflightConfig) string {
	c := *cfg
	if c.Checks.IndexNow != nil {
		tmp := *c.Checks.IndexNow
		tmp.Key = ""
		c.Checks.IndexNow = &tmp
	}
	if c.Checks.StripeWebhook != nil {
		tmp := *c.Checks.StripeWebhook
		tmp.URL = ""
		c.Checks.StripeWebhook = &tmp
	}
	if c.Checks.Secrets != nil {
		tmp := *c.Checks.Secrets
		tmp.Allowlist = nil
		c.Checks.Secrets = &tmp
	}
	data, err := yaml.Marshal(&c)
	if err != nil {
		return ""
	}
	return string(data)
}

// projectKey returns a stable identifier for grouping runs: a hash of the git
// remote origin URL when present (stable across clones and folder renames),
// otherwise the project name.
func projectKey(dir, projectName string) string {
	out, err := exec.Command("git", "-C", dir, "config", "--get", "remote.origin.url").Output()
	if err == nil {
		remote := normalizeRemote(strings.TrimSpace(string(out)))
		if remote != "" {
			sum := sha256.Sum256([]byte(remote))
			return "git:" + hex.EncodeToString(sum[:])[:16]
		}
	}
	return "name:" + projectName
}

// normalizeRemote canonicalizes a git remote URL so the same repository hashes
// identically whether cloned via SSH or HTTPS.
func normalizeRemote(url string) string {
	url = strings.ToLower(strings.TrimSpace(url))
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")
	// git@github.com:owner/repo -> github.com/owner/repo
	if strings.HasPrefix(url, "git@") {
		url = strings.TrimPrefix(url, "git@")
		url = strings.Replace(url, ":", "/", 1)
	}
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "ssh://")
	return url
}
