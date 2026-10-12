package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/preflightsh/preflight/internal/output"
	"gopkg.in/yaml.v3"
)

// publishScanResults sends a scan to the user's dashboard. It is best-effort:
// when the user is not logged in it prints a hint and returns nil so a normal
// scan never fails just because publishing wasn't set up.
func publishScanResults(ctx context.Context, cfg *config.PreflightConfig, projectDir string, results []checks.CheckResult) error {
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
		SchemaVersion: output.SchemaVersion,
		CLIVersion:    version,
		ProjectKey:    projectKey(projectDir, cfg.ProjectName),
		ProjectName:   cfg.ProjectName,
		Stack:         cfg.Stack,
		PreflightYAML: redactedConfigYAML(cfg),
		Result: dashboard.PublishResult{
			Summary: publishSummary(results),
			Checks:  redactChecks(results),
		},
	}

	client, warning := dashboard.ClientForCredentials(creds)
	client.Ctx = ctx
	if warning != "" {
		fmt.Fprintln(os.Stderr, "\n"+warning)
	}
	resp, err := client.PublishRun(creds.Token, req)
	if err != nil {
		if errors.Is(err, dashboard.ErrQuotaExceeded) {
			fmt.Fprintln(os.Stderr, "\n"+strings.TrimPrefix(err.Error(), "free run quota exceeded: "))
			fmt.Fprintf(os.Stderr, "Upgrade or add your own API key at %s/billing\n", client.BaseURL)
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
	return dashboard.PublishSummary{OK: s.OK, Warn: s.Warn, Fail: s.Fail, Skipped: s.Skipped, Inconclusive: s.Inconclusive}
}

// redactChecks publishes only controlled summaries. Local evidence may hold
// secrets in arbitrary tool output or file paths and must never be uploaded.
func redactChecks(results []checks.CheckResult) []dashboard.PublishCheck {
	out := make([]dashboard.PublishCheck, 0, len(results))
	for _, r := range results {
		// Messages can contain arbitrary subprocess output, URLs, filenames or
		// panic text. Publish controlled summaries; full evidence stays local.
		msg := "Check passed."
		if !r.Passed {
			msg = "Check needs attention; see the local scan report for details."
		}
		if r.Skipped {
			msg = "Check skipped (not verified)."
		}
		if r.Inconclusive {
			msg = "Check could not be verified; see the local report for details."
		}
		if r.ID == "secrets" && !r.Passed {
			msg = "Potential secrets detected (details hidden for privacy)."
		}
		out = append(out, dashboard.PublishCheck{
			ID:      r.ID,
			Title:   r.Title,
			Passed:  r.Passed,
			Skipped: r.Skipped, Inconclusive: r.Inconclusive,
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
	c.URLs.Staging = publicOrigin(c.URLs.Staging)
	c.URLs.Production = publicOrigin(c.URLs.Production)
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
	// Paths and optional labels are user-supplied; only the enablement flags
	// are useful to the dashboard. Never publish an arbitrary config string.
	if c.Checks.EnvParity != nil {
		tmp := *c.Checks.EnvParity
		tmp.EnvFile = ""
		tmp.ExampleFile = ""
		c.Checks.EnvParity = &tmp
	}
	if c.Checks.HealthEndpoint != nil {
		tmp := *c.Checks.HealthEndpoint
		tmp.Path = ""
		c.Checks.HealthEndpoint = &tmp
	}
	if c.Checks.SEOMeta != nil {
		tmp := *c.Checks.SEOMeta
		tmp.MainLayout = ""
		c.Checks.SEOMeta = &tmp
	}
	c.Ignore = nil
	data, err := yaml.Marshal(&c)
	if err != nil {
		return ""
	}
	return string(data)
}

func publicOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// projectKey returns a stable identifier for grouping runs: a hash of the git
// remote origin URL when present (stable across clones and folder renames),
// otherwise the project name.
func projectKey(dir, projectName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", "remote.origin.url")
	command.WaitDelay = time.Second
	out, err := command.Output()
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
// identically however it was cloned: scp-style git@host:owner/repo, ssh://,
// https://, with or without userinfo, with or without .git.
func normalizeRemote(url string) string {
	url = strings.ToLower(strings.TrimSpace(url))
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	if i := strings.Index(url, "://"); i >= 0 {
		// ssh://git@github.com/owner/repo, https://github.com/owner/repo
		url = url[i+3:]
	} else if c := strings.Index(url, ":"); c >= 0 && !strings.Contains(url[:c], "/") {
		// scp-style git@github.com:owner/repo -> git@github.com/owner/repo
		url = url[:c] + "/" + url[c+1:]
	}

	// Drop userinfo (git@, user:token@) from the authority so a clone with
	// embedded credentials lands on the same project as one without.
	if slash := strings.Index(url, "/"); slash > 0 {
		if at := strings.LastIndex(url[:slash], "@"); at >= 0 {
			url = url[at+1:]
		}
	}
	return url
}
