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
	"path/filepath"
	"regexp"
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
			Checks:  redactChecks(cfg, results),
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

// publishMessageChecks are the checks whose messages are published as
// written (after scrubbing, see publishedMessage). Each builds its message
// from fixed text, counts, repo-relative paths, DNS names, or public page
// content. Everything else gets a generic summary: secrets (the finding is
// the secret), vulnerability (audit tool output), env_parity (variable
// names from .env), health_endpoint and stripe_webhook (configured URLs
// and paths), index_now (the key), and every service check, whose messages
// are not reviewed for this. The dashboard's AI fixes need the real text,
// so this list should grow as message shapes are reviewed, not shrink.
var publishMessageChecks = map[string]bool{
	"seo_meta": true, "canonical": true, "structured_data": true, "og_twitter": true,
	"viewport": true, "lang": true, "security_headers": true, "ssl": true,
	"www_redirect": true, "email_auth": true, "debug_statements": true,
	"error_pages": true, "image_optimization": true, "legal_pages": true,
	"favicon": true, "robots_txt": true, "sitemap": true, "llms_txt": true,
	"ads_txt": true, "humans_txt": true, "license": true,
}

// publishListChecks put their findings (file:line or file and size, up to
// five) in Suggestions; the dashboard's prompts expect them in the message.
var publishListChecks = map[string]bool{"debug_statements": true, "image_optimization": true}

var (
	urlUserinfoRe = regexp.MustCompile(`(://)[^/@\s]+@`)
	urlQueryRe    = regexp.MustCompile(`(https?://[^\s?#]*)[?#][^\s,;)]*`)
)

// redactChecks publishes the message of each allowlisted check, scrubbed of
// the values redactedConfigYAML withholds, and a controlled summary for the
// rest. Local evidence may hold secrets in arbitrary tool output or file
// paths and must never be uploaded.
func redactChecks(cfg *config.PreflightConfig, results []checks.CheckResult) []dashboard.PublishCheck {
	out := make([]dashboard.PublishCheck, 0, len(results))
	for _, r := range results {
		msg := publishedMessage(cfg, r)
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

// publishedMessage is the message the dashboard receives for r.
func publishedMessage(cfg *config.PreflightConfig, r checks.CheckResult) string {
	// runOneCheck turns an error or panic into "Check failed: ...", which
	// can carry anything, whichever check it came from.
	if publishMessageChecks[r.ID] && !strings.HasPrefix(r.Message, "Check failed:") {
		msg := r.Message
		if publishListChecks[r.ID] && !r.Passed && len(r.Suggestions) > 0 {
			msg += ": " + strings.Join(r.Suggestions, "; ")
		}
		return scrubMessage(cfg, msg)
	}
	switch {
	case r.ID == "secrets" && !r.Passed:
		return "Potential secrets detected (details hidden for privacy)."
	case r.Inconclusive:
		return "Check could not be verified; see the local report for details."
	case r.Skipped:
		return "Check skipped (not verified)."
	case !r.Passed:
		return "Check needs attention; see the local scan report for details."
	}
	return "Check passed."
}

// scrubMessage removes from msg the config values the published config
// withholds, and the credentials, query strings, and fragments of URLs.
func scrubMessage(cfg *config.PreflightConfig, msg string) string {
	replace := func(old, repl string) {
		if strings.TrimSpace(old) != "" {
			msg = strings.ReplaceAll(msg, old, repl)
		}
	}
	if cfg != nil {
		replace(cfg.URLs.Staging, publicOrigin(cfg.URLs.Staging))
		replace(cfg.URLs.Production, publicOrigin(cfg.URLs.Production))
		c := cfg.Checks
		if c.IndexNow != nil {
			replace(c.IndexNow.Key, "<key>")
		}
		if c.StripeWebhook != nil {
			replace(c.StripeWebhook.URL, "<webhook url>")
		}
		if c.SEOMeta != nil {
			replace(c.SEOMeta.MainLayout, "<layout>")
		}
		if c.EnvParity != nil {
			replace(c.EnvParity.EnvFile, "<env file>")
			replace(c.EnvParity.ExampleFile, "<env example file>")
		}
	}
	msg = urlUserinfoRe.ReplaceAllString(msg, "$1")
	return urlQueryRe.ReplaceAllString(msg, "$1")
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
// otherwise the project name. A scan below the repository root (one app in
// a monorepo) also hashes its repo-relative directory, so apps/web and
// apps/api are separate projects; at the root nothing is added, so the
// keys of existing single-app projects do not change.
func projectKey(dir, projectName string) string {
	out, err := gitOutput(dir, "config", "--get", "remote.origin.url")
	if err == nil {
		remote := normalizeRemote(out)
		if remote != "" {
			key := remote
			if prefix, err := gitOutput(dir, "rev-parse", "--show-prefix"); err == nil {
				if prefix = strings.Trim(filepath.ToSlash(prefix), "/"); prefix != "" {
					key += "\x00" + prefix
				}
			}
			sum := sha256.Sum256([]byte(key))
			return "git:" + hex.EncodeToString(sum[:])[:16]
		}
	}
	return "name:" + projectName
}

// gitOutput runs git in dir and returns its trimmed stdout.
func gitOutput(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	command.WaitDelay = time.Second
	out, err := command.Output()
	return strings.TrimSpace(string(out)), err
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
