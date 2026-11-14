package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/gitutil"
)

// secretPattern holds a regex pattern and its human-readable description.
type secretPattern struct {
	pattern     *regexp.Regexp
	description string
	// free patterns carry their own context (a PEM header, a URL) and skip
	// the token boundary and placeholder tests.
	free bool
	// fixed marks a token of fixed length: the character after it must not
	// continue the token, or the match is a slice of something longer.
	fixed bool
	// class is the set of characters that would continue the token on
	// either side. Empty means letters, digits, "_", and "-".
	class string
	// accept, when set, has the final say on a match.
	accept func(match string) bool
}

// tokenChars continue a token: a match with one of these right before it is
// the tail of a longer identifier (task-..., GOOGLE_CLOUD_...), not a key.
const tokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

// base64Chars adds the characters that only occur in base64 runs, for short
// prefixes that turn up by chance inside lockfile hashes and inlined assets.
const base64Chars = tokenChars + "+/"

func tok(expr, description string) secretPattern {
	return secretPattern{pattern: regexp.MustCompile(expr), description: description}
}

func fixedTok(expr, description string) secretPattern {
	return secretPattern{pattern: regexp.MustCompile(expr), description: description, fixed: true}
}

func freePattern(expr, description string) secretPattern {
	return secretPattern{pattern: regexp.MustCompile(expr), description: description, free: true}
}

// secretPatterns are the shapes that indicate a potential secret.
var secretPatterns = []secretPattern{
	// Payments
	tok(`sk_live_[a-zA-Z0-9]{24,}`, "Stripe live key"),
	tok(`sk_test_[a-zA-Z0-9]{24,}`, "Stripe test key"),
	tok(`rk_live_[a-zA-Z0-9]{24,}`, "Stripe restricted key"),
	tok(`rk_test_[a-zA-Z0-9]{24,}`, "Stripe restricted test key"),
	tok(`whsec_[a-zA-Z0-9]{32,}`, "Stripe webhook secret"),
	tok(`pdl_live_[a-zA-Z0-9]{32,}`, "Paddle live API key"),
	tok(`pdl_test_[a-zA-Z0-9]{32,}`, "Paddle test API key"),
	tok(`sqsp_[a-zA-Z0-9]{50,}`, "LemonSqueezy API key"),
	fixedTok(`shpat_[a-fA-F0-9]{32}`, "Shopify access token"),

	// AI Providers
	tok(`sk-[a-zA-Z0-9]{48,}`, "OpenAI API key"),
	tok(`sk-proj-[a-zA-Z0-9_-]{48,}`, "OpenAI project key"),
	tok(`sk-svcacct-[a-zA-Z0-9_-]{48,}`, "OpenAI service account key"),
	tok(`sk-ant-[a-zA-Z0-9_-]{90,}`, "Anthropic API key"),
	{pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), description: googleAPIKeyType, fixed: true, class: base64Chars},
	fixedTok(`r8_[a-zA-Z0-9]{37}`, "Replicate API token"),
	fixedTok(`hf_[a-zA-Z0-9]{34}`, "Hugging Face API token"),
	tok(`xai-[a-zA-Z0-9]{48,}`, "Grok/xAI API key"),
	tok(`pplx-[a-zA-Z0-9]{48,}`, "Perplexity API key"),

	// Cloud & Infrastructure
	fixedTok(`AKIA[0-9A-Z]{16}`, "AWS Access Key ID"),
	fixedTok(`ASIA[0-9A-Z]{16}`, "AWS temporary Access Key ID"),
	freePattern(`(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]`, "AWS Secret Access Key"),
	// A Cloud Storage HMAC access ID: GOOG, then uppercase letters and
	// digits only. The pattern used to allow lowercase, "_", and "-", so
	// it matched any long identifier starting GOOGLE_.
	{pattern: regexp.MustCompile(`GOOG[0-9A-Z]{20,57}`), description: "Google Cloud HMAC access ID", fixed: true, class: base64Chars, accept: hasDigit},
	fixedTok(`dop_v1_[a-f0-9]{64}`, "DigitalOcean access token"),

	// Auth Providers
	tok(`sbp_[a-zA-Z0-9]{40,}`, "Supabase service key"),

	// Communication
	tok(`xox[baprs]-[a-zA-Z0-9-]{10,}`, "Slack token"),
	tok(`xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]{32,}`, "Slack app-level token"),
	freePattern(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`, "Slack webhook URL"),
	{pattern: regexp.MustCompile(`[MN][A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`), description: "Discord bot token", fixed: true, class: tokenChars + "."},

	// Email
	fixedTok(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, "SendGrid API key"),
	fixedTok(`key-[a-f0-9]{32}`, "Mailgun API key"),
	tok(`re_[a-zA-Z0-9]{32,}`, "Resend API key"),
	tok(`re_[a-zA-Z0-9]{8}_[a-zA-Z0-9]{20,}`, "Resend API key"),

	// Version Control
	fixedTok(`ghp_[a-zA-Z0-9]{36}`, "GitHub personal access token"),
	fixedTok(`gho_[a-zA-Z0-9]{36}`, "GitHub OAuth token"),
	fixedTok(`ghu_[a-zA-Z0-9]{36}`, "GitHub user-to-server token"),
	fixedTok(`ghs_[a-zA-Z0-9]{36}`, "GitHub server-to-server token"),
	fixedTok(`ghr_[a-zA-Z0-9]{36}`, "GitHub refresh token"),
	fixedTok(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`, "GitHub fine-grained PAT"),
	tok(`glpat-[a-zA-Z0-9_-]{20,}`, "GitLab personal access token"),
	tok(`gldt-[a-zA-Z0-9_-]{20,}`, "GitLab deploy token"),
	fixedTok(`npm_[a-zA-Z0-9]{36}`, "npm access token"),

	// Private Keys
	freePattern(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, "Private key"),
	freePattern(`-----BEGIN PGP PRIVATE KEY BLOCK-----`, "PGP private key"),

	// Google OAuth
	tok(`ya29\.[0-9A-Za-z_-]+`, "Google OAuth access token"),

	// A password inside a connection or repository URL.
	{pattern: reURLCredentials, description: urlCredentialsType, free: true, accept: urlHoldsRealCredentials},
}

// secretSkipDirs are skipped by name: dependencies and build output. Inside
// a git repository the name only decides for files git does not track; a
// tracked build/release.sh is carried by version control like any other file.
var secretSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"coverage":     true,
	"tmp":          true,
}

// secretExtensions are the file types scanned: source, templates, config and
// infra files. Markdown stays out on purpose, since docs routinely show
// example keys.
var secretExtensions = map[string]bool{
	// JavaScript and friends, including ESM/CJS configs and SFCs
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".cts": true,
	".tsx": true, ".jsx": true, ".vue": true, ".svelte": true, ".astro": true,
	// Server languages
	".rb": true, ".py": true, ".php": true, ".go": true, ".java": true, ".kt": true,
	".kts": true, ".scala": true, ".groovy": true, ".gradle": true, ".cs": true,
	".rs": true, ".swift": true, ".dart": true, ".ex": true, ".exs": true,
	".lua": true, ".pl": true,
	// Drupal and older PHP projects keep PHP in these
	".module": true, ".inc": true, ".theme": true, ".install": true, ".profile": true, ".engine": true,
	// Templates
	".html": true, ".htm": true, ".erb": true, ".twig": true, ".liquid": true,
	".njk": true, ".hbs": true,
	// Config and infrastructure
	".yml": true, ".yaml": true, ".json": true, ".toml": true, ".xml": true,
	".properties": true, ".tf": true, ".tfvars": true, ".tfstate": true, ".hcl": true,
	".pem": true, ".key": true, ".p8": true,
	".env": true, ".conf": true, ".cfg": true, ".ini": true, ".txt": true,
	".npmrc": true, ".pypirc": true, ".netrc": true,
	".sql": true,
	// Shell
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
}

// secretFileInScope reports whether a file is one the scan reads, by name.
// Extensionless files are in scope (a bare "secret" or "Dockerfile"), as are
// the dotenv family (filepath.Ext(".env.production") is ".production") and
// Dockerfile.prod style names.
func secretFileInScope(baseName string) bool {
	ext := filepath.Ext(baseName)
	return ext == "" || secretExtensions[ext] || strings.HasPrefix(baseName, ".env") || strings.HasPrefix(baseName, "Dockerfile.")
}

type SecretScanCheck struct{}

func (c SecretScanCheck) ID() string {
	return "secrets"
}

func (c SecretScanCheck) Title() string {
	return "Secrets scan"
}

func (c SecretScanCheck) Run(ctx Context) (CheckResult, error) {
	// Resolve git status once. A secrets scanner's job is to catch
	// secrets that version control will carry, so git, not the filename,
	// is the authority on what's in scope when we're inside a repo.
	git := loadGitStatus(ctx.RootDir)
	// Without git, the root .gitignore is the next best statement of what
	// the project means to keep out of version control.
	var ignoreRules gitignoreRules
	if !git.inRepo {
		ignoreRules = loadRootGitignore(ctx.RootDir)
	}

	var findings []secretFinding
	// Files over the cap are skipped: past 2MB a file is a data dump, a
	// bundle or a fixture, slow to scan and noisy when it is. Skipping one
	// makes the scan inconclusive only when git tracks it and it looks like
	// source or config (oversizedNeedsScan); an untracked file or a tracked
	// dump does not fail the check.
	maxFileSize := int64(maxSecretFileSize)
	var skippedSource []string
	filesScanned := 0
	filesErrored := 0

	err := filepath.Walk(ctx.RootDir, func(path string, info os.FileInfo, err error) error {
		rel := filepath.ToSlash(relPath(ctx.RootDir, path))
		if err != nil {
			if info != nil && info.IsDir() {
				// A directory the scan would have skipped anyway is not
				// a gap in it.
				if !secretDirSkipped(path, rel, git, ignoreRules) {
					filesErrored++
				}
				return filepath.SkipDir
			}
			filesErrored++
			return nil
		}

		if info.IsDir() {
			if path != ctx.RootDir && secretDirSkipped(path, rel, git, ignoreRules) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks, devices, pipes: anything not a plain file. A
		// hostile project could otherwise drop a symlink named like an
		// in-scope source file (`leak.env` -> `~/.aws/credentials`,
		// `bigfile.js` -> `/dev/zero`) and trick the scanner into
		// reading outside the project root or hanging on a device.
		if !info.Mode().IsRegular() {
			return nil
		}

		baseName := filepath.Base(path)
		if !secretFileInScope(baseName) {
			return nil
		}

		// Decide scope. Inside a git repo, git is authoritative: a file
		// that's ignored AND untracked will never be committed, so it's
		// allowed to hold real secrets. Everything else is in scope,
		// including a tracked file that happens to be listed in
		// .gitignore (git keeps tracking files added before the ignore
		// rule), which is the dangerous case a plain .gitignore-text
		// check would miss.
		state := ""
		if git.inRepo {
			tracked := git.tracked[rel]
			if !tracked && (git.ignored[rel] || underNameSkippedDir(rel)) {
				// Untracked build output and dependencies stay out,
				// as they always have.
				return nil
			}
			if tracked {
				state = "tracked"
			} else {
				// Untracked and not ignored: `git add .` would commit it.
				state = "committable"
			}
		} else if ignoreRules.match(rel, false) || strings.HasSuffix(baseName, ".local") {
			// Not a git repo: the root .gitignore says what is meant to
			// stay out, and the .env*.local family holds real secrets by
			// convention and is never committed.
			return nil
		}

		if info.Size() > maxFileSize {
			if state == "tracked" && oversizedNeedsScan(baseName) {
				skippedSource = append(skippedSource, rel)
			}
			return nil
		}
		if ctx.reqContext().Err() != nil {
			return ctx.reqContext().Err()
		}
		fileFindings, scanErr := scanFileForSecrets(path, secretPatterns)
		if scanErr != nil {
			filesErrored++
		}
		for i := range fileFindings {
			fileFindings[i].gitState = state
		}
		findings = append(findings, fileFindings...)
		filesScanned++

		return nil
	})

	findings = applySecretAllowlist(findings, ctx)

	if err != nil {
		return CheckResult{
			ID:           c.ID(),
			Title:        c.Title(),
			Severity:     SeverityWarn,
			Passed:       false,
			Message:      fmt.Sprintf("Error scanning files: %v", err),
			Inconclusive: true,
		}, nil
	}

	// Build scan summary
	scanSummary := fmt.Sprintf("Scanned %d files", filesScanned)
	if len(skippedSource) > 0 {
		scanSummary += fmt.Sprintf(", %d tracked file(s) over %dMB not scanned (%s)", len(skippedSource), maxSecretFileSize>>20, strings.Join(skippedSource[:min(3, len(skippedSource))], ", "))
	}
	if filesErrored > 0 {
		scanSummary += fmt.Sprintf(", %d files could not be read", filesErrored)
	}
	// A repository git could not read leaves the scan without its
	// authority on what is committed. Say so instead of guessing.
	if git.failure != "" {
		scanSummary += ", " + git.failure + " so committed files could not be told from ignored ones"
	}
	incomplete := filesErrored > 0 || len(skippedSource) > 0 || git.failure != ""

	if len(findings) == 0 && incomplete {
		return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityWarn, Inconclusive: true, Message: "Secret scan incomplete: " + scanSummary}, nil
	}
	if len(findings) == 0 {
		message := "No secrets detected in committable files"
		if !git.inRepo {
			message = "No secrets detected"
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  message,
		}, nil
	}

	// Build detailed message with secret types
	displayFindings := findings
	if len(displayFindings) > 5 {
		displayFindings = displayFindings[:5]
	}

	var displayMessages []string
	for _, f := range displayFindings {
		rp := relPath(ctx.RootDir, f.file)
		tag := ""
		switch f.gitState {
		case "tracked":
			tag = " [tracked by git]"
		case "committable":
			tag = " [not gitignored]"
		}
		displayMessages = append(displayMessages, fmt.Sprintf("%s:%d (%s)%s", rp, f.line, f.secretType, tag))
	}

	suffix := ""
	if len(findings) > 5 {
		suffix = fmt.Sprintf(" (and %d more)", len(findings)-5)
	}

	// Message is one line (it is rendered on one line everywhere and
	// redacted before publishing); the per-finding locations go in
	// Suggestions, which the terminal prints and the dashboard never sees.
	message := fmt.Sprintf("Potential secrets found in %d place(s)", len(findings))
	if suffix != "" {
		displayMessages[len(displayMessages)-1] += suffix
	}

	// Two kinds of finding are a warning on their own. Browser-side Google
	// keys ship to every visitor by design, so the fix is a referrer
	// restriction, not removal. A key-shaped value in an example file that
	// is not an obvious placeholder is worth checking, but the file is
	// there to show key shapes.
	browser, example := 0, 0
	for _, f := range findings {
		switch {
		case f.browserKey:
			browser++
		case f.example:
			example++
		}
	}
	severity := SeverityError
	advice := []string{
		"Remove secrets from source code",
		"Use environment variables instead",
		"Add sensitive files to .gitignore",
		"Consider using git-crypt or similar for encrypted secrets",
	}
	switch {
	case browser == len(findings):
		severity = SeverityWarn
		message = fmt.Sprintf("Browser-side Google API key(s) in %d place(s), check they are restricted by HTTP referrer", len(findings))
	case browser+example == len(findings):
		severity = SeverityWarn
		message = fmt.Sprintf("Key-shaped values in example files in %d place(s), check they are placeholders and not real keys", len(findings))
		advice = []string{
			"Replace real values in example files with obvious placeholders (your_key_here)",
			"If a real key was committed, rotate it",
		}
	}
	if incomplete {
		message += " (" + scanSummary + ")"
	}

	return CheckResult{
		ID:           c.ID(),
		Title:        c.Title(),
		Severity:     severity,
		Passed:       false,
		Inconclusive: incomplete,
		Message:      message,
		Suggestions:  append(displayMessages, advice...),
	}, nil
}

// secretDirSkipped reports whether the walk stays out of a directory.
func secretDirSkipped(path, rel string, git gitStatus, rules gitignoreRules) bool {
	name := filepath.Base(path)
	if name == ".git" {
		return true
	}
	if git.inRepo {
		// A directory git tracks files under is walked whatever it is
		// called; the per-file test keeps untracked content out.
		if git.trackedDirs[rel] {
			return false
		}
		return git.ignoredDirs[rel] || nameSkippedDir(name) || isAgentWorktreesDir(path)
	}
	return nameSkippedDir(name) || isAgentWorktreesDir(path) || rules.match(rel, true)
}

func nameSkippedDir(name string) bool {
	return secretSkipDirs[name] || toolchainDirs[name]
}

// underNameSkippedDir reports whether a project-relative file path sits
// below a directory skipped by name.
func underNameSkippedDir(rel string) bool {
	dir, _ := pathSplit(rel)
	for dir != "" {
		var name string
		dir, name = pathSplit(dir)
		if nameSkippedDir(name) || (name == "worktrees" && (dir == ".claude" || strings.HasSuffix(dir, "/.claude"))) {
			return true
		}
	}
	return false
}

// pathSplit splits a slash-separated path into its parent and last element.
func pathSplit(p string) (dir, name string) {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

type secretFinding struct {
	file        string
	line        int
	secretType  string
	fingerprint string // "sha256:<hex>" of the matched secret value
	gitState    string // "tracked", "committable", or "" (not a git repo)
	// browserKey marks a Google API key used from the browser (Maps, a
	// Firebase web config), which is public by design and secured by
	// referrer restrictions rather than secrecy.
	browserKey bool
	// example marks a finding in a file that documents settings
	// (.env.example). What survives the placeholder tests there is worth a
	// look, but it is a warning: the file exists to show key shapes.
	example bool
}

// googleAPIKeyType labels AIza keys. They serve Maps, Firebase, Gemini and
// every other Google API alike, so the label names none of them.
const googleAPIKeyType = "Google API key" //nolint:gosec // a finding label, not a credential

// browserGoogleKeyHints on the same line mark a key meant for the browser.
var browserGoogleKeyHints = []string{"maps.googleapis.com", "maps/api/js", "google.maps", "firebaseconfig", "authdomain"}

// browserServedDirs hold files shipped to the browser as they are.
var browserServedDirs = []string{"public/", "static/", "assets/", "web/js/", "wwwroot/"}

// isBrowserGoogleKey reports whether an AIza key on line looks like a
// browser-side key: used with Maps or a Firebase web config, or committed in
// a directory served to browsers.
func isBrowserGoogleKey(path, line string) bool {
	lower := strings.ToLower(line)
	for _, h := range browserGoogleKeyHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	slashed := filepath.ToSlash(path)
	for _, d := range browserServedDirs {
		if strings.Contains(slashed, "/"+d) {
			return true
		}
	}
	return false
}

// gitStatus captures which project-relative paths git is tracking and
// which untracked paths it ignores. Paths use forward slashes.
type gitStatus struct {
	inRepo bool
	// failure is set when root is inside a repository that git could not
	// read (git missing, a refused or broken repository, a timeout). The
	// scan then falls back to filename rules and reports itself incomplete.
	failure     string
	tracked     map[string]bool
	trackedDirs map[string]bool // every directory holding a tracked file
	ignored     map[string]bool // ignored untracked files
	ignoredDirs map[string]bool // directories ignored as a whole
}

// loadGitStatus shells out to git once to learn the tracked and
// ignored-untracked file sets for root. If root isn't in a git work tree,
// inRepo is false and callers fall back to filename rules. If it is but git
// cannot say what is tracked, failure names why. Paths are reported relative
// to root because every git invocation runs with -C root.
func loadGitStatus(root string) gitStatus {
	st := gitStatus{
		tracked: map[string]bool{}, trackedDirs: map[string]bool{},
		ignored: map[string]bool{}, ignoredDirs: map[string]bool{},
	}
	if !hasGitMarker(root) {
		return st
	}
	fail := func(stderr string, err error) gitStatus {
		st.failure = gitFailureReason(stderr, err)
		return st
	}

	out, stderr, err := gitOutput(root, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return fail(stderr, err)
	}
	if strings.TrimSpace(out) != "true" {
		// Inside a .git directory or a bare repository: no work tree.
		return st
	}

	tracked, stderr, err := gitOutput(root, "ls-files", "-z")
	if err != nil {
		return fail(stderr, err)
	}
	// --others limits to untracked files; --ignored --exclude-standard
	// restricts that to the ones the standard ignore rules exclude. A
	// tracked-but-ignored file therefore never lands here, which is what
	// keeps it in scope. --directory reports a wholly ignored directory
	// (node_modules/) as one entry instead of listing every file in it.
	ignored, stderr, err := gitOutput(root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
	if err != nil {
		return fail(stderr, err)
	}

	st.inRepo = true
	for _, p := range strings.Split(tracked, "\x00") {
		if p == "" {
			continue
		}
		p = filepath.ToSlash(p)
		st.tracked[p] = true
		for dir, _ := pathSplit(p); dir != "" && !st.trackedDirs[dir]; dir, _ = pathSplit(dir) {
			st.trackedDirs[dir] = true
		}
	}
	for _, p := range strings.Split(ignored, "\x00") {
		if p == "" {
			continue
		}
		p = filepath.ToSlash(p)
		if strings.HasSuffix(p, "/") {
			st.ignoredDirs[strings.TrimSuffix(p, "/")] = true
		} else {
			st.ignored[p] = true
		}
	}
	return st
}

// hasGitMarker reports whether root or one of its parents holds a .git entry
// (a directory, or the file a worktree or submodule uses).
func hasGitMarker(root string) bool {
	dir, err := filepath.Abs(root)
	if err != nil {
		dir = root
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// gitFailureReason turns a failed git call into a short clause for the
// result message. It never includes git's own output, which names absolute
// paths.
func gitFailureReason(stderr string, err error) string {
	lower := strings.ToLower(stderr)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return "git is not installed"
	case errors.Is(err, context.DeadlineExceeded):
		return "git timed out"
	case strings.Contains(lower, "dubious ownership") || strings.Contains(lower, "safe.directory"):
		return "git refuses this repository (owned by another user, see safe.directory)"
	}
	return "git could not read this repository"
}

// gitOutput runs `git -C root <args...>` through gitutil.Command and returns
// stdout and stderr. The listings of a large repository take longer than
// runGit's budget allows.
func gitOutput(root string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := gitutil.Command(ctx, root, args...)
	cmd.WaitDelay = time.Second
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return outBuf.String(), errBuf.String(), err
}

// gitignoreRules is a small reading of one .gitignore, used only where git
// itself is not available to ask. It covers the common forms (names, globs,
// directory rules, anchored paths, negation) and not git's full grammar.
type gitignoreRules []gitignoreRule

type gitignoreRule struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
}

func loadRootGitignore(root string) gitignoreRules {
	data, err := readSourceFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return nil
	}
	var rules gitignoreRules
	for _, line := range strings.Split(strings.TrimPrefix(string(data), string(rune(0xFEFF))), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := gitignoreRule{}
		if strings.HasPrefix(line, "!") {
			r.negate = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		// A slash anywhere but the end ties the pattern to the root.
		r.anchored = strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" || !doublestar.ValidatePattern(line) {
			continue
		}
		r.pattern = line
		rules = append(rules, r)
	}
	return rules
}

// match reports whether the rules ignore a project-relative path. The last
// matching rule wins, as in git.
func (rules gitignoreRules) match(rel string, isDir bool) bool {
	ignored := false
	_, base := pathSplit(rel)
	for _, r := range rules {
		if r.dirOnly && !isDir {
			continue
		}
		var ok bool
		if r.anchored {
			ok, _ = doublestar.Match(r.pattern, rel)
		} else {
			ok, _ = doublestar.Match(r.pattern, base)
		}
		if ok {
			ignored = !r.negate
		}
	}
	return ignored
}

// runGit runs `git -C root <args...>` and returns stdout. Stderr is
// discarded; callers only care whether the command succeeded. The scanned
// repo controls its own git config, so this goes through gitutil.Command,
// which keeps that config from running commands.
func runGit(root string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := gitutil.Command(ctx, root, args...)
	cmd.WaitDelay = time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	err := cmd.Run()
	return stdout.String(), err
}

// fingerprintSecret returns "sha256:<hex>" for a matched secret value.
func fingerprintSecret(match string) string {
	sum := sha256.Sum256([]byte(match))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// applySecretAllowlist drops findings that match an entry in
// checks.secrets.allowlist. An entry matches when the doublestar glob
// in `path` matches the project-relative file path; if `fingerprint`
// is also set, the finding's fingerprint must match exactly. This means
// rotating a secret invalidates the allowlist entry and the finding
// re-alerts, which is the point.
func applySecretAllowlist(findings []secretFinding, ctx Context) []secretFinding {
	if ctx.Config == nil || ctx.Config.Checks.Secrets == nil || len(ctx.Config.Checks.Secrets.Allowlist) == 0 {
		return findings
	}
	entries := ctx.Config.Checks.Secrets.Allowlist

	var kept []secretFinding
	for _, f := range findings {
		rel, err := filepath.Rel(ctx.RootDir, f.file)
		if err != nil {
			rel = f.file
		}
		rel = filepath.ToSlash(rel)

		if matchesSecretAllowlist(rel, f.fingerprint, entries) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

func matchesSecretAllowlist(relPath, fingerprint string, entries []config.SecretAllowlistEntry) bool {
	for _, e := range entries {
		if e.Path == "" {
			continue
		}
		pattern := filepath.ToSlash(e.Path)
		ok, err := doublestar.Match(pattern, relPath)
		if err != nil || !ok {
			continue
		}
		if e.Fingerprint != "" && e.Fingerprint != fingerprint {
			continue
		}
		return true
	}
	return false
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func scanFileForSecrets(path string, patterns []secretPattern) ([]secretFinding, error) {
	var findings []secretFinding

	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// One byte past the cap is enough to tell a file that grew after the
	// walker measured it from one that fits exactly.
	counter := &countingReader{r: io.LimitReader(file, maxSecretFileSize+1)}
	scanner := bufio.NewScanner(counter)
	// A minified bundle can legally be a single line at the walker's cap.
	// Give the scanner enough headroom so the whole file fits in one token
	// instead of being silently skipped.
	const maxLine = maxSecretFileSize + 1
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	lineNum := 0
	// Key-block headers wait for the lines after them.
	example := isExampleFile(filepath.Base(path))
	var lines []string
	type keyHeader struct{ finding, line, col int }
	var headers []keyHeader

	for scanner.Scan() {
		lineNum++
		if counter.n > maxSecretFileSize {
			return findings, fmt.Errorf("incomplete scan: file exceeds read budget")
		}
		line := scanner.Text()
		lines = append(lines, line)

		// Collect every match on the line, not just the first one. If a
		// line contains an allowlisted token AND a real secret,
		// recording only the first would let applySecretAllowlist drop
		// the allowlisted finding while the real one was never seen.
		// Dedupe by fingerprint so two patterns that match the same
		// exact substring don't double-report.
		seen := map[string]struct{}{}
		for _, sp := range patterns {
			for _, loc := range sp.pattern.FindAllStringIndex(line, -1) {
				m := line[loc[0]:loc[1]]
				if !sp.plausible(line, loc[0], loc[1]) {
					continue
				}
				fp := fingerprintSecret(m)
				if _, dup := seen[fp]; dup {
					continue
				}
				seen[fp] = struct{}{}
				// A header that opens its line is a key block as laid
				// out in a key file. One inside a string or after KEY=
				// is a key only if key material follows, and in an
				// example file that holds for both.
				if strings.HasPrefix(m, "-----BEGIN") && (example || strings.TrimSpace(line[:loc[0]]) != "") {
					headers = append(headers, keyHeader{len(findings), lineNum - 1, loc[1]})
				}
				findings = append(findings, secretFinding{
					file:        path,
					line:        lineNum,
					secretType:  sp.description,
					fingerprint: fp,
					browserKey:  sp.description == googleAPIKeyType && isBrowserGoogleKey(path, line),
					example:     example,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("incomplete scan of %s: %w", path, err)
	}

	// A file showing the shape of a key setting
	// (KEY="-----BEGIN RSA PRIVATE KEY-----\nYour private key here..."),
	// or code that handles one (s.replace("-----BEGIN PRIVATE KEY-----", "")),
	// names a header without holding a key. Only a header followed by key
	// material is a key.
	if len(headers) > 0 {
		drop := map[int]bool{}
		for _, h := range headers {
			if !keyMaterialFollows(lines, h.line, h.col) {
				drop[h.finding] = true
			}
		}
		kept := findings[:0]
		for i, f := range findings {
			if !drop[i] {
				kept = append(kept, f)
			}
		}
		findings = kept
	}

	return findings, nil
}

// plausible reports whether the match at line[start:end] can be a secret:
// it stands on its own instead of being a slice of a longer identifier, and
// it is not a placeholder.
func (sp secretPattern) plausible(line string, start, end int) bool {
	m := line[start:end]
	if sp.accept != nil && !sp.accept(m) {
		return false
	}
	if sp.free {
		return true
	}
	class := sp.class
	if class == "" {
		class = tokenChars
	}
	if start > 0 && strings.IndexByte(class, line[start-1]) >= 0 {
		return false
	}
	if sp.fixed && end < len(line) && strings.IndexByte(class, line[end]) >= 0 {
		return false
	}
	return !looksLikePlaceholder(m)
}

// placeholderWords mark a value written to show a key's shape. A random
// token of the lengths matched here contains one by chance about once in
// tens of thousands of keys.
var placeholderWords = []string{
	"example", "placeholder", "changeme", "your", "dummy", "redacted",
	"sample", "fake", "xxxx", "0000000", "1234567", "abcdef",
}

var reAlnumRun = regexp.MustCompile(`[A-Za-z0-9]+`)

// looksLikePlaceholder reports a key-shaped value that is not a key:
// AKIAIOSFODNN7EXAMPLE, ghp_xxxxxxxx..., sk_test_your_key_here, or a body
// drawn from a handful of characters. Real keys are random.
func looksLikePlaceholder(match string) bool {
	lower := strings.ToLower(match)
	for _, w := range placeholderWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	// The longest run of letters and digits is the key body.
	body := ""
	for _, run := range reAlnumRun.FindAllString(match, -1) {
		if len(run) > len(body) {
			body = run
		}
	}
	if len(body) < 16 {
		return false
	}
	distinct := map[rune]bool{}
	for _, r := range body {
		distinct[r] = true
	}
	return len(distinct) < 6
}

func hasDigit(s string) bool {
	return strings.ContainsAny(s, "0123456789")
}

// urlCredentialsType labels a password embedded in a URL.
const urlCredentialsType = "Credentials in a URL" //nolint:gosec // a finding label, not a credential

// reURLCredentials matches scheme://user:password@host for the schemes that
// carry credentials this way: databases, brokers, mail, file transfer, and
// HTTP basic auth (package registries, git remotes).
var reURLCredentials = regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|smtps?|s?ftp|ftps|https?)://([^\s:/@'"<>]+):([^\s@/'"<>]+)@([A-Za-z0-9.-]+)`)

// urlPlaceholderPasswords are the values that fill the password slot in
// docs, compose files, and local defaults.
var urlPlaceholderPasswords = []string{
	"password", "passwd", "secret", "changeme", "example", "placeholder",
	"your", "xxx", "token", "apikey", "api_key", "redacted", "dummy", "fake",
	"test", "demo", "admin", "root", "qwerty", "letmein", "hunter",
}

// unleet undoes the digit-for-letter spelling fixtures and docs use for a
// stand-in password (s3cr3t, p4ssw0rd), so the placeholder words match it.
var unleet = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a")

var reIPv4Host = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// isPrivateIPv4Host reports a host written as an address that is only
// reachable inside a network: a fixture or a local service, not a leak
// anyone outside could use.
func isPrivateIPv4Host(host string) bool {
	if !reIPv4Host.MatchString(host) {
		return false
	}
	for _, prefix := range []string{"10.", "127.", "192.168.", "169.254.", "0."} {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}
	if rest, ok := strings.CutPrefix(host, "172."); ok {
		second, _, _ := strings.Cut(rest, ".")
		return len(second) == 2 && second >= "16" && second <= "31"
	}
	return false
}

// urlLocalHostSuffixes are hosts that only exist on a developer's machine or
// in documentation.
var urlLocalHostSuffixes = []string{
	".local", ".localhost", ".test", ".internal", ".example", ".invalid", ".lan",
	"example.com", "example.org", "example.net",
}

// urlHoldsRealCredentials reports whether a scheme://user:password@host
// match looks like a real password for a real host. Interpolations
// (${DB_PASS}, %s, <password>), placeholder words, a password equal to the
// user name, and local or documentation hosts are all left alone: those are
// templates and development defaults, not leaks.
func urlHoldsRealCredentials(match string) bool {
	sub := reURLCredentials.FindStringSubmatch(match)
	if sub == nil {
		return false
	}
	user, pass, host := sub[1], sub[2], strings.ToLower(strings.Trim(sub[3], ".-"))
	if strings.ContainsAny(user+pass, "${}*[]()#") || strings.Contains(pass, "%s") || strings.Contains(pass, "%d") {
		return false
	}
	lowerPass := strings.ToLower(pass)
	if len(pass) < 6 || lowerPass == strings.ToLower(user) {
		return false
	}
	plain := unleet.Replace(lowerPass)
	for _, w := range urlPlaceholderPasswords {
		if strings.Contains(lowerPass, w) || strings.Contains(plain, w) {
			return false
		}
	}
	if looksLikePlaceholder(pass) {
		return false
	}
	// A host with no dot is a compose service name or localhost.
	if !strings.Contains(host, ".") || isPrivateIPv4Host(host) {
		return false
	}
	for _, suffix := range urlLocalHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}

// maxSecretFileSize caps the files the secret scan reads.
const maxSecretFileSize = 2 << 20

// oversizedNeedsScan reports whether skipping an oversized tracked file
// leaves a gap worth reporting. Hand-written source and config that large is
// unusual and could hold anything. Data dumps (.json, .sql, .csv, .txt, .log,
// .xml) and generated bundles and maps (app.min.js, main.bundle.js) are
// exported or rebuilt rather than edited, and a secret scan that went
// inconclusive on every committed fixture would be ignored.
func oversizedNeedsScan(baseName string) bool {
	lower := strings.ToLower(baseName)
	switch filepath.Ext(lower) {
	case ".json", ".jsonl", ".ndjson", ".geojson", ".sql", ".csv", ".tsv", ".txt", ".log", ".xml", ".map", ".lock":
		return false
	}
	for _, generated := range []string{".min.", ".bundle.", ".chunk.", "-bundle."} {
		if strings.Contains(lower, generated) {
			return false
		}
	}
	return true
}

// isExampleFile reports a file committed to document settings rather than
// hold them: .env.example, settings.sample.py, config.template.yml,
// phpunit.xml.dist.
func isExampleFile(baseName string) bool {
	parts := strings.Split(strings.ToLower(baseName), ".")
	for _, marker := range []string{"example", "sample", "template", "dist"} {
		if slices.Contains(parts[1:], marker) {
			return true
		}
	}
	return false
}

var reBase64Run = regexp.MustCompile(`^[A-Za-z0-9+/=]{40,}$`)

// keyMaterialFollows reports whether the text after a key-block header (at
// lines[line][col:]) holds base64 key material before the END line: on the
// next lines, or after a literal \n in a quoted one-line value. A run of
// one repeated filler character is not material.
func keyMaterialFollows(lines []string, line, col int) bool {
	text := lines[line][col:]
	for i := line + 1; i < len(lines) && i <= line+5; i++ {
		text += "\n" + lines[i]
	}
	text = strings.NewReplacer(`\r`, "\n", `\n`, "\n").Replace(text)
	for _, seg := range strings.Split(text, "\n") {
		seg = strings.Trim(strings.TrimSpace(seg), `"',\`)
		if strings.HasPrefix(seg, "-----END") {
			return false
		}
		if !reBase64Run.MatchString(seg) {
			continue
		}
		distinct := map[rune]bool{}
		for _, r := range seg {
			distinct[r] = true
		}
		if len(distinct) >= 16 {
			return true
		}
	}
	return false
}
