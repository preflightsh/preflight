package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// secretPattern holds a regex pattern and its human-readable description
type secretPattern struct {
	pattern     *regexp.Regexp
	description string
}

type SecretScanCheck struct{}

func (c SecretScanCheck) ID() string {
	return "secrets"
}

func (c SecretScanCheck) Title() string {
	return "Secrets scan"
}

func (c SecretScanCheck) Run(ctx Context) (CheckResult, error) {
	// Patterns that indicate potential secrets
	patterns := []secretPattern{
		// Payments
		{regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "Stripe live key"},
		{regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`), "Stripe test key"},
		{regexp.MustCompile(`rk_live_[a-zA-Z0-9]{24,}`), "Stripe restricted key"},
		{regexp.MustCompile(`whsec_[a-zA-Z0-9]{32,}`), "Stripe webhook secret"},
		{regexp.MustCompile(`pdl_live_[a-zA-Z0-9]{32,}`), "Paddle live API key"},
		{regexp.MustCompile(`pdl_test_[a-zA-Z0-9]{32,}`), "Paddle test API key"},
		{regexp.MustCompile(`sqsp_[a-zA-Z0-9]{50,}`), "LemonSqueezy API key"},

		// AI Providers
		{regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`), "OpenAI API key"},
		{regexp.MustCompile(`sk-proj-[a-zA-Z0-9_-]{48,}`), "OpenAI project key"},
		{regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{90,}`), "Anthropic API key"},
		{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "Google AI/Firebase API key"},
		{regexp.MustCompile(`r8_[a-zA-Z0-9]{37}`), "Replicate API token"},
		{regexp.MustCompile(`hf_[a-zA-Z0-9]{34}`), "Hugging Face API token"},
		{regexp.MustCompile(`xai-[a-zA-Z0-9]{48,}`), "Grok/xAI API key"},
		{regexp.MustCompile(`pplx-[a-zA-Z0-9]{48,}`), "Perplexity API key"},

		// Cloud & Infrastructure
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID"},
		{regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]`), "AWS Secret Access Key"},
		{regexp.MustCompile(`GOOG[0-9a-zA-Z_-]{28,}`), "Google Cloud API key"},

		// Auth Providers
		{regexp.MustCompile(`sbp_[a-zA-Z0-9]{40,}`), "Supabase service key"},

		// Communication
		{regexp.MustCompile(`AC[a-f0-9]{32}`), "Twilio Account SID"},
		{regexp.MustCompile(`SK[a-f0-9]{32}`), "Twilio API Key SID"},
		{regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`), "Slack token"},
		{regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`), "Slack webhook URL"},
		{regexp.MustCompile(`[MN][A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`), "Discord bot token"},

		// Email
		{regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), "SendGrid API key"},
		{regexp.MustCompile(`key-[a-f0-9]{32}`), "Mailgun API key"},
		{regexp.MustCompile(`re_[a-zA-Z0-9]{32,}`), "Resend API key"},

		// Error Tracking
		{regexp.MustCompile(`https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io`), "Sentry DSN"},

		// Analytics
		{regexp.MustCompile(`phc_[a-zA-Z0-9]{32,}`), "PostHog project API key"},

		// Version Control
		{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub personal access token"},
		{regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), "GitHub OAuth token"},
		{regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`), "GitHub user-to-server token"},
		{regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), "GitHub server-to-server token"},
		{regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`), "GitHub refresh token"},
		{regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`), "GitHub fine-grained PAT"},
		{regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`), "GitLab personal access token"},
		{regexp.MustCompile(`gldt-[a-zA-Z0-9_-]{20,}`), "GitLab deploy token"},
		{regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`), "npm access token"},

		// Private Keys
		{regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY`), "Private key"},
		{regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK`), "PGP private key"},

		// Google OAuth
		{regexp.MustCompile(`ya29\.[0-9A-Za-z_-]+`), "Google OAuth access token"},
	}

	// Directories to skip
	skipDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		"dist":         true,
		"build":        true,
		".next":        true,
		"coverage":     true,
		"tmp":          true,
	}

	// File extensions to check
	codeExtensions := map[string]bool{
		".js":   true,
		".ts":   true,
		".tsx":  true,
		".jsx":  true,
		".rb":   true,
		".py":   true,
		".php":  true,
		".go":   true,
		".java": true,
		".yml":  true,
		".yaml": true,
		".json": true,
		".env":  true,
		".sh":   true,
		".bash": true,
		".zsh":  true,
		".conf": true,
		".cfg":  true,
		".ini":  true,
	}

	var findings []secretFinding
	maxFileSize := int64(1024 * 1024) // 1 MB

	err := filepath.Walk(ctx.RootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that are too large
		if info.Size() > maxFileSize {
			return nil
		}

		// Check extension
		ext := filepath.Ext(path)
		baseName := filepath.Base(path)

		// Also check files without extension that might contain secrets
		if !codeExtensions[ext] && ext != "" && baseName != ".env" {
			return nil
		}

		// Skip example env files - they shouldn't have real values
		if strings.Contains(baseName, ".example") || strings.Contains(baseName, ".sample") {
			return nil
		}

		// Skip local env files - these are meant to have secrets and shouldn't be committed
		if strings.HasSuffix(baseName, ".local") ||
			baseName == ".env.local" ||
			baseName == ".env.development.local" ||
			baseName == ".env.test.local" ||
			baseName == ".env.production.local" {
			return nil
		}

		// Scan file
		fileFindings := scanFileForSecrets(path, patterns)
		findings = append(findings, fileFindings...)

		return nil
	})

	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Error scanning files: " + err.Error(),
		}, nil
	}

	if len(findings) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No secrets detected in tracked files",
		}, nil
	}

	// Build detailed message with secret types
	displayFindings := findings
	if len(displayFindings) > 5 {
		displayFindings = displayFindings[:5]
	}

	var displayMessages []string
	for _, f := range displayFindings {
		relPath, err := filepath.Rel(ctx.RootDir, f.file)
		if err != nil {
			relPath = f.file
		}
		displayMessages = append(displayMessages, fmt.Sprintf("%s:%d (%s)", relPath, f.line, f.secretType))
	}

	suffix := ""
	if len(findings) > 5 {
		suffix = fmt.Sprintf(" (and %d more)", len(findings)-5)
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityError,
		Passed:   false,
		Message:  "Potential secrets found:\n  " + strings.Join(displayMessages, "\n  ") + suffix,
		Suggestions: []string{
			"Remove secrets from source code",
			"Use environment variables instead",
			"Add sensitive files to .gitignore",
			"Consider using git-crypt or similar for encrypted secrets",
		},
	}, nil
}

type secretFinding struct {
	file       string
	line       int
	secretType string
}

func scanFileForSecrets(path string, patterns []secretPattern) []secretFinding {
	var findings []secretFinding

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, sp := range patterns {
			if sp.pattern.MatchString(line) {
				findings = append(findings, secretFinding{
					file:       path,
					line:       lineNum,
					secretType: sp.description,
				})
				break // Only report one finding per line
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return findings
	}

	return findings
}
