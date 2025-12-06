package checks

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SecretScanCheck struct{}

func (c SecretScanCheck) ID() string {
	return "secrets"
}

func (c SecretScanCheck) Title() string {
	return "No secrets in tracked files"
}

func (c SecretScanCheck) Run(ctx Context) (CheckResult, error) {
	// Patterns that indicate potential secrets
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),                        // Stripe live key
		regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),                        // Stripe test key (still shouldn't be committed)
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                // AWS Access Key
		regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY`), // Private keys
		regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK`),                // PGP private key
		regexp.MustCompile(`POSTMARK_API_TOKEN\s*=\s*[a-f0-9-]{36}`),          // Postmark token with value
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),                             // GitHub personal access token
		regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),                             // GitHub OAuth token
		regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),      // GitHub fine-grained PAT
		regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`),                    // Slack tokens
		regexp.MustCompile(`ya29\.[0-9A-Za-z_-]+`),                            // Google OAuth token
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
		if !codeExtensions[ext] && ext != "" && baseName != ".env" && baseName != ".env.local" {
			return nil
		}

		// Skip example env files - they shouldn't have real values
		if strings.Contains(baseName, ".example") || strings.Contains(baseName, ".sample") {
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

	// Build message
	var messages []string
	for _, f := range findings {
		relPath, _ := filepath.Rel(ctx.RootDir, f.file)
		messages = append(messages, relPath+":"+string(rune(f.line))+": "+f.pattern)
	}

	// Limit message length
	displayFindings := findings
	if len(displayFindings) > 5 {
		displayFindings = displayFindings[:5]
	}

	var displayMessages []string
	for _, f := range displayFindings {
		relPath, _ := filepath.Rel(ctx.RootDir, f.file)
		displayMessages = append(displayMessages, relPath)
	}

	suffix := ""
	if len(findings) > 5 {
		suffix = " (and " + string(rune(len(findings)-5+'0')) + " more)"
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityError,
		Passed:   false,
		Message:  "Potential secrets found in: " + strings.Join(displayMessages, ", ") + suffix,
		Suggestions: []string{
			"Remove secrets from source code",
			"Use environment variables instead",
			"Add sensitive files to .gitignore",
			"Consider using git-crypt or similar for encrypted secrets",
		},
	}, nil
}

type secretFinding struct {
	file    string
	line    int
	pattern string
}

func scanFileForSecrets(path string, patterns []*regexp.Regexp) []secretFinding {
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

		for _, pattern := range patterns {
			if pattern.MatchString(line) {
				findings = append(findings, secretFinding{
					file:    path,
					line:    lineNum,
					pattern: pattern.String(),
				})
				break // Only report one finding per line
			}
		}
	}

	return findings
}
