package checks

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PostmarkCheck verifies Postmark is properly set up
type PostmarkCheck struct{}

func (c PostmarkCheck) ID() string {
	return "postmark"
}

func (c PostmarkCheck) Title() string {
	return "Postmark"
}

func (c PostmarkCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["postmark"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Postmark not declared, skipping",
		}, nil
	}

	// Check for env var
	if hasEnvVar(ctx.RootDir, "POSTMARK_") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Postmark API key found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`postmarkapp`),
		regexp.MustCompile(`postmark-client`),
		regexp.MustCompile(`@wildbit/postmark`),
		regexp.MustCompile(`ServerClient`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Postmark SDK initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Postmark is declared but configuration not found",
		Suggestions: []string{
			"Add POSTMARK_API_TOKEN to your environment",
			"Initialize the Postmark client in your application",
		},
	}, nil
}

// SendGridCheck verifies SendGrid is properly set up
type SendGridCheck struct{}

func (c SendGridCheck) ID() string {
	return "sendgrid"
}

func (c SendGridCheck) Title() string {
	return "SendGrid"
}

func (c SendGridCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["sendgrid"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "SendGrid not declared, skipping",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "SENDGRID_") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "SendGrid API key found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`@sendgrid/mail`),
		regexp.MustCompile(`sendgrid-ruby`),
		regexp.MustCompile(`SendGrid`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "SendGrid SDK initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "SendGrid is declared but configuration not found",
		Suggestions: []string{
			"Add SENDGRID_API_KEY to your environment",
			"Initialize the SendGrid client in your application",
		},
	}, nil
}

// MailgunCheck verifies Mailgun is properly set up
type MailgunCheck struct{}

func (c MailgunCheck) ID() string {
	return "mailgun"
}

func (c MailgunCheck) Title() string {
	return "Mailgun"
}

func (c MailgunCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["mailgun"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Mailgun not declared, skipping",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "MAILGUN_") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Mailgun API key found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`mailgun-js`),
		regexp.MustCompile(`mailgun\.client`),
		regexp.MustCompile(`Mailgun`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Mailgun SDK initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Mailgun is declared but configuration not found",
		Suggestions: []string{
			"Add MAILGUN_API_KEY to your environment",
			"Initialize the Mailgun client in your application",
		},
	}, nil
}

// ResendCheck verifies Resend is properly set up
type ResendCheck struct{}

func (c ResendCheck) ID() string {
	return "resend"
}

func (c ResendCheck) Title() string {
	return "Resend"
}

func (c ResendCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["resend"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Resend not declared, skipping",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "RESEND_") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Resend API key found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`resend\.emails\.send`),
		regexp.MustCompile(`new Resend`),
		regexp.MustCompile(`Resend\(`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Resend SDK initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Resend is declared but configuration not found",
		Suggestions: []string{
			"Add RESEND_API_KEY to your environment",
			"Initialize the Resend client in your application",
		},
	}, nil
}

// AWSSESCheck verifies AWS SES is properly set up
type AWSSESCheck struct{}

func (c AWSSESCheck) ID() string {
	return "aws_ses"
}

func (c AWSSESCheck) Title() string {
	return "AWS SES"
}

func (c AWSSESCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["aws_ses"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "AWS SES not declared, skipping",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "AWS_SES_") || hasEnvVar(ctx.RootDir, "SES_REGION") {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "AWS SES configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`@aws-sdk/client-ses`),
		regexp.MustCompile(`aws-sdk-ses`),
		regexp.MustCompile(`SESClient`),
		regexp.MustCompile(`ses\.sendEmail`),
		regexp.MustCompile(`craft-amazon-ses`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "AWS SES SDK initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "AWS SES is declared but configuration not found",
		Suggestions: []string{
			"Configure AWS credentials for SES",
			"Initialize the SES client in your application",
		},
	}, nil
}

// hasEnvVar checks if an environment variable with the given prefix exists
func hasEnvVar(rootDir, prefix string) bool {
	envFiles := []string{".env", ".env.example", ".env.local", ".env.development"}

	for _, envFile := range envFiles {
		path := filepath.Join(rootDir, envFile)
		file, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		found := false
		for scanner.Scan() {
			line := strings.ToUpper(scanner.Text())
			if strings.HasPrefix(line, prefix) {
				found = true
				break
			}
		}
		file.Close()
		if found {
			return true
		}
	}

	return false
}
