package checks

import (
	"os"
	"path/filepath"
	"strings"
)

// transactionalEmailCheck is the shape the transactional email checks share:
// a key in an env file, the SDK in the code or a manifest, or the key
// referenced from a config or deploy file.
type transactionalEmailCheck struct {
	id, name    string
	envPrefixes []string
	suggestions []string
}

func (c transactionalEmailCheck) run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.id) {
		return serviceSkipped(c.id, c.name, c.name), nil
	}
	if r, ok := serviceEnvPass(ctx, c.id, c.name, c.envPrefixes...); ok {
		return r, nil
	}
	if ctx.serviceCodeMatch(c.id) != nil {
		return servicePassed(c.id, c.name, c.name+" SDK initialization found"), nil
	}
	if where, ok := hasEnvVarReference(ctx.RootDir, c.envPrefixes...); ok {
		return servicePassed(c.id, c.name, c.name+" configured via env reference in "+where+" (secret resolved from the deploy environment)"), nil
	}
	return serviceWarned(c.id, c.name, c.name+" is declared but configuration not found", c.suggestions...), nil
}

// PostmarkCheck verifies Postmark is properly set up
type PostmarkCheck struct{}

func (c PostmarkCheck) ID() string    { return "postmark" }
func (c PostmarkCheck) Title() string { return "Postmark" }

func (c PostmarkCheck) Run(ctx Context) (CheckResult, error) {
	return transactionalEmailCheck{
		id: c.ID(), name: c.Title(), envPrefixes: []string{"POSTMARK_"},
		suggestions: []string{
			"Add POSTMARK_API_TOKEN to your environment",
			"Initialize the Postmark client in your application",
		},
	}.run(ctx)
}

// SendGridCheck verifies SendGrid is properly set up
type SendGridCheck struct{}

func (c SendGridCheck) ID() string    { return "sendgrid" }
func (c SendGridCheck) Title() string { return "SendGrid" }

func (c SendGridCheck) Run(ctx Context) (CheckResult, error) {
	return transactionalEmailCheck{
		id: c.ID(), name: c.Title(), envPrefixes: []string{"SENDGRID_"},
		suggestions: []string{
			"Add SENDGRID_API_KEY to your environment",
			"Initialize the SendGrid client in your application",
		},
	}.run(ctx)
}

// MailgunCheck verifies Mailgun is properly set up
type MailgunCheck struct{}

func (c MailgunCheck) ID() string    { return "mailgun" }
func (c MailgunCheck) Title() string { return "Mailgun" }

func (c MailgunCheck) Run(ctx Context) (CheckResult, error) {
	return transactionalEmailCheck{
		id: c.ID(), name: c.Title(), envPrefixes: []string{"MAILGUN_"},
		suggestions: []string{
			"Add MAILGUN_API_KEY to your environment",
			"Initialize the Mailgun client in your application",
		},
	}.run(ctx)
}

// ResendCheck verifies Resend is properly set up
type ResendCheck struct{}

func (c ResendCheck) ID() string    { return "resend" }
func (c ResendCheck) Title() string { return "Resend" }

func (c ResendCheck) Run(ctx Context) (CheckResult, error) {
	return transactionalEmailCheck{
		id: c.ID(), name: c.Title(), envPrefixes: []string{"RESEND_"},
		suggestions: []string{
			"Add RESEND_API_KEY to your environment",
			"Initialize the Resend client in your application",
		},
	}.run(ctx)
}

// AWSSESCheck verifies AWS SES is properly set up
type AWSSESCheck struct{}

func (c AWSSESCheck) ID() string    { return "aws_ses" }
func (c AWSSESCheck) Title() string { return "AWS SES" }

func (c AWSSESCheck) Run(ctx Context) (CheckResult, error) {
	return transactionalEmailCheck{
		id: c.ID(), name: c.Title(), envPrefixes: []string{"AWS_SES_", "SES_REGION"},
		suggestions: []string{
			"Configure AWS credentials for SES",
			"Initialize the SES client in your application",
		},
	}.run(ctx)
}

// hasEnvVar reports whether a root env file sets or documents a name the
// prefix covers (envKeyLookup).
func hasEnvVar(rootDir, prefix string) bool {
	status, _ := envKeyLookup(rootDir, envNameMatcher(prefix))
	return status != envKeyMissing
}

// envKeyPass is the passing result for a service whose key a root env file
// sets or documents; ok is false when none does. A documented key passes as
// configured but unverified: in CI, .env.example is all there is.
func envKeyPass(id, title, rootDir string, prefixes ...string) (CheckResult, bool) {
	best, where := envKeyMissing, ""
	for _, prefix := range prefixes {
		if status, file := envKeyLookup(rootDir, envNameMatcher(prefix)); status > best {
			best, where = status, file
		}
	}
	msg := title + " key found in " + where
	switch best {
	case envKeyMissing:
		return CheckResult{}, false
	case envKeyDocumented:
		msg = title + " key documented in " + where + " (no value set locally, so it is not verified)"
	}
	return CheckResult{ID: id, Title: title, Severity: SeverityInfo, Passed: true, Message: msg}, true
}

// envRefConfigFiles are non-.env config and deploy manifests that commonly
// reference a secret by env-var name (e.g. `apiKey: $AWS_SES_API_KEY`,
// `env('MAILGUN_SECRET')`) rather than holding the value. Spans CMSs and hosts
// so detection isn't tied to one stack.
var envRefConfigFiles = []string{
	"config/project/project.yaml",                         // Craft CMS (committed project config)
	"wp-config.php",                                       // WordPress
	"config/services.yaml", "config/packages/mailer.yaml", // Symfony
	"render.yaml", "fly.toml", "vercel.json", "netlify.toml", "app.yaml",
	"app.json", "Procfile", "docker-compose.yml", "docker-compose.yaml",
}

// maxEnvRefScanBytes caps the size of any single config file read while looking
// for an env-var reference, so a walk never slurps a large committed artifact.
const maxEnvRefScanBytes = 512 * 1024

// hasEnvVarReference reports whether any of the given env-var prefixes is
// *referenced* (not necessarily valued) in a non-.env config or deploy file:
// e.g. Craft's project.yaml using `apiKey: $AWS_SES_API_KEY`, a Laravel config
// calling `env('MAILGUN_SECRET')`, or a fly.toml/render.yaml declaring the var.
// A service wired this way is correctly configured: the secret lives in the
// deploy environment, not committed to the repo, so its absence from the local
// .env is expected rather than a misconfiguration. Returns the relative path it
// was found in and true. The prefixes are matched case-insensitively as
// substrings; env-var names (AWS_SES_, MAILGUN_, …) are distinctive enough that
// this won't collide with unrelated config text.
func hasEnvVarReference(rootDir string, prefixes ...string) (string, bool) {
	upper := make([]string, len(prefixes))
	for i, p := range prefixes {
		upper[i] = strings.ToUpper(p)
	}

	scan := func(path string) bool {
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() || fi.Size() > maxEnvRefScanBytes {
			return false
		}
		content, err := readSourceFile(path)
		if err != nil {
			return false
		}
		up := strings.ToUpper(string(content))
		for _, p := range upper {
			if strings.Contains(up, p) {
				return true
			}
		}
		return false
	}

	// Curated config/deploy manifests first.
	for _, rel := range envRefConfigFiles {
		full := filepath.Join(rootDir, rel)
		if scan(full) {
			return rel, true
		}
	}

	// Then a bounded walk of config/ (Laravel, Rails, Craft, Symfony) for the
	// usual config file types.
	found := ""
	configDir := filepath.Join(rootDir, "config")
	_ = filepath.Walk(configDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if fi.IsDir() {
			if fi.Name() == "vendor" || fi.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(fi.Name())) {
		case ".php", ".yaml", ".yml", ".rb", ".env", ".toml", ".json":
			if scan(path) {
				found = relPath(rootDir, path)
			}
		}
		return nil
	})
	if found != "" {
		return found, true
	}
	return "", false
}
