package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestEnvExampleDocumentsDeclaredServices: in CI there is no real .env, and
// a key documented in .env.example is the normal state. v0.23 passed; the
// service must not warn, and where the check words its own message, it says
// the key is documented rather than set.
func TestEnvExampleDocumentsDeclaredServices(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env.example", "OPENAI_API_KEY=\nSTRIPE_SECRET_KEY=\nSTRIPE_PUBLISHABLE_KEY=\nSTRIPE_WEBHOOK_SECRET=\nRESEND_API_KEY=\n")
	writeFixture(t, root, "src/payments.go", "package payments\nfunc charge(){ stripe.Key = k }\n")
	ctx := regressionContext(root)
	for _, s := range []string{"openai", "stripe", "resend"} {
		ctx.Config.Services[s] = config.ServiceConfig{Declared: true}
	}
	for _, c := range []Check{OpenAICheck, ResendCheck{}, StripeWebhookCheck{}} {
		r, _ := c.Run(ctx)
		if !r.Passed || r.Severity != SeverityInfo {
			t.Errorf("%s: %+v", c.ID(), r)
		}
		if c.ID() != "openai" && !strings.Contains(r.Message, "documented in .env.example") {
			t.Errorf("%s message %q does not say the key is documented", c.ID(), r.Message)
		}
	}
}

// TestEnvVariantFilesAreRead: framework env variants hold real keys
// (autochangelog keeps its keys in .env.development.local).
func TestEnvVariantFilesAreRead(t *testing.T) {
	for _, name := range []string{".env.development.local", ".env.production.local", ".env.local", ".env.test", ".env.staging"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, name, "RESEND_API_KEY=re_live_fixture\nSTRIPE_SECRET_KEY=sk_test_fixture\n")
			writeFixture(t, root, "src/payments.go", "package payments\nfunc charge(){ stripe.Key = k }\n")
			ctx := regressionContext(root)
			ctx.Config.Services["resend"] = config.ServiceConfig{Declared: true}
			ctx.Config.Services["stripe"] = config.ServiceConfig{Declared: true}
			if r, _ := (ResendCheck{}).Run(ctx); !r.Passed || !strings.Contains(r.Message, "found in "+name) {
				t.Errorf("resend: %+v", r)
			}
			if r, _ := (StripeWebhookCheck{}).Run(ctx); !r.Passed || strings.Contains(r.Message, "documented") {
				t.Errorf("stripe: %+v", r)
			}
		})
	}
}

// TestEnvPrefixFallback: the per-service name list is a preference, not the
// whole contract. Names outside it still count by prefix, as in v0.23.
func TestEnvPrefixFallback(t *testing.T) {
	for _, tc := range []struct{ prefix, line string }{
		{"DISCORD_", "DISCORD_BOT_TOKEN=abc"},
		{"SUPABASE_", "SUPABASE_KEY=abc"},
		{"SLACK_", "SLACK_SIGNING_SECRET=abc"},
		{"MAILGUN_", "MAILGUN_DOMAIN=mg.example.com"},
	} {
		root := t.TempDir()
		writeFixture(t, root, ".env", tc.line+"\n")
		if !hasEnvVar(root, tc.prefix) {
			t.Errorf("%s not found by prefix %s", tc.line, tc.prefix)
		}
	}
	root := t.TempDir()
	writeFixture(t, root, ".env", "NOT_DISCORD_TOKEN=abc\n# DISCORD_TOKEN=abc\n")
	if hasEnvVar(root, "DISCORD_") {
		t.Error("unrelated or commented name matched")
	}
}
