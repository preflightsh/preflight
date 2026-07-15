package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// runStripeCheck builds a project that has every Stripe env key present, so
// the result turns purely on whether initialization is detected in code.
func runStripeCheck(t *testing.T, srcFile, srcBody string, depFiles map[string]string) CheckResult {
	t.Helper()
	dir := t.TempDir()

	if srcFile != "" {
		if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "src", srcFile), []byte(srcBody), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range depFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	env := "STRIPE_SECRET_KEY=sk_test_x\nSTRIPE_PUBLISHABLE_KEY=pk_test_x\nSTRIPE_WEBHOOK_SECRET=whsec_x\n"
	for _, name := range []string{".env", ".env.example"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(env), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := StripeWebhookCheck{}.Run(Context{
		RootDir: dir,
		Config: &config.PreflightConfig{
			Stack:    "go",
			Services: map[string]config.ServiceConfig{"stripe": {Declared: true}},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// initPatterns are broad by design (a bare `Stripe(` counts), so matching
// raw file bytes meant a project whose only mention of Stripe was a TODO
// comment reported "Stripe keys configured".
func TestStripeInitDetection(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantInit bool
	}{
		{
			name: "comment-only mention is not an integration",
			body: "package payments\n\n" +
				"// TODO: integrate real payments. For now this is a stub.\n" +
				"// Eventually call Stripe() SDK here once we sign up.\n\n" +
				"func Charge() error { return nil }\n",
			wantInit: false,
		},
		{
			name:     "commented-out initialization does not count",
			body:     "package payments\n\n// stripe.Key = \"sk_live_xxx\"\n",
			wantInit: false,
		},
		{
			name:     "real go initialization",
			body:     "package payments\n\nimport \"github.com/stripe/stripe-go\"\n\nfunc init() { stripe.Key = \"sk_test\" }\n",
			wantInit: true,
		},
		{
			name:     "real initialization with a trailing comment",
			body:     "package payments\n\nfunc init() { stripe.Key = k } // configured at boot\n",
			wantInit: true,
		},
		{
			name:     "no mention at all",
			body:     "package payments\n\nfunc Charge() error { return nil }\n",
			wantInit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runStripeCheck(t, "payments.go", tc.body, nil)
			gotInit := !containsIssue(res.Message, "Stripe initialization not found")
			if gotInit != tc.wantInit {
				t.Errorf("init detected = %v, want %v (message=%q)", gotInit, tc.wantInit, res.Message)
			}
		})
	}
}

func TestStripeDependencyFileDetection(t *testing.T) {
	t.Run("commented-out Gemfile entry does not count", func(t *testing.T) {
		res := runStripeCheck(t, "", "", map[string]string{"Gemfile": "source 'https://rubygems.org'\n# gem 'stripe'\n"})
		if !containsIssue(res.Message, "Stripe initialization not found") {
			t.Errorf("commented Gemfile entry counted as a dependency (message=%q)", res.Message)
		}
	})

	t.Run("real Gemfile entry counts", func(t *testing.T) {
		res := runStripeCheck(t, "", "", map[string]string{"Gemfile": "source 'https://rubygems.org'\ngem 'stripe'\n"})
		if containsIssue(res.Message, "Stripe initialization not found") {
			t.Errorf("real Gemfile entry not detected (message=%q)", res.Message)
		}
	})

	t.Run("package.json dependency counts", func(t *testing.T) {
		res := runStripeCheck(t, "", "", map[string]string{"package.json": "{\n  \"dependencies\": {\n    \"stripe\": \"^14.0.0\"\n  }\n}\n"})
		if containsIssue(res.Message, "Stripe initialization not found") {
			t.Errorf("package.json dependency not detected (message=%q)", res.Message)
		}
	})
}

func containsIssue(message, want string) bool {
	return strings.Contains(message, want)
}
