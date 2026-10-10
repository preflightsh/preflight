package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func stripeCtx(root string) Context {
	return Context{RootDir: root, Config: &config.PreflightConfig{
		Services: map[string]config.ServiceConfig{"stripe": {Declared: true}},
	}}
}

// TestStripeGoProjectWithPrefixedPublishableKey: a Go app with stripe-go in
// go.mod, stripe.Key set under cmd/, and a NEXT_PUBLIC_ publishable key was
// reported as "STRIPE_PUBLISHABLE_KEY not found; Stripe initialization not
// found" because only exact names and a few directories were searched.
func TestStripeGoProjectWithPrefixedPublishableKey(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module x\n\nrequire github.com/stripe/stripe-go/v82 v82.0.0\n")
	writeFixture(t, root, "cmd/server/main.go", "package main\nfunc main(){ stripe.Key = os.Getenv(\"STRIPE_SECRET_KEY\") }\n")
	writeFixture(t, root, ".env.example", "STRIPE_SECRET_KEY=\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\n")

	res, _ := StripeWebhookCheck{}.Run(stripeCtx(root))
	if !res.Passed {
		t.Fatalf("passed=false msg=%q", res.Message)
	}
	if strings.Contains(res.Message, "publishable") {
		t.Errorf("prefixed publishable key not recognized: %q", res.Message)
	}
}

// TestStripeCheckoutOnlyNeedsNoPublishableKey: a server-side Checkout app has
// only the secret key; that is noted, not failed.
func TestStripeCheckoutOnlyNeedsNoPublishableKey(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "requirements.txt", "django>=5\nstripe==11.1.0\n")
	writeFixture(t, root, ".env.example", "STRIPE_SECRET_KEY=\n")

	res, _ := StripeWebhookCheck{}.Run(stripeCtx(root))
	if !res.Passed || !strings.Contains(res.Message, "no publishable key") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// TestStripeCommentedDependencyDoesNotCount keeps the existing guard: a
// commented-out gem line and a TODO comment are not an integration.
func TestStripeCommentedDependencyDoesNotCount(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Gemfile", "source 'https://rubygems.org'\n# gem 'stripe'\n")
	writeFixture(t, root, "app/models/user.rb", "class User\n  # TODO: call Stripe() once we sign up\nend\n")
	writeFixture(t, root, ".env.example", "STRIPE_SECRET_KEY=\n")

	res, _ := StripeWebhookCheck{}.Run(stripeCtx(root))
	if res.Passed || !strings.Contains(res.Message, "initialization not found") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}
