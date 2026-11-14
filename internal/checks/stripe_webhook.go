package checks

import (
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type StripeWebhookCheck struct{}

func (c StripeWebhookCheck) ID() string {
	return "stripe"
}

func (c StripeWebhookCheck) Title() string {
	return "Stripe"
}

func (c StripeWebhookCheck) Run(ctx Context) (CheckResult, error) {
	// Check if Stripe is declared
	stripeService, declared := ctx.Config.Services["stripe"]
	if !declared || !stripeService.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Stripe not declared, skipping",
		}, nil
	}

	var issues []string
	var suggestions []string

	// A value in a real env file (.env, .env.local, .env.development.local)
	// sets a key; a name in .env.example only documents it. Documented is
	// enough to pass (CI has no real .env), and the message says which.
	//
	// Laravel Cashier names the pair STRIPE_KEY and STRIPE_SECRET; those and
	// the other common spellings count as the same keys.
	keyStatus := func(keys ...string) (envKeyStatus, string) {
		return envKeyLookup(ctx.RootDir, func(name string) bool { return slices.Contains(keys, name) })
	}
	secretStatus, secretWhere := keyStatus("STRIPE_SECRET_KEY", "STRIPE_SECRET", "STRIPE_API_KEY")
	publishableStatus, _ := keyStatus("STRIPE_PUBLISHABLE_KEY", "STRIPE_KEY", "STRIPE_PUBLIC_KEY")
	webhookStatus, _ := keyStatus("STRIPE_WEBHOOK_SECRET")

	// The secret key is required. The publishable key only matters for
	// Stripe.js in the browser (a Checkout-only server app never needs it),
	// so its absence is noted rather than failed.
	if secretStatus == envKeyMissing {
		issues = append(issues, "STRIPE_SECRET_KEY not found in env files")
		suggestions = append(suggestions, "Set STRIPE_SECRET_KEY in your application environment, or document it in .env.example")
	}
	publishableNote := ""
	if publishableStatus == envKeyMissing {
		publishableNote = ", no publishable key (only needed for Stripe.js)"
	}

	// Check webhook secret (warn but don't fail)
	hasWebhookSecret := webhookStatus != envKeyMissing

	initFound := stripeInitFound(ctx)

	if !initFound {
		issues = append(issues, "Stripe initialization not found")
		suggestions = append(suggestions, "Ensure Stripe is initialized in your application")
	}

	// Webhook endpoint reachability. README documents stripeWebhook.url
	// and publish redacts it, but until now nothing read it.
	webhookNote := ""
	if cfg := ctx.Config.Checks.StripeWebhook; cfg != nil && cfg.URL != "" {
		switch probeWebhookEndpoint(ctx, cfg.URL) {
		case webhookReachable:
			webhookNote = ", webhook endpoint reachable"
		case webhookMissing:
			issues = append(issues, "webhook URL returns 404")
			suggestions = append(suggestions, "Check the route for "+cfg.URL+" is deployed")
		case webhookUnreachable:
			issues = append(issues, "webhook URL unreachable")
			suggestions = append(suggestions, "Check that "+cfg.URL+" resolves and accepts connections")
		}
	}

	// Build result
	if len(issues) == 0 {
		message := "Stripe integration found with nonempty local key values (authentication not verified)"
		if secretStatus == envKeyDocumented {
			message = "Stripe integration found, STRIPE_SECRET_KEY documented in " + secretWhere + " (no value set locally, so it is not verified)"
		}
		if hasWebhookSecret {
			message += ", webhook secret present"
		} else {
			message += " (webhook secret not found, needed for webhooks)"
		}
		message += publishableNote + webhookNote
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  message,
		}, nil
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     strings.Join(issues, "; "),
		Suggestions: suggestions,
	}, nil
}

// stripeCodePatterns match Stripe being set up in code, across the
// languages with an official Stripe SDK.
var stripeCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bStripe\.api_key\b`),                                   // Ruby
	regexp.MustCompile(`\bstripe\.(?:Key|api_key)\b`),                           // Go, Python
	regexp.MustCompile(`\bnew Stripe\(`),                                        // Node
	regexp.MustCompile(`\bStripe\(`),                                            // Node alt
	regexp.MustCompile(`\bstripe\.setApiKey\b`),                                 // Node alt
	regexp.MustCompile(`\\Stripe\\StripeClient|\bStripe::`),                     // PHP, Ruby
	regexp.MustCompile(`\bLaravel\\Cashier\b|\bCashier::`),                      // Laravel Cashier
	regexp.MustCompile(`\bSTRIPE_(?:SECRET_KEY|SECRET|API_KEY)\b`),              // Generic env usage
	regexp.MustCompile(`from\s+["']stripe["']|require\s*\(\s*["']stripe["']\)`), // Node import
}

// stripeDependencyPatterns match Stripe declared in a package manifest, by
// manifest. One list for every manifest let the Python form, a bare
// "stripe" word, match the prose in a package.json description.
var stripeDependencyPatterns = map[string][]*regexp.Regexp{
	"composer.json":    re(`"stripe/stripe-php"`, `"laravel/cashier"`),
	"Gemfile":          re(`gem ['"](?:stripe|pay|stripe-rails)['"]`),
	"Gemfile.lock":     re(`(?m)^\s+stripe \(`),
	"package.json":     re(`"(?:stripe|@stripe/[\w-]+)"\s*:`),
	"go.mod":           re(`github\.com/stripe/stripe-go`),
	"requirements.txt": re(`(?im)^\s*(?:stripe|dj-stripe)\s*(?:[=<>~!\[;]|$)`),
	"pyproject.toml":   re(`(?im)["']stripe\s*(?:[=<>~!\[]|["'])`, `(?im)^\s*stripe\s*=`),
	"Pipfile":          re(`(?im)^\s*stripe\s*=`),
}

// stripeInitFound reports whether Stripe is initialized anywhere in the
// project's source or declared as a dependency. Manifests are reduced to
// their dependencies (manifestDependencies), so neither `# gem "stripe"` nor
// a description that mentions Stripe counts. Source has comments stripped:
// the patterns are broad on purpose (`Stripe(` alone counts), so
// "// TODO: call Stripe() here" must not.
func stripeInitFound(ctx Context) bool {
	for _, name := range append([]string{"Gemfile.lock"}, dependencyManifests...) {
		content, err := readSourceFile(filepath.Join(ctx.RootDir, name))
		if err != nil {
			continue
		}
		if _, ok := firstMatch(stripeDependencyPatterns[name], manifestDependencies(name, content)); ok {
			return true
		}
	}
	return ctx.serviceCodeMatch("stripe") != nil
}

type webhookProbe int

const (
	webhookSkipped webhookProbe = iota
	webhookReachable
	webhookMissing
	webhookUnreachable
)

// probeWebhookEndpoint asks whether a route exists at the configured Stripe
// webhook URL. Nothing is posted: Stripe endpoints only accept signed POST
// bodies, so a GET answering 405, 400, 401 or 403 is the route saying "I am
// here, that is not a webhook", which is the answer wanted. Only a 404 (no
// route) or no response at all (host down, DNS, SSRF refusal) count against
// the check; a 5xx is reported as reachable since the route clearly ran.
func probeWebhookEndpoint(ctx Context, rawURL string) webhookProbe {
	if ctx.Client == nil {
		return webhookSkipped
	}
	resp, err := doGet(ctx.reqContext(), ctx.Client, rawURL)
	if err != nil {
		return webhookUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return webhookMissing
	}
	return webhookReachable
}
