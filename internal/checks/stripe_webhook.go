package checks

import (
	"bufio"
	"net/http"
	"path/filepath"
	"regexp"
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
			Passed:   true,
			Message:  "Stripe not declared, skipping",
		}, nil
	}

	var issues []string
	var suggestions []string

	// Check for required env vars in .env.example or .env
	envFiles := []string{".env.example", ".env", ".env.local"}
	requiredKeys := []string{"STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY"}
	webhookKey := "STRIPE_WEBHOOK_SECRET"

	keysToScan := append(append([]string{}, requiredKeys...), webhookKey)

	foundKeys := make(map[string]bool)
	for _, envFile := range envFiles {
		path := filepath.Join(ctx.RootDir, envFile)
		scanEnvFile(path, keysToScan, foundKeys)
	}

	// The secret key is required. The publishable key only matters for
	// Stripe.js in the browser (a Checkout-only server app never needs it),
	// so its absence is noted rather than failed.
	if !foundKeys["STRIPE_SECRET_KEY"] {
		issues = append(issues, "STRIPE_SECRET_KEY not found in env files")
		suggestions = append(suggestions, "Add STRIPE_SECRET_KEY to .env.example")
	}
	publishableNote := ""
	if !foundKeys["STRIPE_PUBLISHABLE_KEY"] {
		publishableNote = ", no publishable key (only needed for Stripe.js)"
	}

	// Check webhook secret (warn but don't fail)
	hasWebhookSecret := foundKeys[webhookKey]

	initFound := stripeInitFound(ctx.RootDir)

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
		message := "Stripe keys configured"
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

func scanEnvFile(path string, keys []string, foundKeys map[string]bool) {
	file, err := openRegular(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Default Scanner cap is 64KB per line; an .env file with a longer
	// inline value would silently abort the scan and report later keys
	// as missing. Read errors are treated like an unreadable file
	// (best-effort skip, same as the os.Open path above).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		name := envVarName(scanner.Text())
		for _, key := range keys {
			// NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY, VITE_STRIPE_..., and so
			// on: frameworks expose browser vars under a prefix.
			if name == key || strings.HasSuffix(name, "_"+key) {
				foundKeys[key] = true
			}
		}
	}
	_ = scanner.Err()
}

// stripeCodePatterns match Stripe being set up in code, across the
// languages with an official Stripe SDK.
var stripeCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`Stripe\.api_key`),                 // Ruby
	regexp.MustCompile(`stripe\.(?:Key|api_key)\b`),       // Go, Python
	regexp.MustCompile(`new Stripe\(`),                    // Node
	regexp.MustCompile(`Stripe\(`),                        // Node alt
	regexp.MustCompile(`stripe\.setApiKey`),               // Node alt
	regexp.MustCompile(`\\Stripe\\StripeClient|Stripe::`), // PHP, Ruby
	regexp.MustCompile(`STRIPE_SECRET_KEY`),               // Generic env usage
}

// stripeDependencyPatterns match Stripe declared in a package manifest.
var stripeDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`stripe/stripe-php`),                                 // composer.json
	regexp.MustCompile(`gem ['"]stripe['"]`),                                // Gemfile
	regexp.MustCompile(`(?m)^\s+stripe \(`),                                 // Gemfile.lock
	regexp.MustCompile(`"(?:stripe|@stripe/[\w-]+)"\s*:`),                   // package.json
	regexp.MustCompile(`github\.com/stripe/stripe-go`),                      // go.mod
	regexp.MustCompile(`(?im)(?:^|["'\s,\[])stripe\s*(?:[=<>~!\[]|["']|$)`), // requirements.txt, pyproject, Pipfile
}

// stripeInitFound reports whether Stripe is initialized anywhere in the
// project's source or declared as a dependency. Manifests are compared with
// comments stripped (a Gemfile comments with "#", so `# gem "stripe"` must not
// count), and source with code comments stripped: the patterns are broad on
// purpose (`Stripe\(` alone counts), so "// TODO: call Stripe() here" must not.
func stripeInitFound(rootDir string) bool {
	for _, name := range append([]string{"Gemfile.lock"}, dependencyManifests...) {
		content, err := readSourceFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}
		deps := stripComments(string(content))
		for _, p := range stripeDependencyPatterns {
			if p.MatchString(deps) {
				return true
			}
		}
	}
	return walkSourceFiles(rootDir, func(path string, content []byte) bool {
		code := stripCodeComments(string(content))
		if ext := filepath.Ext(path); ext == ".rb" || ext == ".py" {
			code = stripComments(code) // "#" comments too
		}
		for _, p := range stripeCodePatterns {
			if p.MatchString(code) {
				return true
			}
		}
		return false
	})
}

// envVarName returns the upper-cased variable name assigned on a .env line,
// or "" for comments and lines without an assignment. The whole name is
// compared so STRIPE_SECRET_KEY_OLD does not satisfy STRIPE_SECRET_KEY, and
// a leading `export` is allowed.
func envVarName(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "export ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	}
	name, _, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(name))
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
