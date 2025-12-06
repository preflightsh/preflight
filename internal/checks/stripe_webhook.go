package checks

import (
	"fmt"
	"net/http"
)

type StripeWebhookCheck struct{}

func (c StripeWebhookCheck) ID() string {
	return "stripeWebhook"
}

func (c StripeWebhookCheck) Title() string {
	return "Stripe webhook endpoint is reachable"
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

	cfg := ctx.Config.Checks.StripeWebhook
	if cfg == nil || cfg.URL == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Stripe webhook URL not configured",
			Suggestions: []string{
				"Add stripeWebhook.url to preflight.yml",
			},
		}, nil
	}

	// Try HEAD request first, fallback to GET
	req, err := http.NewRequest(http.MethodHead, cfg.URL, nil)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  fmt.Sprintf("Invalid webhook URL: %v", err),
		}, nil
	}

	resp, err := ctx.Client.Do(req)
	if err != nil {
		// Try GET as fallback
		resp, err = ctx.Client.Get(cfg.URL)
		if err != nil {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  fmt.Sprintf("Webhook endpoint unreachable: %v", err),
				Suggestions: []string{
					"Ensure your Stripe webhook endpoint is accessible",
					"Check that the URL is correct in preflight.yml",
				},
			}, nil
		}
	}
	defer resp.Body.Close()

	// Any response means the endpoint exists (Stripe webhooks may return 400 without proper signature)
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  fmt.Sprintf("Webhook endpoint reachable at %s", cfg.URL),
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  fmt.Sprintf("Webhook endpoint returned %d", resp.StatusCode),
		Suggestions: []string{
			"Check your webhook endpoint configuration",
		},
	}, nil
}
