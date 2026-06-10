package checks

import (
	"regexp"
)

// CookieConsentJSCheck verifies CookieConsent JS library is properly set up
var CookieConsentJSCheck = ServiceCheck{
	CheckID:    "cookieconsent",
	CheckTitle: "CookieConsent",
	LivePatterns: []*regexp.Regexp{
		regexp.MustCompile(`(?i)cookieconsent\.min\.js`),
		regexp.MustCompile(`(?i)cdn\.jsdelivr\.net.*cookieconsent`),
		regexp.MustCompile(`(?i)osano.*cookieconsent`),
		regexp.MustCompile(`(?i)CookieConsent\.run\(`),
		regexp.MustCompile(`(?i)cc\.initialise\(`),
	},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`cookieconsent`),
		regexp.MustCompile(`CookieConsent`),
		regexp.MustCompile(`cdn\.jsdelivr\.net.*cookieconsent`),
	},
	LiveFoundMsg:   "Cookie Consent script found on live site",
	CodeFoundMsg:   "Cookie Consent script found in codebase",
	LiveMissingMsg: "Cookie Consent code found but not detected on live site",
	NotFoundMsg:    "Cookie Consent is declared but script not found",
	LiveMissingSuggestions: []string{
		"Ensure the consent banner script is loading in production",
		"Check browser console for script errors",
	},
	NotFoundSuggestions: []string{
		"Add Cookie Consent script to your templates",
	},
}

// CookiebotCheck verifies Cookiebot is properly set up
type CookiebotCheck struct{}

func (c CookiebotCheck) ID() string {
	return "cookiebot"
}

func (c CookiebotCheck) Title() string {
	return "Cookiebot"
}

func (c CookiebotCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["cookiebot"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Cookiebot not declared, skipping",
		}, nil
	}

	// Check live site for Cookiebot script
	livePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)consent\.cookiebot\.com`),
		regexp.MustCompile(`(?i)Cookiebot\.consent`),
		regexp.MustCompile(`(?i)window\.Cookiebot`),
		regexp.MustCompile(`(?i)data-cbid=`),
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, livePatterns)

	if foundOnLive {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Cookiebot script found on live site",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "COOKIEBOT_") {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Cookiebot env var found but not detected on live site",
				Suggestions: []string{
					"Verify COOKIEBOT_CBID is correct",
					"Check that the script tag is in your page head",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Cookiebot configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`consent\.cookiebot\.com`),
		regexp.MustCompile(`Cookiebot`),
		regexp.MustCompile(`cookiebot`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Cookiebot code found but not detected on live site",
				Suggestions: []string{
					"Ensure the Cookiebot script is loading in production",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Cookiebot script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Cookiebot is declared but script not found",
		Suggestions: []string{
			"Add Cookiebot script to your templates",
			"Add COOKIEBOT_CBID to environment",
		},
	}, nil
}

// OneTrustCheck verifies OneTrust is properly set up
type OneTrustCheck struct{}

func (c OneTrustCheck) ID() string {
	return "onetrust"
}

func (c OneTrustCheck) Title() string {
	return "OneTrust"
}

func (c OneTrustCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["onetrust"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "OneTrust not declared, skipping",
		}, nil
	}

	// Check live site for OneTrust script
	livePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)cdn\.cookielaw\.org`),
		regexp.MustCompile(`(?i)optanon-wrapper`),
		regexp.MustCompile(`(?i)onetrust-consent`),
		regexp.MustCompile(`(?i)OneTrust\.Init`),
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, livePatterns)

	if foundOnLive {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "OneTrust script found on live site",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "ONETRUST_") {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "OneTrust env var found but not detected on live site",
				Suggestions: []string{
					"Verify OneTrust configuration is correct",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "OneTrust configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`cdn\.cookielaw\.org`),
		regexp.MustCompile(`onetrust`),
		regexp.MustCompile(`OneTrust`),
		regexp.MustCompile(`optanon`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "OneTrust code found but not detected on live site",
				Suggestions: []string{
					"Ensure the OneTrust script is loading in production",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "OneTrust script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "OneTrust is declared but script not found",
		Suggestions: []string{
			"Add OneTrust script to your templates",
		},
	}, nil
}

// TermlyCheck verifies Termly is properly set up
type TermlyCheck struct{}

func (c TermlyCheck) ID() string {
	return "termly"
}

func (c TermlyCheck) Title() string {
	return "Termly"
}

func (c TermlyCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["termly"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Termly not declared, skipping",
		}, nil
	}

	// Check live site for Termly script
	livePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)app\.termly\.io`),
		regexp.MustCompile(`(?i)termly\.min\.js`),
		regexp.MustCompile(`(?i)termly-code-snippet`),
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, livePatterns)

	if foundOnLive {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Termly script found on live site",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "TERMLY_") {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Termly env var found but not detected on live site",
				Suggestions: []string{
					"Verify Termly configuration is correct",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Termly configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`app\.termly\.io`),
		regexp.MustCompile(`termly`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Termly code found but not detected on live site",
				Suggestions: []string{
					"Ensure the Termly script is loading in production",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Termly script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Termly is declared but script not found",
		Suggestions: []string{
			"Add Termly consent banner script to your templates",
		},
	}, nil
}

// CookieYesCheck verifies CookieYes is properly set up
type CookieYesCheck struct{}

func (c CookieYesCheck) ID() string {
	return "cookieyes"
}

func (c CookieYesCheck) Title() string {
	return "CookieYes"
}

func (c CookieYesCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["cookieyes"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "CookieYes not declared, skipping",
		}, nil
	}

	// Check live site for CookieYes script
	livePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)cdn-cookieyes\.com`),
		regexp.MustCompile(`(?i)cookieyes\.min\.js`),
		regexp.MustCompile(`(?i)cky-consent`),
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, livePatterns)

	if foundOnLive {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "CookieYes script found on live site",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "COOKIEYES_") {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "CookieYes env var found but not detected on live site",
				Suggestions: []string{
					"Verify CookieYes configuration is correct",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "CookieYes configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`cdn-cookieyes\.com`),
		regexp.MustCompile(`cookieyes`),
		regexp.MustCompile(`CookieYes`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "CookieYes code found but not detected on live site",
				Suggestions: []string{
					"Ensure the CookieYes script is loading in production",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "CookieYes script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "CookieYes is declared but script not found",
		Suggestions: []string{
			"Add CookieYes script to your templates",
		},
	}, nil
}

// IubendaCheck verifies Iubenda is properly set up
type IubendaCheck struct{}

func (c IubendaCheck) ID() string {
	return "iubenda"
}

func (c IubendaCheck) Title() string {
	return "Iubenda"
}

func (c IubendaCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["iubenda"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Iubenda not declared, skipping",
		}, nil
	}

	// Check live site for Iubenda script
	livePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)cdn\.iubenda\.com`),
		regexp.MustCompile(`(?i)_iub\.csConfiguration`),
		regexp.MustCompile(`(?i)iubenda-cs-banner`),
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, livePatterns)

	if foundOnLive {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Iubenda script found on live site",
		}, nil
	}

	if hasEnvVar(ctx.RootDir, "IUBENDA_") {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Iubenda env var found but not detected on live site",
				Suggestions: []string{
					"Verify Iubenda configuration is correct",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Iubenda configuration found in environment",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`cdn\.iubenda\.com`),
		regexp.MustCompile(`iubenda`),
		regexp.MustCompile(`_iub`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		if liveURL != "" {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  "Iubenda code found but not detected on live site",
				Suggestions: []string{
					"Ensure the Iubenda script is loading in production",
				},
			}, nil
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Iubenda script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Iubenda is declared but script not found",
		Suggestions: []string{
			"Add Iubenda cookie banner script to your templates",
		},
	}, nil
}
