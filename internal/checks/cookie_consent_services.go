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
		regexp.MustCompile(`\bcookieconsent\b`),
		regexp.MustCompile(`\bCookieConsent\b`),
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

// consentPlatformCheck is the shape the hosted consent platforms share. The
// banner is a script on the page, so the live homepage is the best evidence
// and is looked at first; an env key or code that names the platform passes
// only when no live page could be read, and warns when one was read and
// showed no banner. The live page and the code are both matched with
// comments stripped: a commented-out script tag is not a banner.
type consentPlatformCheck struct {
	id, name     string
	envPrefix    string
	livePatterns []*regexp.Regexp

	envMissingSuggestions []string
	notFoundSuggestions   []string
}

func (c consentPlatformCheck) run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.id) {
		return serviceSkipped(c.id, c.name, c.name), nil
	}

	foundOnLive, liveURL := checkLiveSiteForPatterns(ctx, c.livePatterns)
	if foundOnLive {
		return servicePassed(c.id, c.name, c.name+" script found on live site"), nil
	}

	if r, ok := serviceEnvPass(ctx, c.id, c.name, c.envPrefix); ok {
		if liveURL != "" {
			return serviceWarned(c.id, c.name, c.name+" env var found but not detected on live site", c.envMissingSuggestions...), nil
		}
		return r, nil
	}

	if ctx.serviceCodeMatch(c.id) != nil {
		if liveURL != "" {
			return serviceWarned(c.id, c.name, c.name+" code found but not detected on live site",
				"Ensure the "+c.name+" script is loading in production"), nil
		}
		return servicePassed(c.id, c.name, c.name+" script found"), nil
	}

	return serviceWarned(c.id, c.name, c.name+" is declared but script not found", c.notFoundSuggestions...), nil
}

var (
	cookiebotLivePatterns = re(
		`(?i)consent\.cookiebot\.com`,
		`(?i)Cookiebot\.consent`,
		`(?i)window\.Cookiebot`,
		`(?i)data-cbid=`,
	)
	oneTrustLivePatterns = re(
		`(?i)cdn\.cookielaw\.org`,
		`(?i)optanon-wrapper`,
		`(?i)onetrust-consent`,
		`(?i)OneTrust\.Init`,
	)
	termlyLivePatterns = re(
		`(?i)app\.termly\.io`,
		`(?i)termly\.min\.js`,
		`(?i)termly-code-snippet`,
	)
	cookieYesLivePatterns = re(
		`(?i)cdn-cookieyes\.com`,
		`(?i)cookieyes\.min\.js`,
		`(?i)cky-consent`,
	)
	iubendaLivePatterns = re(
		`(?i)cdn\.iubenda\.com`,
		`(?i)_iub\.csConfiguration`,
		`(?i)iubenda-cs-banner`,
	)
)

// CookiebotCheck verifies Cookiebot is properly set up
type CookiebotCheck struct{}

func (c CookiebotCheck) ID() string    { return "cookiebot" }
func (c CookiebotCheck) Title() string { return "Cookiebot" }

func (c CookiebotCheck) Run(ctx Context) (CheckResult, error) {
	return consentPlatformCheck{
		id: c.ID(), name: c.Title(), envPrefix: "COOKIEBOT_", livePatterns: cookiebotLivePatterns,
		envMissingSuggestions: []string{
			"Verify COOKIEBOT_CBID is correct",
			"Check that the script tag is in your page head",
		},
		notFoundSuggestions: []string{
			"Add Cookiebot script to your templates",
			"Add COOKIEBOT_CBID to environment",
		},
	}.run(ctx)
}

// OneTrustCheck verifies OneTrust is properly set up
type OneTrustCheck struct{}

func (c OneTrustCheck) ID() string    { return "onetrust" }
func (c OneTrustCheck) Title() string { return "OneTrust" }

func (c OneTrustCheck) Run(ctx Context) (CheckResult, error) {
	return consentPlatformCheck{
		id: c.ID(), name: c.Title(), envPrefix: "ONETRUST_", livePatterns: oneTrustLivePatterns,
		envMissingSuggestions: []string{"Verify OneTrust configuration is correct"},
		notFoundSuggestions:   []string{"Add OneTrust script to your templates"},
	}.run(ctx)
}

// TermlyCheck verifies Termly is properly set up
type TermlyCheck struct{}

func (c TermlyCheck) ID() string    { return "termly" }
func (c TermlyCheck) Title() string { return "Termly" }

func (c TermlyCheck) Run(ctx Context) (CheckResult, error) {
	return consentPlatformCheck{
		id: c.ID(), name: c.Title(), envPrefix: "TERMLY_", livePatterns: termlyLivePatterns,
		envMissingSuggestions: []string{"Verify Termly configuration is correct"},
		notFoundSuggestions:   []string{"Add Termly consent banner script to your templates"},
	}.run(ctx)
}

// CookieYesCheck verifies CookieYes is properly set up
type CookieYesCheck struct{}

func (c CookieYesCheck) ID() string    { return "cookieyes" }
func (c CookieYesCheck) Title() string { return "CookieYes" }

func (c CookieYesCheck) Run(ctx Context) (CheckResult, error) {
	return consentPlatformCheck{
		id: c.ID(), name: c.Title(), envPrefix: "COOKIEYES_", livePatterns: cookieYesLivePatterns,
		envMissingSuggestions: []string{"Verify CookieYes configuration is correct"},
		notFoundSuggestions:   []string{"Add CookieYes script to your templates"},
	}.run(ctx)
}

// IubendaCheck verifies Iubenda is properly set up
type IubendaCheck struct{}

func (c IubendaCheck) ID() string    { return "iubenda" }
func (c IubendaCheck) Title() string { return "Iubenda" }

func (c IubendaCheck) Run(ctx Context) (CheckResult, error) {
	return consentPlatformCheck{
		id: c.ID(), name: c.Title(), envPrefix: "IUBENDA_", livePatterns: iubendaLivePatterns,
		envMissingSuggestions: []string{"Verify Iubenda configuration is correct"},
		notFoundSuggestions:   []string{"Add Iubenda cookie banner script to your templates"},
	}.run(ctx)
}
