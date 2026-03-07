package checks

import (
	"regexp"
)

// UmamiCheck verifies Umami Analytics is properly set up
type UmamiCheck struct{}

func (c UmamiCheck) ID() string {
	return "umami"
}

func (c UmamiCheck) Title() string {
	return "Umami Analytics"
}

func (c UmamiCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["umami"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Umami not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`data-website-id=`),            // Umami-specific script attribute
		regexp.MustCompile(`(?i)cloud\.umami\.is`),        // Umami Cloud
		regexp.MustCompile(`(?i)analytics\.umami\.is`),    // Umami Cloud (legacy)
		regexp.MustCompile(`(?i)umami\.track\(`),          // umami.track() API
		regexp.MustCompile(`(?i)umami\.identify\(`),       // umami.identify() API
		regexp.MustCompile(`from\s+["']@umami/`),         // npm package import
		regexp.MustCompile(`require\s*\(\s*["']@umami/`), // npm package require
		regexp.MustCompile(`UMAMI_WEBSITE_ID`),            // env var pattern
		regexp.MustCompile(`NEXT_PUBLIC_UMAMI`),           // Next.js env var
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Umami Analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Umami is declared but script not found in templates",
		Suggestions: []string{
			"Add the Umami script tag to your main layout",
			"Example: <script defer src=\"https://your-umami-host/script.js\" data-website-id=\"YOUR-ID\"></script>",
			"For self-hosted Umami, ensure data-website-id attribute is present on the script tag",
		},
	}, nil
}

// FullresCheck verifies Fullres Analytics is properly set up
type FullresCheck struct{}

func (c FullresCheck) ID() string {
	return "fullres"
}

func (c FullresCheck) Title() string {
	return "Fullres Analytics"
}

func (c FullresCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["fullres"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fullres not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`window\.fullres`),
		regexp.MustCompile(`var fullres`),
		regexp.MustCompile(`fullres\.events`),
		regexp.MustCompile(`fullres\.co`),
		regexp.MustCompile(`fullres\.io`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Fullres Analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Fullres is declared but script not found in templates",
		Suggestions: []string{
			"Add the Fullres script tag to your main layout",
			"Check your Fullres dashboard for the correct embed code",
		},
	}, nil
}

// DatafastCheck verifies Datafa.st Analytics is properly set up
type DatafastCheck struct{}

func (c DatafastCheck) ID() string {
	return "datafast"
}

func (c DatafastCheck) Title() string {
	return "Datafa.st Analytics"
}

func (c DatafastCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["datafast"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Datafa.st not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`datafa\.st`),
		regexp.MustCompile(`datafast\.io`),
		regexp.MustCompile(`cdn\.datafast`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Datafa.st Analytics script found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Datafa.st is declared but script not found in templates",
		Suggestions: []string{
			"Add the Datafa.st script tag to your main layout",
		},
	}, nil
}

// PostHogCheck verifies PostHog is properly set up
type PostHogCheck struct{}

func (c PostHogCheck) ID() string {
	return "posthog"
}

func (c PostHogCheck) Title() string {
	return "PostHog"
}

func (c PostHogCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["posthog"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "PostHog not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)posthog\.init`),           // posthog.init() or PostHog.init()
		regexp.MustCompile(`(?i)posthog\.capture`),        // posthog.capture() or PostHog.capture()
		regexp.MustCompile(`PostHogProvider`),             // React provider pattern
		regexp.MustCompile(`from\s+["']posthog-js["']`),   // import from 'posthog-js'
		regexp.MustCompile(`require\s*\(\s*["']posthog-js["']\)`), // require('posthog-js')
		regexp.MustCompile(`i\.posthog\.com`),             // PostHog cloud endpoint
		regexp.MustCompile(`us\.posthog\.com`),            // US cloud endpoint
		regexp.MustCompile(`eu\.posthog\.com`),            // EU cloud endpoint
		regexp.MustCompile(`POSTHOG_KEY`),                 // env var pattern
		regexp.MustCompile(`NEXT_PUBLIC_POSTHOG`),         // Next.js env var
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "PostHog initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "PostHog is declared but initialization not found",
		Suggestions: []string{
			"Add posthog.init() to your application",
			"Check PostHog docs for your framework",
		},
	}, nil
}

// MixpanelCheck verifies Mixpanel is properly set up
type MixpanelCheck struct{}

func (c MixpanelCheck) ID() string {
	return "mixpanel"
}

func (c MixpanelCheck) Title() string {
	return "Mixpanel"
}

func (c MixpanelCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["mixpanel"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Mixpanel not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`mixpanel\.init`),
		regexp.MustCompile(`mixpanel\.track`),
		regexp.MustCompile(`cdn\.mxpnl\.com`),
		regexp.MustCompile(`mixpanel-browser`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Mixpanel initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Mixpanel is declared but initialization not found",
		Suggestions: []string{
			"Add mixpanel.init() with your project token",
			"Check Mixpanel docs for your framework",
		},
	}, nil
}

// HotjarCheck verifies Hotjar is properly set up
type HotjarCheck struct{}

func (c HotjarCheck) ID() string {
	return "hotjar"
}

func (c HotjarCheck) Title() string {
	return "Hotjar"
}

func (c HotjarCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["hotjar"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Hotjar not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`hotjar\.com`),
		regexp.MustCompile(`static\.hotjar\.com`),
		regexp.MustCompile(`hj\s*\(`),
		regexp.MustCompile(`_hjSettings`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Hotjar tracking code found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Hotjar is declared but tracking code not found",
		Suggestions: []string{
			"Add the Hotjar tracking code to your main layout",
			"Get your tracking code from Hotjar dashboard",
		},
	}, nil
}

// AmplitudeCheck verifies Amplitude is properly set up
type AmplitudeCheck struct{}

func (c AmplitudeCheck) ID() string {
	return "amplitude"
}

func (c AmplitudeCheck) Title() string {
	return "Amplitude"
}

func (c AmplitudeCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["amplitude"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Amplitude not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`amplitude\.init`),
		regexp.MustCompile(`amplitude\.getInstance`),
		regexp.MustCompile(`amplitude\.track`),
		regexp.MustCompile(`cdn\.amplitude\.com`),
		regexp.MustCompile(`@amplitude/analytics`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Amplitude initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Amplitude is declared but initialization not found",
		Suggestions: []string{
			"Add amplitude.init() with your API key",
			"Check Amplitude docs for your framework",
		},
	}, nil
}

// SegmentCheck verifies Segment is properly set up
type SegmentCheck struct{}

func (c SegmentCheck) ID() string {
	return "segment"
}

func (c SegmentCheck) Title() string {
	return "Segment"
}

func (c SegmentCheck) Run(ctx Context) (CheckResult, error) {
	service, declared := ctx.Config.Services["segment"]
	if !declared || !service.Declared {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Segment not declared, skipping",
		}, nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`analytics\.load`),
		regexp.MustCompile(`analytics\.track`),
		regexp.MustCompile(`analytics\.identify`),
		regexp.MustCompile(`cdn\.segment\.com`),
		regexp.MustCompile(`@segment/analytics`),
	}

	found := searchForPatterns(ctx.RootDir, ctx.Config.Stack, patterns)

	if found {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Segment initialization found",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Segment is declared but initialization not found",
		Suggestions: []string{
			"Add analytics.load() with your write key",
			"Check Segment docs for your framework",
		},
	}, nil
}
