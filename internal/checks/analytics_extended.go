package checks

import (
	"regexp"
)

// UmamiCheck verifies Umami Analytics is properly set up
var UmamiCheck = ServiceCheck{
	CheckID:    "umami",
	CheckTitle: "Umami Analytics",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`data-website-id=`),           // Umami-specific script attribute
		regexp.MustCompile(`(?i)cloud\.umami\.is`),       // Umami Cloud
		regexp.MustCompile(`(?i)analytics\.umami\.is`),   // Umami Cloud (legacy)
		regexp.MustCompile(`(?i)umami\.track\(`),         // umami.track() API
		regexp.MustCompile(`(?i)umami\.identify\(`),      // umami.identify() API
		regexp.MustCompile(`from\s+["']@umami/`),         // npm package import
		regexp.MustCompile(`require\s*\(\s*["']@umami/`), // npm package require
		regexp.MustCompile(`UMAMI_WEBSITE_ID`),           // env var pattern
		regexp.MustCompile(`NEXT_PUBLIC_UMAMI`),          // Next.js env var
	},
	CodeFoundMsg: "Umami Analytics script found",
	NotFoundMsg:  "Umami is declared but script not found in templates",
	NotFoundSuggestions: []string{
		"Add the Umami script tag to your main layout",
		"Example: <script defer src=\"https://your-umami-host/script.js\" data-website-id=\"YOUR-ID\"></script>",
		"For self-hosted Umami, ensure data-website-id attribute is present on the script tag",
	},
}

// FullresCheck verifies Fullres Analytics is properly set up
var FullresCheck = ServiceCheck{
	CheckID:    "fullres",
	CheckTitle: "Fullres Analytics",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`window\.fullres`),
		regexp.MustCompile(`var fullres`),
		regexp.MustCompile(`fullres\.events`),
		regexp.MustCompile(`fullres\.co`),
		regexp.MustCompile(`fullres\.io`),
	},
	CodeFoundMsg: "Fullres Analytics script found",
	NotFoundMsg:  "Fullres is declared but script not found in templates",
	NotFoundSuggestions: []string{
		"Add the Fullres script tag to your main layout",
		"Check your Fullres dashboard for the correct embed code",
	},
}

// DatafastCheck verifies Datafa.st Analytics is properly set up
var DatafastCheck = ServiceCheck{
	CheckID:    "datafast",
	CheckTitle: "Datafa.st Analytics",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`datafa\.st`),
		regexp.MustCompile(`datafast\.io`),
		regexp.MustCompile(`cdn\.datafast`),
	},
	CodeFoundMsg: "Datafa.st Analytics script found",
	NotFoundMsg:  "Datafa.st is declared but script not found in templates",
	NotFoundSuggestions: []string{
		"Add the Datafa.st script tag to your main layout",
	},
}

// PostHogCheck verifies PostHog is properly set up
var PostHogCheck = ServiceCheck{
	CheckID:    "posthog",
	CheckTitle: "PostHog",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`(?i)posthog\.init`),                   // posthog.init() or PostHog.init()
		regexp.MustCompile(`(?i)posthog\.capture`),                // posthog.capture() or PostHog.capture()
		regexp.MustCompile(`PostHogProvider`),                     // React provider pattern
		regexp.MustCompile(`from\s+["']posthog-js["']`),           // import from 'posthog-js'
		regexp.MustCompile(`require\s*\(\s*["']posthog-js["']\)`), // require('posthog-js')
		regexp.MustCompile(`i\.posthog\.com`),                     // PostHog cloud endpoint
		regexp.MustCompile(`us\.posthog\.com`),                    // US cloud endpoint
		regexp.MustCompile(`eu\.posthog\.com`),                    // EU cloud endpoint
		regexp.MustCompile(`POSTHOG_KEY`),                         // env var pattern
		regexp.MustCompile(`NEXT_PUBLIC_POSTHOG`),                 // Next.js env var
	},
	CodeFoundMsg: "PostHog initialization found",
	NotFoundMsg:  "PostHog is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add posthog.init() to your application",
		"Check PostHog docs for your framework",
	},
}

// MixpanelCheck verifies Mixpanel is properly set up
var MixpanelCheck = ServiceCheck{
	CheckID:    "mixpanel",
	CheckTitle: "Mixpanel",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`mixpanel\.init`),
		regexp.MustCompile(`mixpanel\.track`),
		regexp.MustCompile(`cdn\.mxpnl\.com`),
		regexp.MustCompile(`mixpanel-browser`),
	},
	CodeFoundMsg: "Mixpanel initialization found",
	NotFoundMsg:  "Mixpanel is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add mixpanel.init() with your project token",
		"Check Mixpanel docs for your framework",
	},
}

// HotjarCheck verifies Hotjar is properly set up
var HotjarCheck = ServiceCheck{
	CheckID:    "hotjar",
	CheckTitle: "Hotjar",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`hotjar\.com`),
		regexp.MustCompile(`static\.hotjar\.com`),
		regexp.MustCompile(`hj\s*\(`),
		regexp.MustCompile(`_hjSettings`),
	},
	CodeFoundMsg: "Hotjar tracking code found",
	NotFoundMsg:  "Hotjar is declared but tracking code not found",
	NotFoundSuggestions: []string{
		"Add the Hotjar tracking code to your main layout",
		"Get your tracking code from Hotjar dashboard",
	},
}

// AmplitudeCheck verifies Amplitude is properly set up
var AmplitudeCheck = ServiceCheck{
	CheckID:    "amplitude",
	CheckTitle: "Amplitude",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`amplitude\.init`),
		regexp.MustCompile(`amplitude\.getInstance`),
		regexp.MustCompile(`amplitude\.track`),
		regexp.MustCompile(`cdn\.amplitude\.com`),
		regexp.MustCompile(`@amplitude/analytics`),
	},
	CodeFoundMsg: "Amplitude initialization found",
	NotFoundMsg:  "Amplitude is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add amplitude.init() with your API key",
		"Check Amplitude docs for your framework",
	},
}

// SegmentCheck verifies Segment is properly set up
var SegmentCheck = ServiceCheck{
	CheckID:    "segment",
	CheckTitle: "Segment",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`analytics\.load`),
		regexp.MustCompile(`analytics\.track`),
		regexp.MustCompile(`analytics\.identify`),
		regexp.MustCompile(`cdn\.segment\.com`),
		regexp.MustCompile(`@segment/analytics`),
	},
	CodeFoundMsg: "Segment initialization found",
	NotFoundMsg:  "Segment is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add analytics.load() with your write key",
		"Check Segment docs for your framework",
	},
}
