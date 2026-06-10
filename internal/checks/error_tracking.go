package checks

import (
	"regexp"
)

// BugsnagCheck verifies Bugsnag is properly set up
var BugsnagCheck = ServiceCheck{
	CheckID:    "bugsnag",
	CheckTitle: "Bugsnag",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`Bugsnag\.start`),
		regexp.MustCompile(`bugsnag\.notify`),
		regexp.MustCompile(`@bugsnag/`),
		regexp.MustCompile(`bugsnag-js`),
		regexp.MustCompile(`Bugsnag\.configure`),
	},
	CodeFoundMsg: "Bugsnag initialization found",
	NotFoundMsg:  "Bugsnag is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add Bugsnag.start() to your application entry point",
		"Check Bugsnag docs for your framework",
	},
}

// RollbarCheck verifies Rollbar is properly set up
var RollbarCheck = ServiceCheck{
	CheckID:    "rollbar",
	CheckTitle: "Rollbar",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`Rollbar\.init`),
		regexp.MustCompile(`Rollbar\.configure`),
		regexp.MustCompile(`rollbar\.com`),
		regexp.MustCompile(`@rollbar/`),
	},
	CodeFoundMsg: "Rollbar initialization found",
	NotFoundMsg:  "Rollbar is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add Rollbar.init() with your access token",
		"Check Rollbar docs for your framework",
	},
}

// HoneybadgerCheck verifies Honeybadger is properly set up
var HoneybadgerCheck = ServiceCheck{
	CheckID:    "honeybadger",
	CheckTitle: "Honeybadger",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`Honeybadger\.configure`),
		regexp.MustCompile(`Honeybadger\.notify`),
		regexp.MustCompile(`@honeybadger-io/`),
		regexp.MustCompile(`honeybadger-js`),
	},
	CodeFoundMsg: "Honeybadger initialization found",
	NotFoundMsg:  "Honeybadger is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add Honeybadger.configure() with your API key",
		"Check Honeybadger docs for your framework",
	},
}

// DatadogCheck verifies Datadog is properly set up
var DatadogCheck = ServiceCheck{
	CheckID:    "datadog",
	CheckTitle: "Datadog",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`datadogRum\.init`),
		regexp.MustCompile(`DD_RUM`),
		regexp.MustCompile(`dd-trace`),
		regexp.MustCompile(`@datadog/`),
		regexp.MustCompile(`datadoghq\.com`),
	},
	CodeFoundMsg: "Datadog initialization found",
	NotFoundMsg:  "Datadog is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add Datadog RUM or APM initialization",
		"Check Datadog docs for your framework",
	},
}

// NewRelicCheck verifies New Relic is properly set up
var NewRelicCheck = ServiceCheck{
	CheckID:    "newrelic",
	CheckTitle: "New Relic",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`newrelic`),
		regexp.MustCompile(`@newrelic/`),
		regexp.MustCompile(`NREUM`),
		regexp.MustCompile(`nr-data\.net`),
	},
	CodeFoundMsg: "New Relic initialization found",
	NotFoundMsg:  "New Relic is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add New Relic browser agent or APM",
		"Check New Relic docs for your framework",
	},
}

// LogRocketCheck verifies LogRocket is properly set up
var LogRocketCheck = ServiceCheck{
	CheckID:    "logrocket",
	CheckTitle: "LogRocket",
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`LogRocket\.init`),
		regexp.MustCompile(`logrocket`),
		regexp.MustCompile(`cdn\.logrocket\.com`),
	},
	CodeFoundMsg: "LogRocket initialization found",
	NotFoundMsg:  "LogRocket is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add LogRocket.init() with your app ID",
		"Check LogRocket docs for your framework",
	},
}
