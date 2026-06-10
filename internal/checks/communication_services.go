package checks

import (
	"regexp"
)

// TwilioCheck verifies Twilio is properly set up
var TwilioCheck = ServiceCheck{
	CheckID:     "twilio",
	CheckTitle:  "Twilio",
	EnvPrefixes: []string{"TWILIO_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@twilio/`),
		regexp.MustCompile(`Twilio\.Rest`),
		regexp.MustCompile(`twilio\.com`),
		regexp.MustCompile(`new Twilio\(`),
		regexp.MustCompile(`from\s+["']twilio["']`),
		regexp.MustCompile(`require\s*\(\s*["']twilio["']\)`),
	},
	EnvFoundMsg:  "Twilio configuration found in environment",
	CodeFoundMsg: "Twilio SDK initialization found",
	NotFoundMsg:  "Twilio is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN to environment",
	},
}

// SlackCheck verifies Slack is properly set up
var SlackCheck = ServiceCheck{
	CheckID:     "slack",
	CheckTitle:  "Slack",
	EnvPrefixes: []string{"SLACK_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@slack/`),
		regexp.MustCompile(`slack-ruby`),
		regexp.MustCompile(`hooks\.slack\.com`),
		regexp.MustCompile(`api\.slack\.com`),
	},
	EnvFoundMsg:  "Slack configuration found in environment",
	CodeFoundMsg: "Slack integration found",
	NotFoundMsg:  "Slack is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add SLACK_WEBHOOK_URL or SLACK_TOKEN to environment",
	},
}

// DiscordCheck verifies Discord is properly set up
var DiscordCheck = ServiceCheck{
	CheckID:     "discord",
	CheckTitle:  "Discord",
	EnvPrefixes: []string{"DISCORD_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`discord\.js`),
		regexp.MustCompile(`discord\.py`),
		regexp.MustCompile(`discordrb`),
		regexp.MustCompile(`discord\.com/api`),
	},
	EnvFoundMsg:  "Discord configuration found in environment",
	CodeFoundMsg: "Discord SDK initialization found",
	NotFoundMsg:  "Discord is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add DISCORD_TOKEN or DISCORD_WEBHOOK_URL to environment",
	},
}

// IntercomCheck verifies Intercom is properly set up
var IntercomCheck = ServiceCheck{
	CheckID:     "intercom",
	CheckTitle:  "Intercom",
	EnvPrefixes: []string{"INTERCOM_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`widget\.intercom\.io`),
		regexp.MustCompile(`Intercom\(`),
		regexp.MustCompile(`intercomSettings`),
		regexp.MustCompile(`@intercom/`),
	},
	EnvFoundMsg:  "Intercom configuration found in environment",
	CodeFoundMsg: "Intercom widget found",
	NotFoundMsg:  "Intercom is declared but widget not found",
	NotFoundSuggestions: []string{
		"Add Intercom widget script to your templates",
		"Add INTERCOM_APP_ID to environment",
	},
}

// CrispCheck verifies Crisp is properly set up
var CrispCheck = ServiceCheck{
	CheckID:     "crisp",
	CheckTitle:  "Crisp",
	EnvPrefixes: []string{"CRISP_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`client\.crisp\.chat`),
		regexp.MustCompile(`CRISP_WEBSITE_ID`),
		regexp.MustCompile(`\$crisp`),
	},
	EnvFoundMsg:  "Crisp configuration found in environment",
	CodeFoundMsg: "Crisp widget found",
	NotFoundMsg:  "Crisp is declared but widget not found",
	NotFoundSuggestions: []string{
		"Add Crisp chat widget script to your templates",
		"Add CRISP_WEBSITE_ID to environment",
	},
}
