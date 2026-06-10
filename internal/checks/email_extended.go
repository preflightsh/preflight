package checks

import (
	"regexp"
)

// MailchimpCheck verifies Mailchimp is properly set up
var MailchimpCheck = ServiceCheck{
	CheckID:     "mailchimp",
	CheckTitle:  "Mailchimp",
	EnvPrefixes: []string{"MAILCHIMP_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@mailchimp/`),
		regexp.MustCompile(`mailchimp\.com`),
		regexp.MustCompile(`list-manage\.com`),
		regexp.MustCompile(`mc4wp`),
		regexp.MustCompile(`mailchimp-for-wp`),
	},
	EnvFoundMsg:  "Mailchimp API key found in environment",
	CodeFoundMsg: "Mailchimp integration found",
	NotFoundMsg:  "Mailchimp is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add MAILCHIMP_API_KEY to your environment",
		"Install @mailchimp/mailchimp_marketing SDK",
	},
}

// ConvertKitCheck verifies ConvertKit/Kit is properly set up
var ConvertKitCheck = ServiceCheck{
	CheckID:     "convertkit",
	CheckTitle:  "Kit (ConvertKit)",
	EnvPrefixes: []string{"CONVERTKIT_", "KIT_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`convertkit\.com`),
		regexp.MustCompile(`app\.kit\.com`),
		regexp.MustCompile(`@convertkit/`),
	},
	EnvFoundMsg:  "Kit API key found in environment",
	CodeFoundMsg: "Kit integration found",
	NotFoundMsg:  "Kit is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add CONVERTKIT_API_KEY to your environment",
		"Add Kit form embed code to your templates",
	},
}

// BeehiivCheck verifies Beehiiv is properly set up
var BeehiivCheck = ServiceCheck{
	CheckID:     "beehiiv",
	CheckTitle:  "Beehiiv",
	EnvPrefixes: []string{"BEEHIIV_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`beehiiv\.com`),
		regexp.MustCompile(`embeds\.beehiiv\.com`),
	},
	EnvFoundMsg:  "Beehiiv API key found in environment",
	CodeFoundMsg: "Beehiiv integration found",
	NotFoundMsg:  "Beehiiv is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add BEEHIIV_API_KEY to your environment",
		"Add Beehiiv embed code to your templates",
	},
}

// AWeberCheck verifies AWeber is properly set up
var AWeberCheck = ServiceCheck{
	CheckID:     "aweber",
	CheckTitle:  "AWeber",
	EnvPrefixes: []string{"AWEBER_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`aweber\.com`),
		regexp.MustCompile(`forms\.aweber\.com`),
	},
	EnvFoundMsg:  "AWeber configuration found in environment",
	CodeFoundMsg: "AWeber integration found",
	NotFoundMsg:  "AWeber is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add AWeber form embed code to your templates",
	},
}

// ActiveCampaignCheck verifies ActiveCampaign is properly set up
var ActiveCampaignCheck = ServiceCheck{
	CheckID:     "activecampaign",
	CheckTitle:  "ActiveCampaign",
	EnvPrefixes: []string{"ACTIVECAMPAIGN_", "AC_API"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`activecampaign\.com`),
		regexp.MustCompile(`trackcmp\.net`),
	},
	EnvFoundMsg:  "ActiveCampaign configuration found in environment",
	CodeFoundMsg: "ActiveCampaign integration found",
	NotFoundMsg:  "ActiveCampaign is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add ACTIVECAMPAIGN_API_KEY and ACTIVECAMPAIGN_URL to environment",
	},
}

// CampaignMonitorCheck verifies Campaign Monitor is properly set up
var CampaignMonitorCheck = ServiceCheck{
	CheckID:     "campaignmonitor",
	CheckTitle:  "Campaign Monitor",
	EnvPrefixes: []string{"CAMPAIGNMONITOR_", "CREATESEND_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`campaignmonitor\.com`),
		regexp.MustCompile(`createsend\.com`),
	},
	EnvFoundMsg:  "Campaign Monitor configuration found in environment",
	CodeFoundMsg: "Campaign Monitor integration found",
	NotFoundMsg:  "Campaign Monitor is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add Campaign Monitor API key to environment",
	},
}

// DripCheck verifies Drip is properly set up
var DripCheck = ServiceCheck{
	CheckID:     "drip",
	CheckTitle:  "Drip",
	EnvPrefixes: []string{"DRIP_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`getdrip\.com`),
		regexp.MustCompile(`tag\.getdrip\.com`),
	},
	EnvFoundMsg:  "Drip configuration found in environment",
	CodeFoundMsg: "Drip integration found",
	NotFoundMsg:  "Drip is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add Drip tracking script to your templates",
		"Add DRIP_API_KEY to environment",
	},
}

// KlaviyoCheck verifies Klaviyo is properly set up
var KlaviyoCheck = ServiceCheck{
	CheckID:     "klaviyo",
	CheckTitle:  "Klaviyo",
	EnvPrefixes: []string{"KLAVIYO_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`klaviyo\.com`),
		regexp.MustCompile(`static\.klaviyo\.com`),
	},
	EnvFoundMsg:  "Klaviyo configuration found in environment",
	CodeFoundMsg: "Klaviyo integration found",
	NotFoundMsg:  "Klaviyo is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add Klaviyo tracking script to your templates",
		"Add KLAVIYO_API_KEY to environment",
	},
}

// ButtondownCheck verifies Buttondown is properly set up
var ButtondownCheck = ServiceCheck{
	CheckID:     "buttondown",
	CheckTitle:  "Buttondown",
	EnvPrefixes: []string{"BUTTONDOWN_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`buttondown\.email`),
		regexp.MustCompile(`buttondown\.com`),
	},
	EnvFoundMsg:  "Buttondown configuration found in environment",
	CodeFoundMsg: "Buttondown integration found",
	NotFoundMsg:  "Buttondown is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add Buttondown form embed to your templates",
		"Add BUTTONDOWN_API_KEY to environment",
	},
}
