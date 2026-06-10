package checks

import (
	"regexp"
)

// AlgoliaCheck verifies Algolia is properly set up
var AlgoliaCheck = ServiceCheck{
	CheckID:     "algolia",
	CheckTitle:  "Algolia",
	EnvPrefixes: []string{"ALGOLIA_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`algoliasearch`),
		regexp.MustCompile(`@algolia/`),
		regexp.MustCompile(`algolia\.com`),
		regexp.MustCompile(`InstantSearch`),
	},
	EnvFoundMsg:  "Algolia configuration found in environment",
	CodeFoundMsg: "Algolia SDK initialization found",
	NotFoundMsg:  "Algolia is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add ALGOLIA_APP_ID and ALGOLIA_API_KEY to environment",
		"Initialize Algolia search client in your application",
	},
}
