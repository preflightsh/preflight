package checks

import (
	"io"
	"regexp"
	"strings"
)

// ServiceCheck is a table-driven Check for a declared third-party service.
// Most service integrations are verified the same mechanical way; the steps
// below run in order and the first hit wins:
//
//  1. pass (skip) when the service is not declared in preflight.yml
//  2. pass when an env var with one of EnvPrefixes exists in the project's
//     env files
//  3. pass when any LivePatterns matches the live homepage (production
//     first, then staging)
//  4. CodePatterns found in the codebase: warn when a live page was actually
//     fetched in step 3 and matched nothing (integrated in code but not
//     live), otherwise pass. "Otherwise" covers no URL configured and a URL
//     that could not be reached: neither says anything about what the live
//     page contains.
//  5. warn: declared but nothing found
//
// Steps 2 and 3 are skipped when their pattern lists are empty. Checks that
// need anything beyond this shape (DNS lookups, webhook probing, env-var
// reference scanning) keep their own bespoke Run implementations.
type ServiceCheck struct {
	CheckID    string
	CheckTitle string

	EnvPrefixes  []string
	LivePatterns []*regexp.Regexp
	CodePatterns []*regexp.Regexp

	// Result messages, kept per-service so output matches what each check
	// reported before being table-ified.
	EnvFoundMsg  string
	LiveFoundMsg string
	CodeFoundMsg string
	// LiveMissingMsg is reported when the code matched but the live page was
	// fetched and matched none of LivePatterns.
	LiveMissingMsg string
	NotFoundMsg    string

	LiveMissingSuggestions []string
	NotFoundSuggestions    []string
}

func (c ServiceCheck) ID() string    { return c.CheckID }
func (c ServiceCheck) Title() string { return c.CheckTitle }

func (c ServiceCheck) Run(ctx Context) (CheckResult, error) {
	pass := func(msg string) (CheckResult, error) {
		return CheckResult{
			ID: c.CheckID, Title: c.CheckTitle,
			Severity: SeverityInfo, Passed: true, Message: msg,
		}, nil
	}
	warn := func(msg string, suggestions []string) (CheckResult, error) {
		return CheckResult{
			ID: c.CheckID, Title: c.CheckTitle,
			Severity: SeverityWarn, Passed: false, Message: msg, Suggestions: suggestions,
		}, nil
	}

	service, declared := ctx.Config.Services[c.CheckID]
	if !declared || !service.Declared {
		return pass(c.CheckTitle + " not declared, skipping")
	}

	for _, prefix := range c.EnvPrefixes {
		if hasEnvVar(ctx.RootDir, prefix) {
			return pass(c.EnvFoundMsg)
		}
	}

	liveURL := ""
	if len(c.LivePatterns) > 0 {
		found, url := checkLiveSiteForPatterns(ctx, c.LivePatterns)
		if found {
			return pass(c.LiveFoundMsg)
		}
		liveURL = url
	}

	if len(c.CodePatterns) > 0 && searchForPatterns(ctx.RootDir, ctx.Config.Stack, c.CodePatterns) {
		if liveURL != "" {
			return warn(c.LiveMissingMsg, c.LiveMissingSuggestions)
		}
		return pass(c.CodeFoundMsg)
	}

	return warn(c.NotFoundMsg, c.NotFoundSuggestions)
}

// checkLiveSiteForPatterns fetches the live site (production URL first, then
// staging) and matches the lowercased body against patterns. Returns (found,
// urlInspected).
//
// urlInspected is empty unless a page was actually fetched and read, which is
// what lets callers tell "the live page doesn't have this" apart from "there
// was no live page to look at". They report the former as a warning, so
// returning a URL for a site that was never reached would claim an
// integration is missing from a page nobody looked at. A site that is down,
// a DNS name that doesn't resolve yet, or a CI runner with no egress is not
// evidence about the page's contents, and pre-launch projects (the ones this
// tool is for) hit all three.
func checkLiveSiteForPatterns(ctx Context, patterns []*regexp.Regexp) (bool, string) {
	url := ctx.Config.URLs.Production
	if url == "" {
		url = ctx.Config.URLs.Staging
	}
	if url == "" || ctx.Client == nil {
		return false, ""
	}

	resp, _, err := tryURL(ctx.reqContext(), ctx.Client, url)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, ""
	}

	content := strings.ToLower(string(body))
	for _, pattern := range patterns {
		if pattern.MatchString(content) {
			return true, url
		}
	}
	return false, url
}
