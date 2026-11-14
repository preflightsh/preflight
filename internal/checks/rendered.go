package checks

import "strings"

// renderedResult verifies all requirements against deployed HTML whenever
// an environment is configured. Static hints must not override that evidence.
func renderedResult(ctx Context, c Check, inspect func(renderedDoc) []string) (CheckResult, bool) {
	return renderedResultEnv(ctx, c, func(_ string, doc renderedDoc) []string { return inspect(doc) })
}

// renderedResultEnv is renderedResult for a check whose requirements differ
// between production and staging; inspect is told which one ("prod" or
// "staging") the page came from.
func renderedResultEnv(ctx Context, c Check, inspect func(env string, doc renderedDoc) []string) (CheckResult, bool) {
	if ctx.Config.URLs.Production == "" && ctx.Config.URLs.Staging == "" {
		return CheckResult{}, false
	}
	ctx = ctx.withHomepages()
	summary, passed := runPerEnv(ctx, func(env, body string) []string { return inspect(env, parseRenderedHTML(body)) })
	severity := SeverityInfo
	if !passed {
		severity = SeverityWarn
	}
	body := ctx.PageHTMLProduction
	if ctx.Config.URLs.Production == "" {
		body = ctx.PageHTMLStaging
	}
	return CheckResult{ID: c.ID(), Title: c.Title(), Passed: passed, Severity: severity, Message: summary, Inconclusive: strings.TrimSpace(body) == ""}, true
}

// withHomepages returns ctx with each configured environment's homepage
// fetched, for a check run outside a scan. Inside a scan the pages are
// already there and nothing is requested.
func (c Context) withHomepages() Context {
	if c.Client == nil {
		return c
	}
	if c.Config.URLs.Production != "" && !c.PageFetchProduction.Attempted() {
		c.PageHTMLProduction, c.PageFetchProduction = FetchPage(c.reqContext(), c.Client, c.Config.URLs.Production)
	}
	if c.Config.URLs.Staging != "" && !c.PageFetchStaging.Attempted() {
		c.PageHTMLStaging, c.PageFetchStaging = FetchPage(c.reqContext(), c.Client, c.Config.URLs.Staging)
	}
	return c
}
