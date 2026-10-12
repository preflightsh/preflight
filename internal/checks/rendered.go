package checks

import "strings"

// renderedResult verifies all requirements against deployed HTML whenever
// an environment is configured. Static hints must not override that evidence.
func renderedResult(ctx Context, c Check, inspect func(renderedDoc) []string) (CheckResult, bool) {
	if ctx.Config.URLs.Production == "" && ctx.Config.URLs.Staging == "" {
		return CheckResult{}, false
	}
	if ctx.Client != nil {
		if ctx.Config.URLs.Production != "" && !ctx.PageFetchProduction.Attempted() {
			ctx.PageHTMLProduction, ctx.PageFetchProduction = FetchPage(ctx.reqContext(), ctx.Client, ctx.Config.URLs.Production)
		}
		if ctx.Config.URLs.Staging != "" && !ctx.PageFetchStaging.Attempted() {
			ctx.PageHTMLStaging, ctx.PageFetchStaging = FetchPage(ctx.reqContext(), ctx.Client, ctx.Config.URLs.Staging)
		}
	}
	summary, passed := RunPerEnv(ctx, func(body string) []string { return inspect(parseRenderedHTML(body)) })
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
