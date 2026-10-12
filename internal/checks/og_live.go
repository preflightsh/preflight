package checks

import (
	"fmt"
	"strings"
)

func (c OGTwitterCheck) runRendered(ctx Context) CheckResult {
	// Fetch here so image URLs and the metadata verdict use the same page.
	if ctx.Client != nil {
		if ctx.Config.URLs.Production != "" && !ctx.PageFetchProduction.Attempted() {
			ctx.PageHTMLProduction, ctx.PageFetchProduction = FetchPage(ctx.reqContext(), ctx.Client, ctx.Config.URLs.Production)
		}
		if ctx.Config.URLs.Staging != "" && !ctx.PageFetchStaging.Attempted() {
			ctx.PageHTMLStaging, ctx.PageFetchStaging = FetchPage(ctx.reqContext(), ctx.Client, ctx.Config.URLs.Staging)
		}
	}
	result, _ := renderedResult(ctx, c, func(doc renderedDoc) []string {
		var missing []string
		for _, name := range []string{"og:image", "og:url", "og:type", "twitter:card", "twitter:image"} {
			if !doc.hasMeta(name) {
				missing = append(missing, name)
			}
		}
		return missing
	})
	if !result.Passed {
		return result
	}
	body, base := ctx.PageHTMLProduction, ctx.Config.URLs.Production
	if base == "" {
		body, base = ctx.PageHTMLStaging, ctx.Config.URLs.Staging
	}
	doc := parseRenderedHTML(body)
	if ctx.Client == nil {
		return result
	}
	for _, name := range []string{"og:image", "twitter:image"} {
		raw := doc.metaProperty[name]
		if raw == "" {
			raw = doc.metaName[name]
		}
		width, height, err := fetchImageDimensions(ctx, resolveImageURL(raw, base))
		if err != nil {
			result.Passed = false
			result.Severity = SeverityWarn
			result.Message += "; " + name + " could not be verified"
			result.Inconclusive = true
			continue
		}
		rw, rh := ogRecommendedWidth, ogRecommendedHeight
		if name == "twitter:image" {
			rw, rh = twitterRecommendedWidth, twitterRecommendedHeight
		}
		result.Details = append(result.Details, fmt.Sprintf("%s dimensions: %dx%d", name, width, height))
		mw, mh := ogMinWidth, ogMinHeight
		if name == "twitter:image" {
			mw, mh = twitterMinWidth, twitterMinHeight
		}
		if width < mw || height < mh {
			result.Passed = false
			result.Severity = SeverityWarn
			result.Message += fmt.Sprintf("; %s too small (%dx%d, min %dx%d)", name, width, height, mw, mh)
		} else if width < rw || height < rh {
			result.Passed = false
			result.Severity = SeverityWarn
			result.Message += fmt.Sprintf("; %s below recommended (%dx%d, recommended %dx%d)", name, width, height, rw, rh)
		}
	}
	result.Message = strings.TrimSpace(result.Message)
	return result
}
