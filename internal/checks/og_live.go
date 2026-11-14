package checks

import (
	"fmt"
	"strings"
)

// imageSizeTolerance is how far under the recommended size an image may be
// before it is called out. 1200x628 is what Facebook's own tooling exported
// for years; flagging it as "below recommended (1200x630)" was noise.
const imageSizeTolerance = 0.95

func (c OGTwitterCheck) runRendered(ctx Context) CheckResult {
	// Fetch here so image URLs and the metadata verdict use the same page.
	ctx = ctx.withHomepages()
	result, _ := renderedResult(ctx, c, func(doc renderedDoc) []string {
		var missing []string
		for _, name := range []string{"og:image", "og:url", "og:type", "twitter:card"} {
			if !doc.hasMeta(name) {
				missing = append(missing, name)
			}
		}
		// X falls back to og:image when twitter:image is absent, so
		// twitter:image is only missing when neither is there.
		if !doc.hasMeta("twitter:image") && !doc.hasMeta("og:image") {
			missing = append(missing, "twitter:image")
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
	// measured remembers each image URL's size, so a page that names the
	// same image for both tags costs one request.
	type size struct {
		width, height int
		err           error
	}
	measured := map[string]size{}
	for _, name := range []string{"og:image", "twitter:image"} {
		raw := doc.meta(name)
		if raw == "" {
			continue
		}
		imageURL := resolveImageURL(raw, base)
		dims, seen := measured[imageURL]
		if !seen {
			if imageURL == "" {
				dims.err = fmt.Errorf("unusable image URL")
			} else {
				dims.width, dims.height, dims.err = fetchImageDimensions(ctx, imageURL)
			}
			measured[imageURL] = dims
		}
		width, height := dims.width, dims.height
		if dims.err != nil {
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
		} else if float64(width) < float64(rw)*imageSizeTolerance || float64(height) < float64(rh)*imageSizeTolerance {
			result.Passed = false
			result.Severity = SeverityWarn
			result.Message += fmt.Sprintf("; %s below recommended (%dx%d, recommended %dx%d)", name, width, height, rw, rh)
		}
	}
	result.Message = strings.TrimSpace(result.Message)
	return result
}
