package checks

import (
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestOGRenderedImageDimensionsAreMeasured: a CMS emits og:image at runtime,
// so it is never in the template. The check's comment promised dimension
// checks "against the rendered values", but the image URL only ever came
// from the template, so a 100x50 og:image on production passed silently.
func TestOGRenderedImageDimensionsAreMeasured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_ = png.Encode(w, image.NewRGBA(image.Rect(0, 0, 100, 50)))
	}))
	defer srv.Close()

	root := t.TempDir()
	writeFixture(t, root, "templates/_layout.twig", "<html><head>{{ seomatic }}</head><body></body></html>")
	rendered := `<html><head>
<meta property="og:image" content="` + srv.URL + `/og.png">
<meta property="og:url" content="https://example.com/">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="` + srv.URL + `/og.png">
</head></html>`
	ctx := Context{
		RootDir: root,
		Client:  srv.Client(),
		Config: &config.PreflightConfig{
			Stack:  "craft",
			URLs:   config.URLConfig{Production: "https://example.com"},
			Checks: config.ChecksConfig{SEOMeta: &config.SEOMetaConfig{MainLayout: "templates/_layout.twig"}},
		},
		PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200},
		PageHTMLProduction:  rendered,
	}
	res, _ := OGTwitterCheck{}.Run(ctx)
	if res.Passed || !strings.Contains(res.Message, "og:image too small") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}
