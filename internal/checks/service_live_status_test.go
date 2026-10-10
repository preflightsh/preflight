package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestServiceLiveCheckIgnoresBlockedPage: a Cloudflare challenge answers 403
// with its own markup. Reading that as the live page reported "found in code
// but not detected on live site" for every bot-protected site.
func TestServiceLiveCheckIgnoresBlockedPage(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, "<html><title>Just a moment...</title>challenge</html>")
			}))
			defer srv.Close()
			root := t.TempDir()
			writeFixture(t, root, "src/consent.js", "import 'cookieconsent'; CookieConsent.run({})\n")
			ctx := Context{
				RootDir: root,
				Client:  srv.Client(),
				Config: &config.PreflightConfig{
					URLs:     config.URLConfig{Production: srv.URL},
					Services: map[string]config.ServiceConfig{"cookieconsent": {Declared: true}},
				},
			}
			res, _ := CookieConsentJSCheck.Run(ctx)
			if !res.Passed {
				t.Fatalf("HTTP %d page treated as the live site: %q", status, res.Message)
			}
		})
	}
}

// TestServiceLiveCheckUsesPrefetch: the homepage the scan already fetched is
// the one inspected, so a service live on it passes without a second request.
func TestServiceLiveCheckUsesPrefetch(t *testing.T) {
	ctx := Context{
		RootDir: t.TempDir(),
		Config: &config.PreflightConfig{
			URLs: config.URLConfig{Production: "https://example.invalid"},
		},
		PageFetchProduction: PageFetch{URL: "https://example.invalid/", Status: 200},
		PageHTMLProduction:  `<script src="https://cdn.jsdelivr.net/gh/orestbida/cookieconsent/dist/cookieconsent.umd.js"></script>`,
	}
	found, url := checkLiveSiteForPatterns(ctx, CookieConsentJSCheck.LivePatterns)
	if !found || url == "" {
		t.Fatalf("prefetched page not inspected: found=%v url=%q", found, url)
	}
}
