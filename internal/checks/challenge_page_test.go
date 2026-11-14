package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A bot challenge answered with a 200 used to be read as the site's own
// page, so its markup and headers were graded as if they were real.
func TestFetchPageTreatsAChallengeAsBlocked(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"cloudflare header": func(w http.ResponseWriter) {
			w.Header().Set("Cf-Mitigated", "challenge")
			_, _ = w.Write([]byte("<html><body>checking</body></html>"))
		},
		"cloudflare title": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Just a moment...</title></head><body></body></html>"))
		},
		"sucuri script": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("<html><title>You are being redirected...</title><script>var s={},sucuri_cloudproxy_js='';</script></html>"))
		},
		"imperva stub": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`<html><head><script src="/_Incapsula_Resource?SWJIYLWA=1"></script></head><body></body></html>`))
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) { write(w) })
			html, fetch := FetchPage(context.Background(), srv.Client(), srv.URL)
			if html != "" || !blockedStatus(fetch.Status) {
				t.Errorf("html=%q status=%d, want no page and a blocked status", html, fetch.Status)
			}
		})
	}
}

// A real page behind the same vendors loads their scripts and may talk
// about them; neither makes it a challenge.
func TestFetchPageKeepsRealPagesBehindAWAF(t *testing.T) {
	pages := map[string]string{
		"cloudflare detection script":   `<html><head><title>Acme</title></head><body><h1>Acme</h1><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></body></html>`,
		"imperva script on a full page": `<html><head><title>Acme</title><script src="/_Incapsula_Resource?SWJIYLWA=1"></script></head><body>` + strings.Repeat("<p>Real content here.</p>", 200) + `</body></html>`,
		"an article about it":           `<html><head><title>Why you see "Just a moment..." pages</title></head><body><p>Cloudflare shows a page titled Just a moment... while it checks your browser.</p></body></html>`,
	}
	for name, page := range pages {
		t.Run(name, func(t *testing.T) {
			srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(page)) })
			html, fetch := FetchPage(context.Background(), srv.Client(), srv.URL)
			if html == "" || fetch.Status != http.StatusOK {
				t.Errorf("status=%d and an empty page, want the real page", fetch.Status)
			}
		})
	}
}
