package checks

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// stubWWW replaces the network for one test: answers maps a requested URL
// to where it ended up and with what status. It returns the URLs requested.
func stubWWW(t *testing.T, answers map[string]finalAnswer) *[]string {
	t.Helper()
	orig := wwwFinalURL
	t.Cleanup(func() { wwwFinalURL = orig })
	var mu sync.Mutex
	var asked []string
	wwwFinalURL = func(_ context.Context, u string) finalAnswer {
		mu.Lock()
		asked = append(asked, u)
		mu.Unlock()
		if a, ok := answers[u]; ok {
			return a
		}
		t.Errorf("unexpected request for %s", u)
		return finalAnswer{}
	}
	return &asked
}

func wwwContext(production string) Context {
	return Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: production}}}
}

// A name under a hosting platform's suffix has no www counterpart. The
// check probed www.myapp.vercel.app and told the user to add a DNS record
// they cannot create.
func TestWWWRedirectSkipsPlatformSubdomains(t *testing.T) {
	asked := stubWWW(t, nil)
	for _, host := range []string{"myapp.vercel.app", "myapp.netlify.app", "user.github.io", "myapp.pages.dev"} {
		res, _ := WWWRedirectCheck{}.Run(wwwContext("https://" + host))
		if !res.Skipped || res.Passed || !strings.Contains(res.Message, "platform subdomain") {
			t.Errorf("%s: skipped=%v passed=%v msg=%q", host, res.Skipped, res.Passed, res.Message)
		}
	}
	if len(*asked) != 0 {
		t.Errorf("platform hosts were probed: %v", *asked)
	}
}

// Resolving is not serving: a www name that answers 404 from an
// unconfigured vhost used to read "Both www and non-www resolve correctly".
func TestWWWRedirectLooksAtTheFinalStatus(t *testing.T) {
	stubWWW(t, map[string]finalAnswer{
		"https://www.example.com": {url: "https://www.example.com/", status: 404},
		"https://example.com":     {url: "https://example.com/", status: 200},
	})
	res, _ := WWWRedirectCheck{}.Run(wwwContext("https://example.com"))
	if res.Passed || res.Inconclusive || !strings.Contains(res.Message, "www.example.com resolves but answers HTTP 404") {
		t.Errorf("passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
}

func TestWWWRedirectBlockedIsInconclusive(t *testing.T) {
	stubWWW(t, map[string]finalAnswer{
		"https://www.example.com": {url: "https://www.example.com/", status: 403},
		"https://example.com":     {url: "https://example.com/", status: 200},
	})
	res, _ := WWWRedirectCheck{}.Run(wwwContext("https://example.com"))
	if res.Passed || !res.Inconclusive || !strings.Contains(res.Message, "blocked (HTTP 403)") {
		t.Errorf("passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
}

// A redirect is evidence whatever the page it lands on answers.
func TestWWWRedirectPassesOnARedirect(t *testing.T) {
	stubWWW(t, map[string]finalAnswer{
		"https://www.example.com": {url: "https://example.com/", status: 403},
		"https://example.com":     {url: "https://example.com/", status: 403},
	})
	res, _ := WWWRedirectCheck{}.Run(wwwContext("https://www.example.com"))
	if !res.Passed || !strings.Contains(res.Message, "Both redirect to non-www") {
		t.Errorf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

func TestWWWRedirectKeepsThePort(t *testing.T) {
	asked := stubWWW(t, map[string]finalAnswer{
		"https://www.example.com:8443": {url: "https://example.com:8443/", status: 200},
		"https://example.com:8443":     {url: "https://example.com:8443/", status: 200},
	})
	res, _ := WWWRedirectCheck{}.Run(wwwContext("https://example.com:8443"))
	if !res.Passed || len(*asked) != 2 {
		t.Errorf("passed=%v asked=%v msg=%q", res.Passed, *asked, res.Message)
	}
}
