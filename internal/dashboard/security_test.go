package dashboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardRejectsCrossOriginAndDowngrade(t *testing.T) {
	hits := 0
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; fmt.Fprint(w, `{"email":"bad"}`) }))
	defer sink.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, http.StatusFound) }))
	defer origin.Close()
	c := NewClientFor(origin.URL)
	c.HTTP.Transport = origin.Client().Transport
	if _, err := c.Whoami("dummy-token"); err == nil {
		t.Fatal("redirect accepted")
	}
	if hits != 0 {
		t.Fatal("cross-origin endpoint received a request")
	}
}

func TestDashboardSameOriginRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/who" {
			http.Redirect(w, r, "/who", http.StatusFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer dummy-token" {
			t.Error("missing token")
		}
		fmt.Fprint(w, `{"email":"test@example.com"}`)
	}))
	defer srv.Close()
	if email, err := NewClientFor(srv.URL).Whoami("dummy-token"); err != nil || email != "test@example.com" {
		t.Fatalf("email=%q err=%v", email, err)
	}
}

func TestDashboardRejectsInvalidBaseURLs(t *testing.T) {
	for _, base := range []string{"http://[invalid", "file:///tmp/creds", "https:///missing", "https://user:pass@example.com", "https://example.com/?token=secret", "http://example.com"} {
		t.Run(base, func(t *testing.T) {
			c := NewClientFor(base)
			if _, err := c.Whoami("token"); err == nil {
				t.Fatal("invalid URL accepted")
			}
			if _, err := c.PublishRun("token", &PublishRequest{}); err == nil {
				t.Fatal("publish accepted")
			}
			if _, err := c.GetRun("token", "id"); err == nil {
				t.Fatal("get accepted")
			}
			if _, err := c.ListRuns("token", "", 1); err == nil {
				t.Fatal("list accepted")
			}
			if _, err := c.StartAuth(); err == nil {
				t.Fatal("auth accepted")
			}
		})
	}
}

func TestDashboardCancellationAndResponseLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"email":"test"}`) }))
	defer srv.Close()
	c := NewClientFor(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Ctx = ctx
	if _, err := c.Whoami("token"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxAPIResponse+1)))}
	var dst any
	if err := decodeResponse(resp, &dst); err == nil {
		t.Fatal("unbounded response accepted")
	}
}

func TestLegacyCredentialsCannotFollowEnvironment(t *testing.T) {
	t.Setenv("PREFLIGHT_API_URL", "http://localhost:9999")
	c, _ := ClientForCredentials(&Credentials{Token: "token"})
	if c.BaseURL != DefaultAPIURL {
		t.Fatalf("legacy token redirected to %s", c.BaseURL)
	}
}
