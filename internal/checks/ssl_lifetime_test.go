package checks

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/config"
)

// Certificates are issued for as little as six days now. With the old
// absolute windows such a certificate was an error (exit 2) from the day it
// was issued, and a 45-day one warned while renewal was on schedule.
func TestSSLExpiryScalesWithLifetime(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	cases := []struct {
		name      string
		lifetime  time.Duration
		remaining time.Duration
		severity  Severity
	}{
		{"six-day certificate on the day it is issued", 160 * time.Hour, 159 * time.Hour, SeverityInfo},
		{"six-day certificate two thirds through", 160 * time.Hour, 60 * time.Hour, SeverityInfo},
		{"six-day certificate overdue for renewal", 160 * time.Hour, 40 * time.Hour, SeverityWarn},
		{"six-day certificate about to lapse", 160 * time.Hour, 10 * time.Hour, SeverityError},
		{"45-day certificate with 29 days left", 45 * day, 29 * day, SeverityInfo},
		{"45-day certificate with 10 days left", 45 * day, 10 * day, SeverityWarn},
		{"45-day certificate with 3 days left", 45 * day, 3 * day, SeverityError},
		{"90-day certificate with 29 days left", 90 * day, 29 * day, SeverityWarn},
		{"one-year certificate with 20 days left", 365 * day, 20 * day, SeverityWarn},
		{"one-year certificate with 5 days left", 365 * day, 5 * day, SeverityError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notAfter := now.Add(tc.remaining)
			res := SSLCheck{}.expiryResult(selfSignedCert(t, notAfter.Add(-tc.lifetime), notAfter, "example.com"))
			if res.Severity != tc.severity {
				t.Errorf("severity = %s (%s), want %s", res.Severity, res.Message, tc.severity)
			}
		})
	}
}

func TestSSLExpiryWording(t *testing.T) {
	if got := expiresIn(10 * time.Hour); got != "10 hours" {
		t.Errorf("expiresIn(10h) = %q", got)
	}
	if got := expiresIn(20 * 24 * time.Hour); got != "20 days" {
		t.Errorf("expiresIn(20d) = %q", got)
	}
}

// An http:// production URL that redirects to HTTPS on the same site has a
// certificate to grade. It is a warning about the config, not an error
// telling the user to go and get a certificate.
func TestSSLPlainHTTPThatRedirectsToHTTPS(t *testing.T) {
	origUpgrade, origGrade := sslHTTPSUpgrade, sslGradeHost
	t.Cleanup(func() { sslHTTPSUpgrade, sslGradeHost = origUpgrade, origGrade })

	sslHTTPSUpgrade = func(Context, *url.URL) *url.URL {
		u, _ := url.Parse("https://www.example.com/")
		return u
	}
	ctx := Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: "http://example.com"}}}

	sslGradeHost = func(c SSLCheck, _ Context, u *url.URL) CheckResult {
		if u.Host != "www.example.com" {
			t.Errorf("graded %q, want the host the redirect landed on", u.Host)
		}
		return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityInfo, Passed: true, Message: "Valid, expires in 60 days"}
	}
	res, _ := SSLCheck{}.Run(ctx)
	if res.Passed || res.Severity != SeverityWarn || !strings.Contains(res.Message, "redirects to HTTPS") || !strings.Contains(res.Message, "valid, expires in 60 days") {
		t.Errorf("valid certificate behind an http URL: %s passed=%v %q", res.Severity, res.Passed, res.Message)
	}

	sslGradeHost = func(c SSLCheck, _ Context, _ *url.URL) CheckResult {
		return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityError, Message: "SSL certificate expired 3 days ago"}
	}
	res, _ = SSLCheck{}.Run(ctx)
	if res.Severity != SeverityError || !strings.Contains(res.Message, "expired") {
		t.Errorf("bad certificate behind an http URL must stay an error: %s %q", res.Severity, res.Message)
	}
}

func TestSameSiteAndPlatformHosts(t *testing.T) {
	same := [][2]string{{"example.com", "www.example.com"}, {"Example.com", "example.com"}, {"a.example.co.uk", "example.co.uk"}, {"127.0.0.1", "127.0.0.1"}}
	for _, p := range same {
		if !sameSite(p[0], p[1]) {
			t.Errorf("sameSite(%q, %q) = false", p[0], p[1])
		}
	}
	different := [][2]string{{"example.com", "example.org"}, {"a.vercel.app", "b.vercel.app"}, {"example.co.uk", "other.co.uk"}, {"127.0.0.1", "127.0.0.2"}, {"example.com", ""}}
	for _, p := range different {
		if sameSite(p[0], p[1]) {
			t.Errorf("sameSite(%q, %q) = true", p[0], p[1])
		}
	}
	for _, h := range []string{"myapp.vercel.app", "myapp.netlify.app", "myapp.pages.dev", "user.github.io", "myapp.fly.dev", "myapp.herokuapp.com", "myapp.web.app"} {
		if !platformHost(h) {
			t.Errorf("platformHost(%q) = false", h)
		}
	}
	for _, h := range []string{"example.com", "www.example.com", "example.co.uk", "app.example.dev", "localhost", "example.invalid"} {
		if platformHost(h) {
			t.Errorf("platformHost(%q) = true", h)
		}
	}
}
