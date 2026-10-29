package checks

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/config"
)

func TestMailDNSHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := lookupTXT(ctx, "cancelled.invalid"); err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestMailDomainCandidates(t *testing.T) {
	cases := []struct {
		host string
		want []string
	}{
		// www is typically a CNAME with no TXT records of its own, so the
		// organizational domain has to be tried too.
		{"www.kobo.com", []string{"www.kobo.com", "kobo.com"}},
		{"kobo.com", []string{"kobo.com"}},
		{"WWW.Kobo.com.", []string{"www.kobo.com", "kobo.com"}},
		{"blog.shop.example.co.uk", []string{"blog.shop.example.co.uk", "example.co.uk"}},
		// No registrable domain to fall back to.
		{"localhost", []string{"localhost"}},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := mailDomainCandidates(tc.host); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mailDomainCandidates(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestLookupFirst(t *testing.T) {
	domains := []string{"www.example.com", "example.com"}

	t.Run("falls back to the organizational domain", func(t *testing.T) {
		found, record, domain, err := lookupFirst(domains, func(d string) (bool, string, error) {
			if d == "example.com" {
				return true, "v=DMARC1; p=reject", nil
			}
			return false, "", nil
		})
		if !found || err != nil {
			t.Fatalf("lookupFirst = (%v, %v), want found with no error", found, err)
		}
		if domain != "example.com" || record != "v=DMARC1; p=reject" {
			t.Errorf("lookupFirst = (%q, %q), want the record from example.com", record, domain)
		}
	})

	t.Run("prefers the most specific domain", func(t *testing.T) {
		_, _, domain, _ := lookupFirst(domains, func(d string) (bool, string, error) {
			return true, "v=spf1 -all", nil
		})
		if domain != "www.example.com" {
			t.Errorf("lookupFirst domain = %q, want the host itself", domain)
		}
	})

	t.Run("a resolver failure cannot be hidden by the parent", func(t *testing.T) {
		found, _, domain, err := lookupFirst(domains, func(d string) (bool, string, error) {
			if d == "www.example.com" {
				return false, "", errors.New("server misbehaving")
			}
			return true, "v=spf1 -all", nil
		})
		if found || err == nil {
			t.Fatalf("lookupFirst = (%v, %v), want an inconclusive child lookup", found, err)
		}
		if domain != "www.example.com" {
			t.Errorf("lookupFirst domain = %q, want www.example.com", domain)
		}
	})

	t.Run("reports the error when no candidate resolves", func(t *testing.T) {
		found, _, _, err := lookupFirst(domains, func(d string) (bool, string, error) {
			return false, "", errors.New("server misbehaving")
		})
		if found || err == nil {
			t.Fatalf("lookupFirst = (%v, %v), want not found with an error", found, err)
		}
	})
}

// fakeTXT replaces the DNS lookup with a fixed table for the test's life.
// A name missing from the table is NXDOMAIN.
func fakeTXT(t *testing.T, records map[string][]string) *[]string {
	t.Helper()
	var asked []string
	orig := txtLookup
	txtLookup = func(_ context.Context, name string) ([]string, error) {
		asked = append(asked, name)
		if r, ok := records[name]; ok {
			return r, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	t.Cleanup(func() { txtLookup = orig })
	return &asked
}

// A config with emailAuth enabled but no domain (every one written before
// 0.24) checks the production URL's domain, as v0.23 did, and says where
// the domain came from. Before this it warned as inconclusive on every
// run, so CI could never pass.
func TestEmailAuthWithoutDomainUsesProductionHost(t *testing.T) {
	asked := fakeTXT(t, map[string][]string{
		"example.com":        {"v=spf1 include:_spf.example.net ~all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	})
	cfg := &config.PreflightConfig{
		URLs:   config.URLConfig{Production: "https://www.example.com/shop"},
		Checks: config.ChecksConfig{EmailAuth: &config.EmailAuthConfig{Enabled: true}},
	}
	res, err := EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed || res.Inconclusive || res.Skipped {
		t.Fatalf("got %+v, want a pass on the organizational domain", res)
	}
	if !strings.Contains(res.Message, "example.com") || !strings.Contains(res.Message, "checks.emailAuth.domain") {
		t.Errorf("message %q should name the domain and the key that chooses it", res.Message)
	}
	if len(*asked) == 0 || (*asked)[0] != "www.example.com" {
		t.Errorf("lookups %q should try the host first", *asked)
	}

	fakeTXT(t, map[string][]string{})
	res, _ = EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if res.Passed || res.Inconclusive || res.Severity != SeverityWarn || !strings.Contains(res.Message, "checks.emailAuth.domain") {
		t.Errorf("got %+v, want a real missing-records warning with the domain note", res)
	}
}

// With neither a domain nor a production URL there is nothing to look up.
func TestEmailAuthWithoutDomainOrURLSkips(t *testing.T) {
	asked := fakeTXT(t, nil)
	cfg := &config.PreflightConfig{Checks: config.ChecksConfig{EmailAuth: &config.EmailAuthConfig{Enabled: true}}}
	res, err := EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.Passed || !strings.Contains(res.Message, "checks.emailAuth.domain") {
		t.Errorf("got %+v, want a skip naming checks.emailAuth.domain", res)
	}
	if len(*asked) != 0 {
		t.Errorf("no lookups expected, got %q", *asked)
	}
}

// An explicit domain is used as written: SPF on the domain itself, with no
// note about the production URL.
func TestEmailAuthExplicitDomain(t *testing.T) {
	fakeTXT(t, map[string][]string{
		"mail.example.com":        {"v=spf1 -all"},
		"_dmarc.mail.example.com": {"v=DMARC1; p=none"},
	})
	cfg := &config.PreflightConfig{
		URLs:   config.URLConfig{Production: "https://other.example.org"},
		Checks: config.ChecksConfig{EmailAuth: &config.EmailAuthConfig{Enabled: true, Domain: "mail.example.com"}},
	}
	res, _ := EmailAuthCheck{}.Run(Context{Ctx: context.Background(), Config: cfg})
	if !res.Passed || strings.Contains(res.Message, "production URL") {
		t.Errorf("got %+v, want a pass for mail.example.com without the fallback note", res)
	}
}
