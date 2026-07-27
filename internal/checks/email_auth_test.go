package checks

import (
	"errors"
	"reflect"
	"testing"
)

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

	t.Run("a resolver failure on the subdomain does not mask the parent", func(t *testing.T) {
		found, _, domain, err := lookupFirst(domains, func(d string) (bool, string, error) {
			if d == "www.example.com" {
				return false, "", errors.New("server misbehaving")
			}
			return true, "v=spf1 -all", nil
		})
		if !found || err != nil {
			t.Fatalf("lookupFirst = (%v, %v), want the parent's record and no error", found, err)
		}
		if domain != "example.com" {
			t.Errorf("lookupFirst domain = %q, want example.com", domain)
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
