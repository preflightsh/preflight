package checks

import (
	"testing"

	"github.com/preflightsh/preflight/internal/catalog"
)

// The catalog is what users see (`preflight checks`, init prompts, the
// terminal renderer); ServiceChecks and Registry are what runs. A service
// present in one and missing from the other is exactly the drift that left
// umami scannable but unlisted, so pin the three sets together.
func TestServiceChecksMatchCatalog(t *testing.T) {
	// Verified by a differently-gated check, see the ServiceChecks doc.
	special := map[string]bool{"stripe": true, "indexnow": true}

	registry := map[string]bool{}
	for _, c := range Registry {
		registry[c.ID()] = true
	}

	for _, s := range catalog.Services {
		check, ok := ServiceChecks[s.ID]
		if special[s.ID] {
			if ok {
				t.Errorf("%s is special-cased but also has a ServiceChecks entry", s.ID)
			}
			continue
		}
		if !ok {
			t.Errorf("catalog service %q has no entry in ServiceChecks", s.ID)
			continue
		}
		if check.ID() != s.ID {
			t.Errorf("ServiceChecks[%q] runs a check with ID %q", s.ID, check.ID())
		}
		if !registry[s.ID] {
			t.Errorf("catalog service %q is not in Registry", s.ID)
		}
	}
	for id := range ServiceChecks {
		if _, ok := catalog.LookupService(id); !ok {
			t.Errorf("ServiceChecks has %q, which the catalog does not list", id)
		}
	}
	for _, c := range catalog.Checks {
		if !registry[c.ID] {
			t.Errorf("catalog check %q is not in Registry", c.ID)
		}
	}
	for id := range registry {
		if _, ok := catalog.LookupCheck(id); ok {
			continue
		}
		if _, ok := catalog.LookupService(id); ok {
			continue
		}
		t.Errorf("Registry check %q is missing from the catalog, so `preflight checks` will not list it", id)
	}
}
