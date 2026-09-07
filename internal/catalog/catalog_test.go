package catalog

import "testing"

func TestCanonicalFollowsAliases(t *testing.T) {
	for old, current := range Aliases {
		if got := Canonical(old); got != current {
			t.Errorf("Canonical(%q) = %q, want %q", old, got, current)
		}
		if _, ok := LookupCheck(current); !ok {
			t.Errorf("alias %q points at %q, which is not a catalog check", old, current)
		}
		if _, ok := LookupCheck(old); ok {
			t.Errorf("old ID %q is still a catalog check; the alias would shadow it", old)
		}
	}
	if got := Canonical("sitemap"); got != "sitemap" {
		t.Errorf("Canonical of a current ID = %q, want unchanged", got)
	}
	if got := Canonical("nope"); got != "nope" {
		t.Errorf("Canonical of an unknown ID = %q, want unchanged", got)
	}
}

// Every current ID uses one convention. Mixed camelCase and snake_case
// was the reason for the rename; keep it from creeping back.
func TestCheckIDsAreSnakeCase(t *testing.T) {
	for _, c := range Checks {
		for _, r := range c.ID {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("check ID %q has an uppercase letter; IDs are snake_case", c.ID)
				break
			}
		}
	}
	for _, s := range Services {
		for _, r := range s.ID {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("service ID %q has an uppercase letter; IDs are snake_case", s.ID)
				break
			}
		}
	}
}
