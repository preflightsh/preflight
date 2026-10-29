package catalog

import (
	"strings"
	"testing"
)

func TestRenamesPointAtCurrentChecks(t *testing.T) {
	for old, current := range Renames {
		if _, ok := LookupCheck(current); !ok {
			t.Errorf("rename %q points at %q, which is not a catalog check", old, current)
		}
		if _, ok := LookupCheck(old); ok {
			t.Errorf("old ID %q is still a catalog check", old)
		}
		if got := Canonical(old); got != old {
			t.Errorf("Canonical(%q) = %q; pre-1.0 names are rejected, not resolved", old, got)
		}
		err := RenamedError(old)
		if err == nil || !strings.Contains(err.Error(), `renamed to "`+current+`"`) {
			t.Errorf("RenamedError(%q) = %v, want it to name %q", old, err, current)
		}
	}
	if got := Canonical("sitemap"); got != "sitemap" {
		t.Errorf("Canonical of a current ID = %q, want unchanged", got)
	}
	if got := Canonical("nope"); got != "nope" {
		t.Errorf("Canonical of an unknown ID = %q, want unchanged", got)
	}
	if err := RenamedError("seo_meta"); err != nil {
		t.Errorf("RenamedError of a current ID = %v, want nil", err)
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

// "indexnow" is the IndexNow service ID, but the check is index_now. Before
// this mapping, --only indexnow was rejected and ignore: [indexnow] did nothing.
func TestIndexNowServiceIDResolvesToCheck(t *testing.T) {
	if got := Canonical("indexnow"); got != "index_now" {
		t.Errorf("Canonical(indexnow) = %q, want index_now", got)
	}
}
