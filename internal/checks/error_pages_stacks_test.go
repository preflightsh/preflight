package checks

import (
	"slices"
	"testing"
)

// Remix, Nuxt, and SvelteKit are detected as their own stacks now, so each
// needs its framework's error page convention rather than the default.
func TestErrorPagePathsForNewStacks(t *testing.T) {
	cases := []struct {
		stack, want404 string
	}{
		{"remix", "app/routes/$.tsx"},
		{"nuxt", "error.vue"},
		{"svelte", "src/routes/+error.svelte"},
	}
	for _, tc := range cases {
		paths404, _ := getErrorPagePaths(tc.stack)
		if !slices.Contains(paths404, tc.want404) {
			t.Errorf("%s: 404 paths %v do not include %s", tc.stack, paths404, tc.want404)
		}
		if got := getErrorPageSuggestions(tc.stack); len(got) == 0 || got[0] == "Add a custom 404.html page" {
			t.Errorf("%s: got the default suggestion %v", tc.stack, got)
		}
	}
}
