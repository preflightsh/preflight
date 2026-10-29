package checks

import (
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// SvelteKit, Remix, and Nuxt keep the document head in a file of their own;
// without it the layout-based SEO checks report "No layout file found".
func TestGetLayoutFileMetaFrameworks(t *testing.T) {
	cases := []struct {
		stack string
		files map[string]string
		want  string
	}{
		{"svelte", map[string]string{"src/app.html": "<html>"}, "src/app.html"},
		{"remix", map[string]string{"app/root.tsx": "export default function App() {}"}, "app/root.tsx"},
		{"remix", map[string]string{"app/root.jsx": "export default function App() {}"}, "app/root.jsx"},
		{"nuxt", map[string]string{"app.vue": "<template/>", "nuxt.config.ts": "export default {}"}, "app.vue"},
		{"nuxt", map[string]string{"nuxt.config.ts": "export default {}"}, "nuxt.config.ts"},
		// Stack unknown (detection missed): the fallback still finds them.
		{"vite", map[string]string{"app/root.tsx": "x"}, "app/root.tsx"},
		{"vite", map[string]string{"src/app.html": "x"}, "src/app.html"},
	}
	for _, tc := range cases {
		root := writeFiles(t, tc.files)
		if got := getLayoutFile(root, tc.stack, ""); got != tc.want {
			t.Errorf("%s %v: getLayoutFile = %q, want %q", tc.stack, tc.files, got, tc.want)
		}
	}
}

// Nuxt injects the viewport meta itself, so a Nuxt app.vue without one is
// not missing it.
func TestViewportNuxtDefault(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"app.vue":        "<template><NuxtPage /></template>",
		"nuxt.config.ts": "export default defineNuxtConfig({})",
	})
	res, _ := ViewportCheck{}.Run(Context{RootDir: root, Config: &config.PreflightConfig{Stack: "nuxt"}})
	if !res.Passed {
		t.Fatalf("nuxt viewport: %q", res.Message)
	}
}
