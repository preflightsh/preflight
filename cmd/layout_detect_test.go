package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// SvelteKit, Remix, and Nuxt layouts enable the SEO checks, including for
// configs saved before 0.25 that recorded those projects as stack: vite.
func TestCanAutoDetectFrameworkLayouts(t *testing.T) {
	cases := []struct{ stack, file string }{
		{"remix", "app/root.tsx"},
		{"nuxt", "app.vue"},
		{"vite", "src/app.html"},
		{"vite", "app/root.tsx"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, tc.file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("<html></html>"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !canAutoDetectLayout(dir, tc.stack) {
			t.Errorf("stack %s with %s: layout not detected", tc.stack, tc.file)
		}
	}
	if canAutoDetectLayout(t.TempDir(), "remix") {
		t.Error("an empty remix project should have no layout")
	}
}
