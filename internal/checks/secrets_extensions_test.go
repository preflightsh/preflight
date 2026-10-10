package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestSecretsScansConfigAndTemplateFiles: next.config.mjs, wrangler.toml,
// main.tf and single-file components are where keys actually get pasted.
// They were outside the extension allowlist, so a live key in any of them
// reported "No secrets detected".
func TestSecretsScansConfigAndTemplateFiles(t *testing.T) {
	root := t.TempDir()
	key := "sk_live_" + strings.Repeat("a1B2", 8)
	files := []string{"next.config.mjs", "wrangler.toml", "main.tf", "src/App.vue", "src/Pay.svelte", "index.html", "app.properties", "server.cjs", "control.js"}
	for _, n := range files {
		writeFixture(t, root, n, "const k = \""+key+"\"\n")
	}
	// Docs are deliberately not scanned: they show example keys.
	writeFixture(t, root, "README.md", "Set STRIPE_KEY="+key+"\n")

	res, _ := SecretScanCheck{}.Run(Context{RootDir: root, Config: &config.PreflightConfig{}})
	if res.Passed {
		t.Fatalf("no secrets reported: %q", res.Message)
	}
	// Suggestions list the first few locations only, so count via Message.
	if want := "found in 9 place(s)"; !strings.Contains(res.Message, want) {
		t.Errorf("message %q, want %q", res.Message, want)
	}
	if joined := strings.Join(res.Suggestions, "\n"); strings.Contains(joined, "README.md") {
		t.Errorf("README.md reported; docs should not be scanned")
	}
}
