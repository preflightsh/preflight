package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// Table-driven service checks (the AI providers among them) and the cookie
// consent checks used to say "found in environment" for a key that only
// .env.example names. They share envKeyPass now, so the message says which
// file gave the key and that a documented key is not verified.
func TestServiceEnvMessagesNameTheSource(t *testing.T) {
	cases := []struct {
		name  string
		check Check
		id    string
		key   string
	}{
		{"openai", OpenAICheck, "openai", "OPENAI_API_KEY"},
		{"together_ai", ServiceChecks["together_ai"], "together_ai", "TOGETHER_API_KEY"},
		{"cookiebot", CookiebotCheck{}, "cookiebot", "COOKIEBOT_CBID"},
		{"iubenda", IubendaCheck{}, "iubenda", "IUBENDA_SITE_ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := func(files map[string]string) CheckResult {
				t.Helper()
				dir := t.TempDir()
				for name, body := range files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				r, err := tc.check.Run(Context{RootDir: dir, Config: &config.PreflightConfig{
					Stack:    "static",
					Services: map[string]config.ServiceConfig{tc.id: {Declared: true}},
				}})
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			title := tc.check.Title()

			r := run(map[string]string{".env.example": tc.key + "=\n"})
			want := title + " key documented in .env.example (no value set locally, so it is not verified)"
			if !r.Passed || r.Message != want {
				t.Errorf("example only: passed=%v msg=%q, want %q", r.Passed, r.Message, want)
			}

			r = run(map[string]string{".env.example": tc.key + "=\n", ".env": tc.key + "=live-value-123\n"})
			if want := title + " key found in .env"; !r.Passed || r.Message != want {
				t.Errorf("real value: passed=%v msg=%q, want %q", r.Passed, r.Message, want)
			}
		})
	}
}
