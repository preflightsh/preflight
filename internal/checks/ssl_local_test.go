package checks

import (
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestSSLSkipsLocalURL: a local production URL (a dev server) was graded
// as an Error "does not use HTTPS", while www_redirect skipped it.
func TestSSLSkipsLocalURL(t *testing.T) {
	for _, u := range []string{"http://localhost:3000", "http://myapp.test", "http://127.0.0.1:8080", "localhost:3000", "https://myapp.ddev.site"} {
		ctx := Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: u}}}
		res, _ := SSLCheck{}.Run(ctx)
		if !res.Skipped || res.Passed || res.Severity == SeverityError {
			t.Errorf("%s: skipped=%v passed=%v sev=%s msg=%q", u, res.Skipped, res.Passed, res.Severity, res.Message)
		}
	}
}
