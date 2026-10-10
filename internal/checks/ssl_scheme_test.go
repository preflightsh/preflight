package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestSSLSchemelessURL: "production: example.com" in a hand-edited config
// was graded as an Error "does not use HTTPS". The site may be fine; the
// config is missing its scheme, and the message should say so.
func TestSSLSchemelessURL(t *testing.T) {
	ctx := Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: "autochangelog.com"}}}
	res, _ := SSLCheck{}.Run(ctx)
	if res.Severity == SeverityError || !strings.Contains(res.Message, "no scheme") {
		t.Fatalf("sev=%s msg=%q", res.Severity, res.Message)
	}
}
