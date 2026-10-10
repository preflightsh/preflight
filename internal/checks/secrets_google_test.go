package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestBrowserGoogleKeyIsAWarning: a Maps key in client JavaScript is public
// by design (restricted by referrer). It was reported at Error severity as a
// "Google AI/Firebase API key".
func TestBrowserGoogleKeyIsAWarning(t *testing.T) {
	key := "AIza" + strings.Repeat("Sy0_aB1-cD2", 3) + "xy"
	root := t.TempDir()
	writeFixture(t, root, "web/js/golden-hour.js", "fetch(`https://maps.googleapis.com/maps/api/timezone/json?key="+key+"`)\n")

	res, _ := SecretScanCheck{}.Run(Context{RootDir: root, Config: &config.PreflightConfig{}})
	if res.Passed || res.Severity != SeverityWarn || !strings.Contains(res.Message, "referrer") {
		t.Fatalf("passed=%v sev=%s msg=%q", res.Passed, res.Severity, res.Message)
	}
	if !strings.Contains(strings.Join(res.Suggestions, " "), "(Google API key)") {
		t.Errorf("label: %v", res.Suggestions)
	}

	// The same key in server code is still an error.
	writeFixture(t, root, "server/ai.go", "package server\nconst geminiKey = \""+key+"\"\n")
	res, _ = SecretScanCheck{}.Run(Context{RootDir: root, Config: &config.PreflightConfig{}})
	if res.Severity != SeverityError {
		t.Fatalf("server-side key: sev=%s msg=%q", res.Severity, res.Message)
	}
}
