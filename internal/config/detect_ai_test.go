package config

import (
	"strings"
	"testing"
)

// The Google AI check accepted the current SDK and model names while
// detection still knew only the first generation, so init never declared
// a service the check would have passed.
func TestDetectGoogleAICurrentNames(t *testing.T) {
	for _, content := range []string{
		`"dependencies": {"@google/genai": "^1.0.0"}`,
		"google-genai==1.2.0",
		`"dependencies": {"@google/generative-ai": "^0.21.0"}`,
	} {
		services := map[string]bool{}
		detectServicesFromContent(strings.ToLower(content), services, "node")
		if !services["google_ai"] {
			t.Errorf("google_ai not detected from %q", content)
		}
	}
}
