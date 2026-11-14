package checks

import (
	"encoding/base64"
	"strings"
	"testing"
)

// fakeJWT builds an unsigned, synthetic JWT around the given payload. The
// signature is filler; nothing here is a credential.
func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + fakeBody48
}

// A Supabase service-role key bypasses row level security. It has no
// prefix, so it is recognised by decoding the token, and nothing else
// shaped like a JWT is reported.
func TestSecretsSupabaseServiceRoleKey(t *testing.T) {
	service := fakeJWT(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","iat":1700000000,"exp":2000000000}`)
	r := secretsResult(t, "src/admin.ts", "const key = '"+service+"'\n")
	if r.Passed || r.Severity != SeverityError || !strings.Contains(strings.Join(r.Suggestions, " "), "Supabase service-role key") {
		t.Errorf("service role key: passed=%v severity=%v msg=%q %v", r.Passed, r.Severity, r.Message, r.Suggestions)
	}

	notSecrets := map[string]string{
		"anon key":           fakeJWT(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2000000000}`),
		"local demo key":     fakeJWT(`{"iss":"supabase-demo","role":"service_role","exp":1983812996}`),
		"some other JWT":     fakeJWT(`{"sub":"1234567890","name":"Example User","iat":1700000000}`),
		"payload not JSON":   "eyJhbGciOiJIUzI1NiJ9.eyJub3QganNvbiBhdCBhbGw." + fakeBody48,
		"role in a sentence": fakeJWT(`{"note":"ask an admin for the service_role key"}`),
	}
	for name, token := range notSecrets {
		if r := secretsResult(t, "src/client.ts", "const key = '"+token+"'\n"); !r.Passed {
			t.Errorf("%s was reported: %q %v", name, r.Message, r.Suggestions)
		}
	}
}
