package checks

import (
	"strings"
	"testing"
)

// fakeKeyBody is base64-shaped key material: what a real key pasted into an
// example file looks like. It is not a key.
const fakeKeyBody = "MIIEpAIBAAKCAQEAx3k9Q2b7Zr1Lw8YpV0nTq5HcJmU4aFgDsE6iKoP2lB9yWvXt"

// TestSecretsExampleKeyPlaceholders: an example file that shows the shape of
// a private key setting is documentation. a2745c9 reported these as
// error-severity secrets (autochangelog went from exit 1 to 2). A real key
// pasted into an example file is still caught.
func TestSecretsExampleKeyPlaceholders(t *testing.T) {
	cases := []struct {
		name, file, body string
		found            bool
	}{
		{"escaped newline placeholder", ".env.example", `GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nYour private key here...\n-----END RSA PRIVATE KEY-----"` + "\n", false},
		{"multiline placeholder", ".env.example", "GITHUB_PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nYour private key here\n-----END RSA PRIVATE KEY-----\"\n", false},
		{"header only", ".env.sample", "KEY=\"-----BEGIN PRIVATE KEY-----\"\n", false},
		{"repeated filler", ".env.example", "KEY=\"-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("x", 64) + "\n-----END PRIVATE KEY-----\"\n", false},
		{"template file", "config.template.yml", "key: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  <paste your key>\n  -----END OPENSSH PRIVATE KEY-----\n", false},
		{"real key escaped", ".env.example", `GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n` + fakeKeyBody + `\n-----END RSA PRIVATE KEY-----"` + "\n", true},
		{"real key multiline", ".env.example", "GITHUB_PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\n" + fakeKeyBody + "\n" + fakeKeyBody + "\n-----END RSA PRIVATE KEY-----\"\n", true},
		{"placeholder outside an example file", ".env", "KEY=\"-----BEGIN RSA PRIVATE KEY-----\nYour private key here\n-----END RSA PRIVATE KEY-----\"\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, tc.file, tc.body)
			r, _ := (SecretScanCheck{}).Run(regressionContext(root))
			if r.Passed == tc.found {
				t.Fatalf("result=%+v, want found=%v", r, tc.found)
			}
		})
	}
}
