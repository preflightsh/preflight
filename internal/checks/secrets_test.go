package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// Two distinct values that match the GitHub PAT regex — 36 chars after ghp_.
// Using them in tests gives us two findings with distinct fingerprints.
const (
	fakeGHPATa = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fakeGHPATb = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// writeFile is a tiny helper that creates parent dirs and writes a file.
func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// runSecretsCheck wires up a minimal Context and returns the result.
func runSecretsCheck(t *testing.T, root string, secretsCfg *config.SecretsConfig) CheckResult {
	t.Helper()
	cfg := &config.PreflightConfig{
		Checks: config.ChecksConfig{Secrets: secretsCfg},
	}
	ctx := Context{RootDir: root, Config: cfg}
	res, err := SecretScanCheck{}.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	return res
}

func TestSecrets_PathOnlyAllowlistSuppresses(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "web/js/golden-hour.js", "const KEY = \""+fakeGHPATa+"\";\n")

	res := runSecretsCheck(t, root, &config.SecretsConfig{
		Enabled: true,
		Allowlist: []config.SecretAllowlistEntry{
			{Path: "web/js/golden-hour.js"},
		},
	})

	if !res.Passed {
		t.Fatalf("expected pass (path-only allowlist should suppress), got: %s", res.Message)
	}
}

func TestSecrets_FingerprintMismatchStillAlerts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "web/js/golden-hour.js", "const KEY = \""+fakeGHPATa+"\";\n")

	res := runSecretsCheck(t, root, &config.SecretsConfig{
		Enabled: true,
		Allowlist: []config.SecretAllowlistEntry{
			// Fingerprint belongs to a different secret value — should NOT suppress.
			{Path: "web/js/golden-hour.js", Fingerprint: fingerprintSecret(fakeGHPATb)},
		},
	})

	if res.Passed {
		t.Fatalf("expected alert (fingerprint mismatch should not suppress), got pass: %s", res.Message)
	}
	if !strings.Contains(res.Message, "web/js/golden-hour.js") {
		t.Fatalf("expected finding to reference the file, got: %s", res.Message)
	}
}

func TestSecrets_GlobExpansion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "web/tools/a/one.php", "<?php $k = '"+fakeGHPATa+"';\n")
	writeFile(t, root, "web/tools/b/deep/two.php", "<?php $k = '"+fakeGHPATb+"';\n")

	res := runSecretsCheck(t, root, &config.SecretsConfig{
		Enabled: true,
		Allowlist: []config.SecretAllowlistEntry{
			{Path: "web/tools/**/*.php"},
		},
	})

	if !res.Passed {
		t.Fatalf("expected pass (doublestar should match both files), got: %s", res.Message)
	}
}

func TestSecrets_UnrelatedSecretInAllowlistedFileStillAlerts(t *testing.T) {
	root := t.TempDir()
	// Two different secrets on two different lines → two different fingerprints.
	body := "line A: " + fakeGHPATa + "\nline B: " + fakeGHPATb + "\n"
	writeFile(t, root, "web/js/mixed.js", body)

	// Allowlist only the first secret by (path + fingerprint). The second must
	// still alert — proving findings are matched by path+fingerprint rather
	// than whole-file suppression.
	res := runSecretsCheck(t, root, &config.SecretsConfig{
		Enabled: true,
		Allowlist: []config.SecretAllowlistEntry{
			{Path: "web/js/mixed.js", Fingerprint: fingerprintSecret(fakeGHPATa)},
		},
	})

	if res.Passed {
		t.Fatalf("expected alert for the un-allowlisted secret, got pass: %s", res.Message)
	}
	// The remaining finding should be line 2 (the B secret).
	if !strings.Contains(res.Message, "mixed.js:2") {
		t.Fatalf("expected line 2 finding to remain, got: %s", res.Message)
	}
	if strings.Contains(res.Message, "mixed.js:1") {
		t.Fatalf("line 1 should have been suppressed, got: %s", res.Message)
	}
}

// Sanity: matcher works without an allowlist configured at all.
func TestSecrets_NoAllowlistBehavesAsBefore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.js", "const K = \""+fakeGHPATa+"\";\n")

	res := runSecretsCheck(t, root, &config.SecretsConfig{Enabled: true})
	if res.Passed {
		t.Fatalf("expected alert with no allowlist, got pass: %s", res.Message)
	}
}

// .env.<env> files (production/staging/development) were being silently
// dropped by the extension filter because filepath.Ext(".env.production")
// returns ".production" — not in codeExtensions, and the bare ".env"
// carve-out only matched the exact filename. These are the most
// important files for a pre-launch secrets check.
func TestSecrets_ScansEnvProductionAndSiblings(t *testing.T) {
	for _, name := range []string{".env.production", ".env.staging", ".env.development", ".env.prod"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, "GITHUB_TOKEN="+fakeGHPATa+"\n")

			res := runSecretsCheck(t, root, &config.SecretsConfig{Enabled: true})
			if res.Passed {
				t.Fatalf("expected %s to be scanned and alert, got pass: %s", name, res.Message)
			}
		})
	}
}

// .env.local-family files are intentionally skipped (they're meant to
// hold real secrets and should never be committed). Make sure the
// HasPrefix change above doesn't accidentally re-include them.
func TestSecrets_StillSkipsEnvLocalFamily(t *testing.T) {
	for _, name := range []string{".env.local", ".env.production.local", ".env.example"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, "GITHUB_TOKEN="+fakeGHPATa+"\n")

			res := runSecretsCheck(t, root, &config.SecretsConfig{Enabled: true})
			if !res.Passed {
				t.Fatalf("expected %s to be skipped, got alert: %s", name, res.Message)
			}
		})
	}
}

// Symlinks must not be followed. A hostile repo could plant a symlink
// with an in-scope filename pointing at ~/.aws/credentials etc. and
// trick the scanner into reading outside ctx.RootDir.
func TestSecrets_SkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "real-secrets.env"),
		[]byte("GITHUB_TOKEN="+fakeGHPATa+"\n"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(root, "leak.env")
	if err := os.Symlink(filepath.Join(outside, "real-secrets.env"), link); err != nil {
		t.Skipf("symlinks not supported on this filesystem: %v", err)
	}

	res := runSecretsCheck(t, root, &config.SecretsConfig{Enabled: true})
	if !res.Passed {
		t.Fatalf("expected no findings — symlink should be skipped — got: %s", res.Message)
	}
}

// A line containing an allowlisted secret AND a different real secret
// must still alert on the un-allowlisted one. The previous "only one
// match per line" loop made it possible to hide a real secret behind
// an allowlisted neighbor.
func TestSecrets_SameLineAllowlistDoesNotHideOtherSecret(t *testing.T) {
	root := t.TempDir()
	// Two distinct GitHub PATs on the same line.
	writeFile(t, root, "config.js", "const A = \""+fakeGHPATa+"\"; const B = \""+fakeGHPATb+"\";\n")

	res := runSecretsCheck(t, root, &config.SecretsConfig{
		Enabled: true,
		Allowlist: []config.SecretAllowlistEntry{
			// Only the A secret is allowlisted by fingerprint.
			{Path: "config.js", Fingerprint: fingerprintSecret(fakeGHPATa)},
		},
	})

	if res.Passed {
		t.Fatalf("expected alert for the un-allowlisted same-line secret, got pass: %s", res.Message)
	}
}
