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
