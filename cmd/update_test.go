package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"1.0.2", "1.0.1", true},
		{"v1.0.2", "1.0.1", true},
		{"1.0.1", "1.0.1", false},
		{"1.0.0", "1.0.1", false},
		{"1.10.0", "1.9.0", true},
		{"1.0.1", "1.0.1-rc.1", true},
		{"1.0.1-rc.1", "1.0.1", false},
		{"", "1.0.1", false},
		{"not-a-version", "1.0.1", false},
		{"1.0.2", "dev", false},
	}
	for _, tc := range cases {
		if got := isNewerVersion(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

// The prompt needs someone who can both see it (stderr) and answer it
// (stdin), and a command that is safe and able to run from here.
func TestCanPromptUpgrade(t *testing.T) {
	const brew = "brew upgrade preflightsh/preflight/preflight"
	cases := []struct {
		cmd           string
		stdin, stderr bool
		want          bool
	}{
		{brew, true, true, true},
		{brew, false, true, false},
		{brew, true, false, false},
		{"curl -sSL https://preflight.sh/install.sh | sh", true, true, false},
		{"docker pull ghcr.io/preflightsh/preflight:latest", true, true, false},
	}
	for _, tc := range cases {
		if got := canPromptUpgrade(tc.cmd, tc.stdin, tc.stderr); got != tc.want {
			t.Errorf("canPromptUpgrade(%q, %v, %v) = %v, want %v", tc.cmd, tc.stdin, tc.stderr, got, tc.want)
		}
	}
}

// One check per interval, whether or not the last one got an answer.
func TestShouldCheckForUpdate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if !shouldCheckForUpdate() {
		t.Fatal("no record yet: a check is due")
	}
	markUpdateChecked()
	if shouldCheckForUpdate() {
		t.Error("a check was just recorded: none is due")
	}
	stamp := filepath.Join(home, ".preflight", "last_update_check")
	old := time.Now().Add(-updateCheckInterval - time.Minute).UTC().Format(time.RFC3339)
	if err := os.WriteFile(stamp, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if !shouldCheckForUpdate() {
		t.Error("the record is older than the interval: a check is due")
	}
	if err := os.WriteFile(stamp, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !shouldCheckForUpdate() {
		t.Error("an unreadable record should not block the check")
	}
}

// The upgrade command follows from where the binary lives. The test
// binary lives in a temp dir, which matches no package manager.
func TestGetUpgradeCommandFallsBackToInstaller(t *testing.T) {
	got := getUpgradeCommand()
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("running inside a container")
	}
	if exe, err := os.Executable(); err == nil {
		for _, marker := range []string{"homebrew", "cellar", "node_modules", ".npm", "/go/bin", "gopath"} {
			if strings.Contains(strings.ToLower(filepath.ToSlash(exe)), marker) {
				t.Skipf("test binary path %q looks like a package manager install", exe)
			}
		}
	}
	if want := "curl -sSL https://preflight.sh/install.sh | sh"; got != want {
		t.Errorf("getUpgradeCommand() = %q, want %q", got, want)
	}
}
