package cmd

import "testing"

// One repository must map to one dashboard project however it was cloned.
// Before this test, ssh:// and https://user@ forms hashed differently from
// the scp-style and plain https forms.
func TestNormalizeRemote(t *testing.T) {
	want := "github.com/preflightsh/preflight"
	forms := []string{
		"git@github.com:preflightsh/preflight.git",
		"git@github.com:preflightsh/preflight",
		"https://github.com/preflightsh/preflight.git",
		"https://github.com/preflightsh/preflight/",
		"http://github.com/preflightsh/preflight",
		"ssh://git@github.com/preflightsh/preflight.git",
		"https://jon@github.com/preflightsh/preflight.git",
		"https://jon:s3cr3t@github.com/preflightsh/preflight.git",
		"  HTTPS://GitHub.com/PreflightSH/Preflight.git\n",
	}
	for _, f := range forms {
		if got := normalizeRemote(f); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", f, got, want)
		}
	}
	// Different repositories must stay different.
	if normalizeRemote("git@github.com:preflightsh/preflight") == normalizeRemote("git@github.com:preflightsh/other") {
		t.Error("distinct repositories collapsed to the same key")
	}
}

func TestTruncateIsRuneSafe(t *testing.T) {
	if got := truncate("héllo wörld", 6); got != "héllo…" {
		t.Errorf("truncate = %q, want %q", got, "héllo…")
	}
	if got := truncate("short", 28); got != "short" {
		t.Errorf("truncate should leave short strings alone, got %q", got)
	}
}
