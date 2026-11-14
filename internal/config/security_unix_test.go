//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSpecialConfigAndManifestFiles(t *testing.T) {
	d := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(d, "preflight.yml"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil {
		t.Fatal("FIFO config accepted")
	}
	if err := syscall.Mkfifo(filepath.Join(d, "package.json"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = DetectStack(d)
	_ = DetectServices(d)
}

// A symlinked config is refused, and the message says why and what to do.
func TestSymlinkedConfigSaysSo(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.yml")
	if err := os.WriteFile(target, []byte("projectName: x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d, "preflight.yml")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(d)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err=%v, want a message naming the symlink", err)
	}
}

// Service IDs are map keys from the file; one holding terminal escapes
// must not reach the note verbatim.
func TestUndeclaredServiceNoteQuotesIDs(t *testing.T) {
	cfg, err := Load(writeConfig(t, "services:\n  \"\\e]0;x\\abogus\":\n    declared: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notes) != 1 || strings.ContainsAny(cfg.Notes[0], "\x1b\x07") {
		t.Fatalf("notes=%q", cfg.Notes)
	}
}
