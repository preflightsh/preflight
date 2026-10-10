package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "preflight.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := WriteFile(link, []byte("replaced"), 0o644); err == nil {
		t.Fatal("WriteFile through a symlink should fail")
	}
	if got, _ := os.ReadFile(target); string(got) != "original" {
		t.Errorf("symlink target was modified: %q", got)
	}

	// A dangling symlink must not be followed to create its target either.
	dangling := filepath.Join(dir, ".gitignore")
	if err := os.Symlink(filepath.Join(dir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(dangling, []byte("x"), 0o644); err == nil {
		t.Fatal("WriteFile through a dangling symlink should fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); err == nil {
		t.Error("dangling symlink target was created")
	}
}

func TestWriteFileKeepsModeAndReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "two" {
		t.Errorf("content = %q, want two", got)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want existing 0600 kept", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.js")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if data, ok := ReadRegularFile(p, 1024); !ok || string(data) != "hello" {
		t.Errorf("regular file: got %q, %v", data, ok)
	}
	if _, ok := ReadRegularFile(p, 2); ok {
		t.Error("file over the cap should be skipped")
	}
	link := filepath.Join(dir, "link.js")
	if err := os.Symlink(p, link); err == nil {
		if _, ok := ReadRegularFile(link, 1024); ok {
			t.Error("symlink should be skipped")
		}
	}
}
