package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A path from the scanned project's config must not reach outside it, by
// "..", by an absolute path, or through a symlinked directory.
func TestReadFileInStaysInsideRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.env")
	for path, body := range map[string]string{
		outside:                               "SECRET_KEY=1\n",
		filepath.Join(root, "config", ".env"): "INSIDE=1\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if data, err := ReadFileIn(root, filepath.Join("config", ".env"), 1024); err != nil || string(data) != "INSIDE=1\n" {
		t.Fatalf("file inside the root: %q, %v", data, err)
	}
	for _, rel := range []string{"../outside.env", "config/../../outside.env", outside, ""} {
		data, err := ReadFileIn(root, rel, 1024)
		if err == nil {
			t.Errorf("%q was read: %q", rel, data)
		} else if strings.Contains(err.Error(), base) && rel != outside {
			t.Errorf("%q: error names an absolute path: %v", rel, err)
		}
	}
	if _, err := ReadFileIn(root, "missing.env", 1024); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file should be fs.ErrNotExist, got %v", err)
	}
	if _, err := ReadFileIn(root, filepath.Join("config", ".env"), 4); err == nil {
		t.Error("a file over the limit should be an error")
	}

	if runtime.GOOS == "windows" {
		return // symlinks need a privilege there
	}
	// A symlinked directory leading out of the project, and a symlink as
	// the file itself.
	if err := os.Symlink(base, filepath.Join(root, "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.env")); err != nil {
		t.Fatal(err)
	}
	// A symlinked directory that stays inside the project still works.
	if err := os.Symlink("config", filepath.Join(root, "conf")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"up/outside.env", "link.env"} {
		if data, err := ReadFileIn(root, rel, 1024); err == nil {
			t.Errorf("%q was read through a symlink: %q", rel, data)
		}
	}
	if data, err := ReadFileIn(root, "conf/.env", 1024); err != nil || string(data) != "INSIDE=1\n" {
		t.Errorf("symlinked directory inside the root: %q, %v", data, err)
	}
}
