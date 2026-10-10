//go:build !windows

package checks

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestSourceReadersSkipSpecialFiles guards every project-file reader against a
// hostile repo: a FIFO named like source would block open() forever, and a
// symlink to /dev/zero would read without bound. Both must be skipped while a
// real file next to them is still read.
func TestSourceReadersSkipSpecialFiles(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(src, "evil.js"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(src, "zero.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "fly.toml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ok.js"), []byte("posthog.init('k')"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan []string, 1)
	go func() {
		var seen []string
		walkSourceFiles(root, func(path string, _ []byte) bool {
			seen = append(seen, filepath.Base(path))
			return false
		})
		hasEnvVarReference(root, "MAILGUN_")
		done <- seen
	}()

	select {
	case seen := <-done:
		if len(seen) != 1 || seen[0] != "ok.js" {
			t.Fatalf("visited %v, want only ok.js", seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source walk hung on a FIFO or device file")
	}
}

func TestReadSourceFileCapsSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.js")
	if err := os.WriteFile(p, make([]byte, maxSourceFileSize+100), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := readSourceFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != maxSourceFileSize {
		t.Fatalf("read %d bytes, want cap %d", len(b), maxSourceFileSize)
	}
}
