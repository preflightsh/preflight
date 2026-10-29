package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretsOversizedFiles: files over the size cap are skipped, as before
// a2745c9 (which raised the cap to 32MB and made anything larger fail the
// whole check). Only a skipped file git tracks that looks like source or
// config makes the scan inconclusive; data dumps and untracked files do not.
func TestSecretsOversizedFiles(t *testing.T) {
	big := func(t *testing.T, root, name string) {
		t.Helper()
		f, err := os.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("TOKEN=" + fakeGHPATa + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(3 << 20); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	t.Run("untracked", func(t *testing.T) {
		root := t.TempDir()
		big(t, root, "dump.js")
		big(t, root, "huge.js")
		if err := os.Truncate(filepath.Join(root, "huge.js"), 40<<20); err != nil {
			t.Fatal(err)
		}
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if !r.Passed || r.Inconclusive {
			t.Fatalf("result=%+v", r)
		}
	})
	t.Run("tracked data dump", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		big(t, root, "fixtures.json")
		big(t, root, "app.min.js")
		gitCommit(t, root, "fixtures.json", "app.min.js")
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if !r.Passed || r.Inconclusive {
			t.Fatalf("result=%+v", r)
		}
	})
	t.Run("tracked source", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		big(t, root, "settings.py")
		gitCommit(t, root, "settings.py")
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || !r.Inconclusive || !strings.Contains(r.Message, "settings.py") {
			t.Fatalf("result=%+v", r)
		}
	})
	t.Run("under the cap is scanned", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "large.js", strings.Repeat(" ", 3<<19)+"\nTOKEN="+fakeGHPATa)
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || r.Severity != SeverityError {
			t.Fatalf("result=%+v", r)
		}
	})
}
