//go:build unix

// Package gittest builds hostile git fixtures for regression tests.
package gittest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// HostileRepos builds the two repo shapes that make a plain `git -C dir ...`
// run a command named in repo-controlled config, and returns the directories
// to point git at plus the marker file that command creates.
//
//   - embedded: a clone whose apps/web is laid out as a bare repository
//     (HEAD, objects/, refs/, config) with core.fsmonitor set. Plain git
//     clone keeps it, and git discovers apps/web as its own repository.
//   - shipped: a work tree whose .git/config sets core.fsmonitor, as when a
//     repo arrives as an archive rather than a clone.
func HostileRepos(t *testing.T) (embedded, shipped, marker string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	base := t.TempDir()
	marker = filepath.Join(base, "fsmonitor-ran")
	hook := "touch '" + marker + "'; false"

	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	upstream := filepath.Join(base, "upstream")
	git(base, "init", "-q", "-b", "main", upstream)
	web := filepath.Join(upstream, "apps", "web")
	write(filepath.Join(web, "HEAD"), "ref: refs/heads/main\n")
	write(filepath.Join(web, "config"), "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = .\n\tfsmonitor = \""+hook+"\"\n")
	write(filepath.Join(web, "objects", ".keep"), "")
	write(filepath.Join(web, "refs", ".keep"), "")
	write(filepath.Join(web, "preflight.yml"), "projectName: web\n")
	git(upstream, "add", "-A")
	git(upstream, "commit", "-qm", "init")
	clone := filepath.Join(base, "clone")
	git(base, "clone", "-q", upstream, clone)
	embedded = filepath.Join(clone, "apps", "web")

	shipped = filepath.Join(base, "shipped")
	git(base, "init", "-q", "-b", "main", shipped)
	git(shipped, "config", "core.fsmonitor", hook)
	write(filepath.Join(shipped, "a.txt"), "x\n")
	git(shipped, "remote", "add", "origin", "https://example.com/o/r.git")

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("fixture setup itself ran the fsmonitor command")
	}
	return embedded, shipped, marker
}
