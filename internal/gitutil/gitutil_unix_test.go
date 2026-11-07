//go:build unix

package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/gitutil/gittest"
)

func output(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	out, err := Command(context.Background(), dir, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func TestCommandDoesNotRunRepoFsmonitor(t *testing.T) {
	embedded, shipped, marker := gittest.HostileRepos(t)
	for name, dir := range map[string]string{"embedded": embedded, "shipped": shipped} {
		t.Run(name, func(t *testing.T) {
			_, _ = output(t, dir, "ls-files", "-z")
			_, _ = output(t, dir, "status", "--porcelain")
			if _, err := os.Stat(marker); err == nil {
				os.Remove(marker)
				t.Fatal("git ran the repo's core.fsmonitor command")
			}
		})
	}
	// The shipped work tree is still a normal repo and must keep working.
	if out, err := output(t, shipped, "config", "--get", "remote.origin.url"); err != nil || out != "https://example.com/o/r.git" {
		t.Fatalf("remote lookup in shipped repo = %q, %v", out, err)
	}
}

// Ordinary layouts Preflight scans must still be recognized: a plain repo,
// a linked worktree, and a submodule (the last two use a .git file), also
// when Preflight runs from a git hook with GIT_DIR pointing elsewhere.
func TestCommandKeepsOrdinaryRepos(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	base := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "protocol.file.allow=always"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commitFile := func(repo, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		run(repo, "add", name)
		run(repo, "commit", "-qm", name)
	}

	main := filepath.Join(base, "main")
	run(base, "init", "-q", "-b", "main", main)
	commitFile(main, "a.txt")
	lib := filepath.Join(base, "lib")
	run(base, "init", "-q", "-b", "main", lib)
	commitFile(lib, "lib.txt")
	run(main, "submodule", "add", "-q", lib, "vendor/lib")
	run(main, "commit", "-qm", "sub")
	wt := filepath.Join(base, "wt")
	run(main, "worktree", "add", "-q", wt)

	t.Setenv("GIT_DIR", filepath.Join(base, "nowhere"))
	for dir, want := range map[string]string{main: "a.txt", wt: "a.txt", filepath.Join(main, "vendor", "lib"): "lib.txt"} {
		out, err := output(t, dir, "ls-files")
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("ls-files in %s = %q, %v; want it to list %s", dir, out, err, want)
		}
	}
}
