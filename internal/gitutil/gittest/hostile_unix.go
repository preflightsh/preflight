//go:build unix

// Package gittest builds hostile git fixtures for regression tests.
package gittest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// LazyFetchRepo builds a work tree whose .git/config makes git start a
// transport by itself: it claims to be a partial clone of an ssh remote, the
// tracked .gitignore is skip-worktree with its blob missing, and
// core.sshCommand names a command. Any git command that needs the ignore
// rules (ls-files --exclude-standard with an untracked directory present)
// then lazy-fetches the blob and runs that command. It returns the directory
// and the marker file the command creates.
func LazyFetchRepo(t *testing.T) (dir, marker string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	base := t.TempDir()
	marker = filepath.Join(base, "sshcommand-ran")
	dir = filepath.Join(base, "partial")

	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	write(".gitignore", "node_modules/\n")
	write("package.json", "{\"name\":\"x\",\"version\":\"1.0.0\"}\n")
	git("add", "-A")
	git("commit", "-qm", "init")

	blob := strings.TrimSpace(git("rev-parse", "HEAD:.gitignore"))
	if len(blob) < 3 {
		t.Fatalf("could not resolve the .gitignore blob: %q", blob)
	}
	git("update-index", "--skip-worktree", ".gitignore")
	if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	// Appended to the config file directly: once the repo claims to be a
	// partial clone, git config itself can start a fetch.
	cfg, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.WriteString("[core]\n\trepositoryformatversion = 1\n\tsshCommand = \"touch '" + marker + "'; false\"\n" +
		"[extensions]\n\tpartialClone = origin\n" +
		"[remote \"origin\"]\n\turl = ssh://git@127.0.0.1:1/x.git\n\tpromisor = true\n\tpartialclonefilter = blob:none\n")
	if cerr := cfg.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	// An untracked directory makes git consult the ignore rules.
	write("untracked/file.txt", "x\n")

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("fixture setup itself ran the sshCommand")
	}
	return dir, marker
}

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
