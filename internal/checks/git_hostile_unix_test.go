//go:build unix

package checks

import (
	"os"
	"testing"

	"github.com/preflightsh/preflight/internal/gitutil/gittest"
)

// TestGitCallsDoNotLazyFetch guards against a shipped .git/config that
// claims to be a partial clone: listing ignored directories made git fetch
// the missing .gitignore blob, which ran the repo's core.sshCommand.
func TestGitCallsDoNotLazyFetch(t *testing.T) {
	dir, marker := gittest.LazyFetchRepo(t)
	gitIgnoredDirs(dir)
	loadGitStatus(dir)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("git ran the repo's core.sshCommand through a lazy fetch")
	}
}

// TestGitCallsDoNotRunRepoFsmonitor guards against a scanned repo running
// code through core.fsmonitor in config it controls: an embedded
// bare-repo-shaped directory that survives git clone, or a shipped
// .git/config.
func TestGitCallsDoNotRunRepoFsmonitor(t *testing.T) {
	embedded, shipped, marker := gittest.HostileRepos(t)
	for name, dir := range map[string]string{"embedded": embedded, "shipped": shipped} {
		t.Run(name, func(t *testing.T) {
			loadGitStatus(dir)
			gitIgnoredDirs(dir)
			if _, err := os.Stat(marker); err == nil {
				os.Remove(marker)
				t.Fatal("git ran the repo's core.fsmonitor command")
			}
		})
	}
}
