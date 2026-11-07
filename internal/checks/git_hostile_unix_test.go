//go:build unix

package checks

import (
	"os"
	"testing"

	"github.com/preflightsh/preflight/internal/gitutil/gittest"
)

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
