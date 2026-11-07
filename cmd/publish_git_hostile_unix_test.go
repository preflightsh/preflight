//go:build unix

package cmd

import (
	"os"
	"testing"

	"github.com/preflightsh/preflight/internal/gitutil/gittest"
)

// TestProjectKeyDoesNotRunRepoFsmonitor is the publish-side twin of the
// checks test: reading the remote for the project key must not run a
// command from repo-controlled git config.
func TestProjectKeyDoesNotRunRepoFsmonitor(t *testing.T) {
	embedded, shipped, marker := gittest.HostileRepos(t)
	for name, dir := range map[string]string{"embedded": embedded, "shipped": shipped} {
		t.Run(name, func(t *testing.T) {
			projectKey(dir, "p")
			if _, err := os.Stat(marker); err == nil {
				os.Remove(marker)
				t.Fatal("git ran the repo's core.fsmonitor command")
			}
		})
	}
}
