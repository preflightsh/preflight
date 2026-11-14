// Package gitutil runs git against directories Preflight scans, which may
// belong to someone else.
package gitutil

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// hardening turns off the git settings that run a command named in config.
// A scanned repo controls its own config, so without these, `git -C dir
// ls-files` in a hostile checkout runs the repo author's code:
//
//   - core.fsmonitor names a program git runs whenever it reads the index.
//   - core.hooksPath is pointed at nothing so no repo hook can run.
//   - safe.bareRepository=explicit stops git from treating a directory laid
//     out as a bare repository (HEAD, objects/, refs/, config) as a repo when
//     it finds one. That layout survives git clone, so without this a
//     subdirectory of an ordinary clone can carry config of its own.
//   - protocol.allow=never refuses every transport. Nothing Preflight asks
//     git for needs the network, but a repo that claims to be a partial
//     clone (extensions.partialClone plus a promisor remote) makes git fetch
//     a missing object by itself, and an ssh remote runs core.sshCommand to
//     do it. Listing ignored files is enough to trigger that when the
//     tracked .gitignore blob is absent.
//
// Command-line -c settings take precedence over every config file.
var hardening = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=" + os.DevNull,
	"-c", "safe.bareRepository=explicit",
	"-c", "protocol.allow=never",
}

// fixedEnv is set on every git call, replacing whatever the caller had.
//
//   - GIT_TERMINAL_PROMPT=0 keeps git from waiting on a prompt.
//   - GIT_NO_LAZY_FETCH=1 stops the partial-clone fetch described above
//     before git picks a transport at all (git 2.45 and later; older
//     versions fall back on protocol.allow).
//   - GIT_ALLOW_PROTOCOL overrides protocol.allow when set, so a caller who
//     exports it for their own work would hand the transports back. Empty
//     allows none.
var fixedEnv = []string{
	"GIT_TERMINAL_PROMPT=0",
	"GIT_NO_LAZY_FETCH=1",
	"GIT_ALLOW_PROTOCOL=",
}

// relocatingEnv are the variables that point git at a repository other than
// the one under dir. They are set when Preflight runs from a git hook, and
// would make git report on the wrong tree.
var relocatingEnv = []string{
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_INDEX_FILE",
	"GIT_COMMON_DIR",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_NAMESPACE",
}

// Command returns `git -C dir <args...>` with the settings that run commands
// from config turned off, transports refused, and prompts disabled.
func Command(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := append([]string{"-C", dir}, hardening...)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = env(os.Environ())
	return cmd
}

func env(environ []string) []string {
	out := make([]string, 0, len(environ)+len(fixedEnv))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if relocates(name) || fixed(name) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, fixedEnv...)
}

func fixed(name string) bool {
	for _, kv := range fixedEnv {
		v, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(name, v) {
			return true
		}
	}
	return false
}

func relocates(name string) bool {
	for _, v := range relocatingEnv {
		// Windows environment names are case-insensitive.
		if strings.EqualFold(name, v) {
			return true
		}
	}
	return false
}
