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
//
// Command-line -c settings take precedence over every config file.
var hardening = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=" + os.DevNull,
	"-c", "safe.bareRepository=explicit",
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
// from config turned off and prompts disabled.
func Command(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := append([]string{"-C", dir}, hardening...)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = env(os.Environ())
	return cmd
}

func env(environ []string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if relocates(name) || name == "GIT_TERMINAL_PROMPT" {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GIT_TERMINAL_PROMPT=0")
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
