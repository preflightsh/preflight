package gitutil

import (
	"strings"
	"testing"
)

func TestEnvDropsRelocatingVars(t *testing.T) {
	got := env([]string{"PATH=/bin", "GIT_DIR=/x", "git_work_tree=/y", "GIT_TERMINAL_PROMPT=1", "GIT_AUTHOR_NAME=a", "GIT_ALLOW_PROTOCOL=ssh", "GIT_NO_LAZY_FETCH=0"})
	want := []string{"PATH=/bin", "GIT_AUTHOR_NAME=a", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("env = %v, want %v", got, want)
	}
}
