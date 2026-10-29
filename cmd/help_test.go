package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func runRoot(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

// The custom help command was added with AddCommand, so cobra's own help
// was listed beside it.
func TestRootHelpListsHelpOnce(t *testing.T) {
	out := runRoot(t, "--help")
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "help ") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("help listed %d times in:\n%s", count, out)
	}
}

// `preflight help scan` printed the general page and ignored its argument.
func TestHelpWithCommandShowsThatCommand(t *testing.T) {
	out := runRoot(t, "help", "scan")
	if !strings.Contains(out, "--only") || !strings.Contains(out, "scan [path]") {
		t.Errorf("help scan should print scan's help, got:\n%s", out)
	}
}

func TestHelpPageListsEveryCommand(t *testing.T) {
	out := runRoot(t, "help")
	for _, name := range []string{"auth", "history", "completion", "scan", "init"} {
		if !strings.Contains(out, "\n  "+name+" ") {
			t.Errorf("help page omits %s:\n%s", name, out)
		}
	}
}
