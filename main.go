package main

import (
	"os"

	"github.com/preflightsh/preflight/cmd"
)

func main() {
	os.Exit(cmd.ExitCode(cmd.Execute(), os.Stderr))
}
