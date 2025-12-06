package main

import (
	"os"

	"github.com/phillips-jon/preflight/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
