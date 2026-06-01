//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// execNewBinary replaces the current process image with the freshly installed
// binary, preserving the user's original arguments. On success it does not
// return (the new program takes over); it only returns on error so the caller
// can fall back to asking the user to re-run.
func execNewBinary() error {
	bin, err := resolveNewBinary()
	if err != nil {
		return err
	}
	env := append(os.Environ(), noUpdateCheckEnv+"=1")
	return syscall.Exec(bin, os.Args, env)
}
