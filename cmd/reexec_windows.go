//go:build windows

package cmd

import "errors"

// execNewBinary is unsupported on Windows: there is no exec(2) equivalent that
// replaces the running process image in place. The caller falls back to asking
// the user to re-run their command on the new version.
func execNewBinary() error {
	return errors.New("in-place re-exec is not supported on windows")
}
