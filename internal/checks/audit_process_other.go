//go:build !unix && !windows

package checks

import "os/exec"

// CommandContext kills the direct child; WaitDelay bounds inherited pipes on
// platforms without POSIX process groups.
func configureAuditProcess(cmd *exec.Cmd) {}
