//go:build windows

package checks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func configureAuditProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		// Use the system binary, never a taskkill planted in the scanned repo.
		root := os.Getenv("SYSTEMROOT")
		if root != "" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			kill := exec.CommandContext(ctx, filepath.Join(root, "System32", "taskkill.exe"), "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
			kill.WaitDelay = time.Second
			if err := kill.Run(); err == nil {
				return nil
			}
		}
		return cmd.Process.Kill()
	}
}
