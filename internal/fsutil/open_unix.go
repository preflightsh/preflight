//go:build unix

package fsutil

import (
	"os"
	"syscall"
)

// openFlags never block on a FIFO and never follow a symlink in the last
// path element.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW

func openFile(path string) (*os.File, error) {
	return os.OpenFile(path, openFlags, 0)
}
