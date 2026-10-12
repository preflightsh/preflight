//go:build unix

package fsutil

import (
	"os"
	"syscall"
)

func openFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
