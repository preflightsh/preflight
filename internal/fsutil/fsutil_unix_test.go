//go:build unix

package fsutil

import (
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO used to hang source walkers forever.
func TestReadRegularFileSkipsFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo.js")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	if _, ok := ReadRegularFile(fifo, 1024); ok {
		t.Error("FIFO should be skipped")
	}
}
