//go:build unix

package config

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestSpecialConfigAndManifestFiles(t *testing.T) {
	d := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(d, "preflight.yml"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil {
		t.Fatal("FIFO config accepted")
	}
	if err := syscall.Mkfifo(filepath.Join(d, "package.json"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = DetectStack(d)
	_ = DetectServices(d)
}
