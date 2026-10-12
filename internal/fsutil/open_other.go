//go:build !unix

package fsutil

import "os"

func openFile(path string) (*os.File, error) { return os.Open(path) }
