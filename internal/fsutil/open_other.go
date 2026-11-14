//go:build !unix

package fsutil

import "os"

const openFlags = os.O_RDONLY

func openFile(path string) (*os.File, error) { return os.Open(path) }
