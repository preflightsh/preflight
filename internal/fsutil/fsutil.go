// Package fsutil holds tiny filesystem helpers shared across packages.
package fsutil

import (
	"os"
	"path/filepath"
)

// FileExists reports whether rootDir/relativePath exists (file or dir).
func FileExists(rootDir, relativePath string) bool {
	_, err := os.Stat(filepath.Join(rootDir, relativePath))
	return err == nil
}
