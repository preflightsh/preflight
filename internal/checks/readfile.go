package checks

import (
	"os"

	"github.com/preflightsh/preflight/internal/fsutil"
)

// maxSourceFileSize caps how much of any one project file a check reads.
// Detection patterns live near the top of real source files; anything past
// this is a bundle, a dump or a hostile file meant to exhaust memory.
const maxSourceFileSize = 2 << 20 // 2 MiB

// openRegular opens path only if it resolves to a regular file. A cloned repo
// can contain FIFOs, device nodes or symlinks to them (src/app.js -> /dev/zero),
// and a plain os.Open on a FIFO blocks forever waiting for a writer. Stat first
// so those are refused before open, then re-check the opened descriptor in case
// the path was swapped in between.
func openRegular(path string) (*os.File, error) {
	return fsutil.OpenRegularFile(path)
}

// readSourceFile is the os.ReadFile every check uses for project files: it
// refuses anything that is not a regular file and reads at most
// maxSourceFileSize bytes, rejecting larger files as incomplete input.
func readSourceFile(path string) ([]byte, error) {
	return fsutil.ReadFile(path, maxSourceFileSize)
}

// openProjectFile opens rel, a path taken from preflight.yml, only if it is
// a regular file inside root. The config belongs to the scanned repo, so
// rel can be "../outside" or pass through a symlinked directory; joining it
// onto root and opening the result read files outside the project.
func openProjectFile(root, rel string) (*os.File, error) {
	return fsutil.OpenRegularFileIn(root, rel)
}

// readProjectFile is readSourceFile for a path taken from preflight.yml
// (see openProjectFile).
func readProjectFile(root, rel string) ([]byte, error) {
	return fsutil.ReadFileIn(root, rel, maxSourceFileSize)
}
