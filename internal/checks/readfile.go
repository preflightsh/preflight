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
