// Package fsutil holds tiny filesystem helpers shared across packages.
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// FileExists reports whether rootDir/relativePath exists (file or dir).
func FileExists(rootDir, relativePath string) bool {
	_, err := os.Stat(filepath.Join(rootDir, relativePath))
	return err == nil
}

// WriteFile writes data to path without following a symlink at path. It
// refuses a path that is a symlink or not a regular file, then writes a
// temporary file in the same directory and renames it into place, so a
// crash never leaves a half-written file. A cloned repo can plant
// `preflight.yml -> ~/.bashrc`; os.WriteFile would truncate the target.
//
// An existing file keeps its permission bits; a new one gets perm.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to write %s: it is a symlink", path)
	case err == nil && !info.Mode().IsRegular():
		return fmt.Errorf("refusing to write %s: it is not a regular file", path)
	case err == nil:
		perm = info.Mode().Perm()
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return cleanup(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// ReadRegularFile reads path only if it is a regular file (following no
// symlink) of at most maxBytes, so source walkers cannot be pointed at a
// FIFO, a device, or a huge file by a hostile repo. ok is false when the
// file was skipped or unreadable.
func ReadRegularFile(path string, maxBytes int64) (data []byte, ok bool) {
	data, err := ReadFile(path, maxBytes)
	return data, err == nil
}

// OpenRegularFile refuses symlinks and special files. The platform opener
// prevents a swapped-in FIFO from blocking between inspection and opening.
func OpenRegularFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return f, nil
}

// ReadFile reads an entire regular file within maxBytes. Oversized files are
// errors rather than successful, truncated input.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid read limit")
	}
	f, err := OpenRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s: exceeds %d byte read limit", path, maxBytes)
	}
	return data, nil
}
