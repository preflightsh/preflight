package output

import "io"

type errorWriter struct {
	io.Writer
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.Writer.Write(p)
	if n < len(p) && err == nil {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}
