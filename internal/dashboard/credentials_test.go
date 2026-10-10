package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// os.WriteFile keeps an existing file's mode and MkdirAll leaves an existing
// directory alone, so a credentials file or ~/.preflight that was ever
// loosened stayed readable by other users.
func TestSaveTightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".preflight")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&Credentials{Token: "t"}).Save(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("credentials mode = %v, want 0600", info.Mode().Perm())
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", info.Mode().Perm())
	}
}

// A 4xx from the poll endpoint will not fix itself; it must be marked
// permanent so the login loop stops instead of spinning for ten minutes.
func TestPollClientErrorIsPermanent(t *testing.T) {
	for status, wantPermanent := range map[int]bool{
		http.StatusBadRequest:          true,
		http.StatusNotFound:            true,
		http.StatusTooManyRequests:     false,
		http.StatusInternalServerError: false,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
		_, err := c.Poll("x")
		srv.Close()
		var permanent *PermanentError
		if err == nil || errors.As(err, &permanent) != wantPermanent {
			t.Errorf("status %d: err = %v, permanent = %v, want permanent %v", status, err, errors.As(err, &permanent), wantPermanent)
		}
	}
}
