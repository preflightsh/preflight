package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestStockErrorPagesAreNotCustom: nginx's default 404 (and other server and
// platform defaults) is HTML, so it passed as "404 page found (served
// dynamically)".
func TestStockErrorPagesAreNotCustom(t *testing.T) {
	bodies := map[string]string{
		"nginx":  "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>",
		"apache": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>Apache/2.4.58 Server at x Port 80</address></body></html>",
		"bare":   "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, body)
			}))
			defer srv.Close()
			ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{Stack: "static", URLs: config.URLConfig{Production: srv.URL}}}
			if servesHTML404(ctx, srv.URL) {
				t.Fatal("stock 404 counted as a custom page")
			}
		})
	}
}

func TestCustomErrorPageCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<!doctype html><html><body><nav>Acme</nav><h1>We lost that page</h1><a href=\"/\">Home</a></body></html>")
	}))
	defer srv.Close()
	ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{URLs: config.URLConfig{Production: srv.URL}}}
	if !servesHTML404(ctx, srv.URL) {
		t.Fatal("custom 404 not counted")
	}
}
