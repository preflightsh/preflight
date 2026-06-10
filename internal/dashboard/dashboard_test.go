package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPollStatusContract pins the CLI side of the device-auth poll protocol:
// the server encodes state in BOTH the status code and the JSON body
// (200 approved, 202 pending, 410 expired), and only genuine failures
// (5xx etc.) may surface as errors. A previous fix treated every non-200 as
// an error, which silently turned "pending" and "expired" into retries.
func TestPollStatusContract(t *testing.T) {
	cases := []struct {
		name       string
		httpStatus int
		body       string
		wantStatus string
		wantToken  string
		wantErr    bool
	}{
		{"approved", http.StatusOK, `{"status":"approved","token":"tok123"}`, "approved", "tok123", false},
		{"pending", http.StatusAccepted, `{"status":"pending"}`, "pending", "", false},
		{"expired", http.StatusGone, `{"status":"expired"}`, "expired", "", false},
		{"server error", http.StatusInternalServerError, `boom`, "", "", true},
		{"bad gateway", http.StatusBadGateway, `<html>nginx</html>`, "", "", true},
		{"garbage body", http.StatusOK, `not json`, "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/cli/auth/poll" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.httpStatus)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
			got, err := c.Poll("device123")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tc.wantStatus || got.Token != tc.wantToken {
				t.Errorf("got status=%q token=%q, want %q/%q", got.Status, got.Token, tc.wantStatus, tc.wantToken)
			}
		})
	}
}
