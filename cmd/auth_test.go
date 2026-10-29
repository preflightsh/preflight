package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/dashboard"
)

// A network error while polling printed nothing and kept polling for the
// full ten minutes. Persistent errors are shown and end the wait early.
func TestPollLoginFailsOnPersistentErrors(t *testing.T) {
	calls := 0
	poll := func() (*dashboard.PollStatus, error) {
		calls++
		return nil, errors.New("dial tcp: connection refused")
	}
	var out bytes.Buffer
	start := time.Now()
	_, err := pollLogin(context.Background(), poll, time.Millisecond, time.Now().Add(time.Minute), &out)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("want an error carrying the network failure, got %v", err)
	}
	if time.Since(start) > 5*time.Second || calls != maxPollFailures {
		t.Errorf("gave up after %d calls in %s, want %d calls", calls, time.Since(start), maxPollFailures)
	}
	if !strings.Contains(out.String(), "connection refused") {
		t.Errorf("the error should be shown while waiting, got %q", out.String())
	}
}

// A blip is shown but polling carries on, and a success resets the count.
func TestPollLoginRecoversFromTransientErrors(t *testing.T) {
	calls := 0
	poll := func() (*dashboard.PollStatus, error) {
		calls++
		switch {
		case calls%3 != 0 && calls < 3*maxPollFailures:
			return nil, errors.New("timeout")
		case calls < 3*maxPollFailures:
			return &dashboard.PollStatus{Status: "pending"}, nil
		}
		return &dashboard.PollStatus{Status: "approved", Token: "tok"}, nil
	}
	var out bytes.Buffer
	token, err := pollLogin(context.Background(), poll, time.Millisecond, time.Now().Add(time.Minute), &out)
	if err != nil || token != "tok" {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

// `auth status` printed "Logged in as " with nothing after it when the
// post-login account lookup had failed.
func TestAuthStatusWithoutEmail(t *testing.T) {
	got := authStatusText(&dashboard.Credentials{Token: "t", APIURL: "https://app.example"})
	if strings.Contains(got, "Logged in as \n") || !strings.Contains(got, "Logged in") {
		t.Errorf("got %q", got)
	}
	got = authStatusText(&dashboard.Credentials{Token: "t", Email: "a@b.c", APIURL: "https://app.example"})
	if !strings.Contains(got, "Logged in as a@b.c") {
		t.Errorf("got %q", got)
	}
}
