// Package dashboard is the client for the Preflight dashboard service
// (app.preflight.sh): credential storage and the HTTP API used by `preflight
// auth` and `preflight scan --publish`.
//
// The base URL is configurable via PREFLIGHT_API_URL so the whole flow can be
// exercised against a local server (e.g. http://localhost:8080) without a
// release.
package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ErrQuotaExceeded is returned by PublishRun when the account is out of free
// runs for the month and has no paid plan or own API key.
var ErrQuotaExceeded = errors.New("free run quota exceeded")

// DefaultAPIURL is the production dashboard origin.
const DefaultAPIURL = "https://app.preflight.sh"

// APIURL returns the dashboard base URL, honoring PREFLIGHT_API_URL.
func APIURL() string {
	if v := os.Getenv("PREFLIGHT_API_URL"); v != "" {
		return v
	}
	return DefaultAPIURL
}

// Credentials is the persisted CLI auth state.
type Credentials struct {
	Token  string `json:"token"`
	Email  string `json:"email"`
	APIURL string `json:"api_url"`
}

// credentialsPath returns ~/.preflight/credentials.json.
func credentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".preflight", "credentials.json"), nil
}

// LoadCredentials reads stored credentials, returning (nil, nil) when none exist.
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return &c, nil
}

// Save writes credentials to ~/.preflight/credentials.json with 0600 perms.
func (c *Credentials) Save() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ClearCredentials removes any stored credentials (logout).
func ClearCredentials() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Client talks to the dashboard API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client pointed at APIURL().
func NewClient() *Client {
	return &Client{BaseURL: APIURL(), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// StartResponse is returned by StartAuth.
type StartResponse struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	VerifyURL  string `json:"verify_url"`
	Interval   int    `json:"interval"`
}

// StartAuth begins the device-authorization flow.
func (c *Client) StartAuth() (*StartResponse, error) {
	resp, err := c.HTTP.Post(c.BaseURL+"/api/cli/auth/start", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth start failed: %s", resp.Status)
	}
	var out StartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PollStatus is the result of one Poll call.
type PollStatus struct {
	Status string // "pending", "approved", "expired"
	Token  string
}

// Poll checks once whether the device code has been approved.
func (c *Client) Poll(deviceCode string) (*PollStatus, error) {
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	resp, err := c.HTTP.Post(c.BaseURL+"/api/cli/auth/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// The poll endpoint encodes state in the status code AND body:
	// 200 approved, 202 pending, 410 expired. Anything else (5xx, proxy
	// errors) is a real failure, surfaced as an error so callers don't
	// mistake an outage for a pending approval.
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusGone:
		var out struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("auth poll: parse response: %w", err)
		}
		return &PollStatus{Status: out.Status, Token: out.Token}, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("auth poll failed: %s: %s", resp.Status, string(b))
	}
}

// PublishRequest is the body posted to /api/runs.
type PublishRequest struct {
	ProjectKey    string        `json:"project_key"`
	ProjectName   string        `json:"project_name"`
	Stack         string        `json:"stack"`
	PreflightYAML string        `json:"preflight_yaml"`
	Result        PublishResult `json:"result"`
}

// PublishResult mirrors the CLI's JSONOutput summary + checks.
type PublishResult struct {
	Summary PublishSummary `json:"summary"`
	Checks  []PublishCheck `json:"checks"`
}

// PublishSummary is the ok/warn/fail tally.
type PublishSummary struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// PublishCheck is a single redacted check result.
type PublishCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Passed   bool   `json:"passed"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// PublishResponse is returned on a successful publish.
type PublishResponse struct {
	RunID     string `json:"run_id"`
	ProjectID string `json:"project_id"`
	URL       string `json:"url"`
}

// PublishRun posts a scan result to the dashboard. Returns ErrQuotaExceeded
// (wrapped with the server's message) when the account is out of free runs.
func (c *Client) PublishRun(token string, req *PublishRequest) (*PublishResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, _ := http.NewRequest(http.MethodPost, c.BaseURL+"/api/runs", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		var out PublishResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, err
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("not authenticated; run 'preflight auth login'")
	case http.StatusForbidden:
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "quota_exceeded" {
			return nil, fmt.Errorf("%w: %s", ErrQuotaExceeded, e.Message)
		}
		return nil, fmt.Errorf("forbidden: %s", e.Message)
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("publish failed: %s: %s", resp.Status, string(b))
	}
}

// RunSummary is one row of scan history from GET /api/runs.
type RunSummary struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name"`
	ProjectKey  string `json:"project_key"`
	OK          int    `json:"ok"`
	Warn        int    `json:"warn"`
	Fail        int    `json:"fail"`
	CreatedAt   int64  `json:"created_at"`
	URL         string `json:"url"`
}

// RunDetail is a single run with its check results from GET /api/runs/{id}.
type RunDetail struct {
	ID          string         `json:"id"`
	ProjectName string         `json:"project_name"`
	Stack       string         `json:"stack"`
	OK          int            `json:"ok"`
	Warn        int            `json:"warn"`
	Fail        int            `json:"fail"`
	CreatedAt   int64          `json:"created_at"`
	Checks      []PublishCheck `json:"checks"`
}

// ListRuns fetches recent runs for the authenticated account. projectKey ""
// lists across all projects; limit <= 0 uses the server default.
func (c *Client) ListRuns(token, projectKey string, limit int) ([]RunSummary, error) {
	u, err := url.Parse(c.BaseURL + "/api/runs")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if projectKey != "" {
		q.Set("project_key", projectKey)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("not authenticated; run 'preflight auth login'")
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("history failed: %s: %s", resp.Status, string(b))
	}
	var out struct {
		Runs []RunSummary `json:"runs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Runs, nil
}

// GetRun fetches a single run with its check results.
func (c *Client) GetRun(token, runID string) (*RunDetail, error) {
	req, _ := http.NewRequest(http.MethodGet, c.BaseURL+"/api/runs/"+url.PathEscape(runID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var out RunDetail
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, err
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("not authenticated; run 'preflight auth login'")
	case http.StatusNotFound:
		return nil, fmt.Errorf("run %q not found", runID)
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("get run failed: %s: %s", resp.Status, string(b))
	}
}

// Whoami returns the email for a token, or an error if it is invalid.
func (c *Client) Whoami(token string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, c.BaseURL+"/api/cli/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("token is not valid")
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("whoami failed: %s: %s", resp.Status, string(b))
	}
	var out struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Email, nil
}
