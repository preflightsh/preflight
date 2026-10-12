package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxAPIResponse = 8 << 20

func validateAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid dashboard URL: %w", err)
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("dashboard URL must have a host and no credentials, query, or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		local := strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())
		if u.Scheme != "http" || !local {
			return nil, fmt.Errorf("dashboard URL must use HTTPS (HTTP is allowed only on loopback for development)")
		}
	}
	return u, nil
}

func (c *Client) request(method, endpoint string, body io.Reader) (*http.Request, error) {
	if _, err := validateAPIURL(c.BaseURL); err != nil {
		return nil, err
	}
	ctx := c.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+endpoint, body)
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b) && b.User == nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.HTTP == nil {
		return nil, fmt.Errorf("dashboard HTTP client is missing")
	}
	client := *c.HTTP
	previous := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many dashboard redirects")
		}
		if len(via) == 0 || !sameOrigin(via[0].URL, next.URL) {
			return fmt.Errorf("refusing dashboard redirect outside the authenticated origin")
		}
		if previous != nil {
			return previous(next, via)
		}
		return nil
	}
	return client.Do(req)
}

func (c *Client) post(endpoint string, body io.Reader) (*http.Response, error) {
	req, err := c.request(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func decodeResponse(resp *http.Response, dst any) error {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxAPIResponse {
		return fmt.Errorf("dashboard response exceeds size limit")
	}
	return json.Unmarshal(data, dst)
}
