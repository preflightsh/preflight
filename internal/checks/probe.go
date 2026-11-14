package checks

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// This file holds what the probe-based checks share: telling a host that
// could not answer from one that answered "no", following a redirect that
// stays on the site, and recognising a host that answers every path.

// ProbeCache shares per-host probe results between the checks of one scan,
// so the legal, health, and error-page checks do not each send their own
// request for a path that cannot exist. A nil cache is valid: every lookup
// then makes its own requests.
type ProbeCache struct {
	mu     sync.Mutex
	shells map[string]*shellEntry
}

type shellEntry struct {
	once sync.Once
	info catchAll
}

// NewProbeCache returns an empty cache for one scan.
func NewProbeCache() *ProbeCache {
	return &ProbeCache{shells: map[string]*shellEntry{}}
}

// catchAll describes what a host serves for paths that cannot exist.
type catchAll struct {
	// answers is true when the host returns 2xx for such a path (an SPA
	// rewrite or a catch-all route) instead of a 404.
	answers bool
	// digest is the body digest of that answer.
	digest []byte
	// unstable is true when two such paths got different bodies, so the
	// digest cannot be used to recognise the shell.
	unstable bool
	// html is true when that answer is an HTML page, which is what a
	// catch-all route almost always serves.
	html bool
}

// serves reports whether a 2xx body with the given digest could be the
// host's catch-all answer rather than a real page. On a host whose shell
// differs between requests every 2xx is suspect.
func (s catchAll) serves(digest []byte) bool {
	return s.answers && (s.unstable || bytes.Equal(digest, s.digest))
}

// servesFile is serves for a body already known not to be HTML (a text
// file such as llms.txt). A shell that differs between requests makes
// every 2xx suspect only when the shell could be that body: an HTML shell
// cannot be, so a real text file on such a host still counts as served.
func (s catchAll) servesFile(digest []byte) bool {
	if !s.answers {
		return false
	}
	if bytes.Equal(digest, s.digest) {
		return true
	}
	return s.unstable && !s.html
}

// Paths no real site serves. Two of them, because a shell that stamps a
// counter or a render time into every response only shows itself when two
// answers are compared.
const (
	catchAllProbePath  = "/preflight-404-probe-please-do-not-exist"
	catchAllProbePath2 = "/preflight-404-probe-also-does-not-exist"
)

// catchAllFor returns what baseURL serves for paths that cannot exist,
// asking the host once per scan.
func (c Context) catchAllFor(baseURL string) catchAll {
	base := strings.TrimSuffix(baseURL, "/")
	if c.Client == nil || base == "" {
		return catchAll{}
	}
	if c.Probes == nil {
		return probeCatchAll(c, base)
	}
	c.Probes.mu.Lock()
	entry := c.Probes.shells[base]
	if entry == nil {
		entry = &shellEntry{}
		c.Probes.shells[base] = entry
	}
	c.Probes.mu.Unlock()
	entry.once.Do(func() { entry.info = probeCatchAll(c, base) })
	return entry.info
}

func probeCatchAll(ctx Context, base string) catchAll {
	paths := []string{catchAllProbePath, catchAllProbePath2}
	answers := make([]probeAnswer, len(paths))
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			answers[i] = fetchOnSite(ctx, base+p)
		}(i, p)
	}
	wg.Wait()

	first, second := answers[0], answers[1]
	if !first.ok() {
		return catchAll{}
	}
	info := catchAll{
		answers: true,
		digest:  first.digest(catchAllProbePath),
		html:    looksLikeHTML(first.header.Get("Content-Type"), first.body),
	}
	if second.ok() && !bytes.Equal(info.digest, second.digest(catchAllProbePath2)) {
		info.unstable = true
	}
	return info
}

// probeAnswer is the final response to a request that followed redirects
// only while they stayed on the site.
type probeAnswer struct {
	// err is set when nothing answered.
	err error
	// status is the status of the final response.
	status int
	header http.Header
	// body is the first MiB of a 2xx response body, nil otherwise.
	body []byte
	// url is the URL that produced the final response.
	url string
	// redirected is true when at least one redirect was followed.
	redirected bool
	// offSite is true when the host redirected to another site; status is
	// then the redirect's own status.
	offSite bool
	// authWall is true when the host redirected to a login page.
	authWall bool
}

// ok reports a usable 2xx answer.
func (a probeAnswer) ok() bool {
	return a.err == nil && a.status >= 200 && a.status < 300 && !a.offSite && !a.authWall
}

// conclusive reports whether the answer says anything about the path. A
// host that could not be reached, refused the scanner, failed with a 5xx,
// or bounced the request to a login page or another site has not answered
// the question.
func (a probeAnswer) conclusive() bool {
	if a.err != nil || a.offSite || a.authWall {
		return false
	}
	return !blockedStatus(a.status) && a.status < 500
}

func (a probeAnswer) digest(reqPath string) []byte {
	return pageDigest(bytes.NewReader(a.body), reqPath)
}

func (a probeAnswer) isHTML() bool {
	return looksLikeHTML(a.header.Get("Content-Type"), a.body)
}

// maxSiteHops is how many same-site redirects fetchOnSite follows: enough
// for http to https to www to a trailing slash.
const maxSiteHops = 4

// fetchOnSite requests rawURL and follows redirects by hand, stopping at
// the first one that leaves the site or lands on a login page. Judging the
// final response, rather than the redirect, is what lets a check tell an
// apex-to-www or trailing-slash redirect from a page that exists.
//
// Redirects are followed with a copy of the scan client, so every hop is
// still dialed through the same private-address guard.
func fetchOnSite(ctx Context, rawURL string) probeAnswer {
	if ctx.Client == nil {
		return probeAnswer{err: fmt.Errorf("no HTTP client")}
	}
	noFollow := *ctx.Client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	current := rawURL
	answer := probeAnswer{}
	for hop := 0; ; hop++ {
		resp, requested, err := tryURL(ctx.reqContext(), &noFollow, current)
		if err != nil {
			return probeAnswer{err: err, url: current}
		}
		answer.status, answer.header, answer.url = resp.StatusCode, resp.Header, requested
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || hop >= maxSiteHops {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				answer.body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			}
			resp.Body.Close()
			return answer
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if isAuthRedirect(location) {
			answer.authWall = true
			return answer
		}
		next, ok := resolveOnSite(requested, location)
		if !ok {
			answer.offSite = true
			return answer
		}
		answer.redirected = true
		current = next
	}
}

// resolveOnSite resolves a redirect Location against the URL that sent it
// and reports whether the target stays on the same site.
func resolveOnSite(from, location string) (string, bool) {
	if strings.TrimSpace(location) == "" {
		return "", false
	}
	base, err := url.Parse(from)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", false
	}
	target := base.ResolveReference(ref)
	if target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return "", false
	}
	if !sameSite(base.Hostname(), target.Hostname()) {
		return "", false
	}
	return target.String(), true
}

// sameSite reports whether two hosts belong to the same site: the same
// host, or the same registrable domain (example.com and www.example.com).
// Hosts under a platform's shared suffix (a.vercel.app and b.vercel.app)
// are different sites, which the public suffix list already encodes.
func sameSite(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if net.ParseIP(a) != nil || net.ParseIP(b) != nil {
		return false
	}
	apexA, errA := publicsuffix.EffectiveTLDPlusOne(a)
	apexB, errB := publicsuffix.EffectiveTLDPlusOne(b)
	return errA == nil && errB == nil && apexA == apexB
}

// platformHost reports whether host sits directly under a suffix a hosting
// platform hands out (myapp.vercel.app, user.github.io). Such a name is the
// whole site: it has no apex, no www counterpart, and no mail of its own.
func platformHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix, icann := publicsuffix.PublicSuffix(host)
	// An unlisted TLD also comes back as not ICANN-managed, with the bare
	// last label as its suffix. A platform suffix always has a dot.
	return !icann && strings.Contains(suffix, ".") && host != suffix
}

// looksLikeHTML reports whether a response is an HTML page: by its content
// type, or by its first bytes once a byte order mark and leading comments
// are out of the way. A page served for a path that should be a text or
// XML file is a soft 404, a login wall, or an SPA shell.
func looksLikeHTML(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	head := body
	if len(head) > 2048 {
		head = head[:2048]
	}
	lower := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(string(head), utf8BOM)))
	lower = strings.TrimSpace(reHTMLComment.ReplaceAllString(lower, ""))
	for _, prefix := range []string{"<!doctype html", "<html", "<head", "<body"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// envName labels a configured base URL the way the per-environment checks
// do.
func (c Context) envName(baseURL string) string {
	base := strings.TrimSuffix(baseURL, "/")
	if c.Config != nil {
		if base == strings.TrimSuffix(c.Config.URLs.Production, "/") && base != "" {
			return "prod"
		}
		if base == strings.TrimSuffix(c.Config.URLs.Staging, "/") && base != "" {
			return "staging"
		}
	}
	return base
}

// urlConfigured reports whether the scan has a deployed site to ask.
func (c Context) urlConfigured() bool {
	return c.Config != nil && (c.Config.URLs.Production != "" || c.Config.URLs.Staging != "")
}

// siteUnverified explains why no configured environment could be measured,
// from the scan's homepage requests: "prod: blocked (HTTP 403)", "staging:
// unreachable". It returns "" when an environment answered normally, when
// no URL is configured, or when the scan made no homepage request to go on.
func (c Context) siteUnverified() string {
	if c.Config == nil {
		return ""
	}
	var reasons []string
	for _, env := range []struct {
		name  string
		url   string
		fetch PageFetch
	}{
		{"prod", c.Config.URLs.Production, c.PageFetchProduction},
		{"staging", c.Config.URLs.Staging, c.PageFetchStaging},
	} {
		if env.url == "" {
			continue
		}
		if !env.fetch.Attempted() {
			return ""
		}
		if env.fetch.Status != 0 && !blockedStatus(env.fetch.Status) && env.fetch.Status < 500 {
			return ""
		}
		reasons = append(reasons, env.name+": "+fetchFailure(env.fetch.Status))
	}
	return strings.Join(reasons, "; ")
}

// inconclusiveResult is the result for a check that has a deployed site to
// ask and got no answer it could use. It is a warning, never a "missing":
// a WAF answering 403 or a host that is down says nothing about the site.
func inconclusiveResult(c Check, subject, reason string) CheckResult {
	return CheckResult{
		ID:           c.ID(),
		Title:        c.Title(),
		Severity:     SeverityWarn,
		Passed:       false,
		Inconclusive: true,
		Message:      "Could not verify " + subject + ": " + reason,
		Suggestions: []string{
			"Run the scan again once the site answers, or from a network the site does not block",
		},
	}
}

// prefetched returns the scan's homepage request for baseURL when the scan
// made one and a response arrived, so a check that only needs the homepage
// status does not ask for it again.
func (c Context) prefetched(baseURL string) (PageFetch, bool) {
	base := strings.TrimSuffix(baseURL, "/")
	if c.Config == nil || base == "" {
		return PageFetch{}, false
	}
	for _, env := range []struct {
		url   string
		fetch PageFetch
	}{
		{c.Config.URLs.Staging, c.PageFetchStaging},
		{c.Config.URLs.Production, c.PageFetchProduction},
	} {
		if strings.TrimSuffix(env.url, "/") == base && env.fetch.Attempted() && env.fetch.Status != 0 {
			return env.fetch, true
		}
	}
	return PageFetch{}, false
}

// utf8BOM is the byte order mark some editors and servers put in front of
// a text file.
const utf8BOM = "\xef\xbb\xbf"
