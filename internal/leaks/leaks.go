// Package leaks asks a site for a few files that should never be served.
//
// A Git repository left in the web root hands over the site's source and its
// history; an environment file hands over its passwords and keys; a status
// page hands over who is visiting and from where. Each is found by whoever
// asks for it by name, and asking is all it takes. This asks first, for the
// owner.
//
// # What it does, and nothing else
//
// A fixed list of paths, each one GET over HTTPS on port 443 to the host the
// web check was given, no redirect followed, at most 4 KB read. A file counts
// as served only if what came back is what that file looks like — a Git HEAD
// that names a ref, an environment file with variable assignments, the magic
// bytes of a .DS_Store — because many sites answer every path with a page of
// their own, and a scanner that took a 200 for a leak would be wrong on most
// of the web.
//
// What came back is never kept. The answer is the path and what it is; the
// bytes are read into a buffer, matched, and dropped, because the whole point
// of the file is that it holds secrets, and a report is something people paste
// into tickets.
//
// It runs only where a scan may reach the host: a proven domain, the command
// line, or the demonstration's own.
package leaks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	maxRead        = 4 << 10
	defaultTimeout = 10 * time.Second
)

// UserAgent identifies this client, as everything else here does.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// Kind is what an exposed file gives away, which decides how it is graded.
type Kind string

const (
	// Source is a version-control repository: the code and its history.
	Source Kind = "source"
	// Secrets is a file that holds passwords or keys.
	Secrets Kind = "secrets"
	// Diagnostics is a page that describes the server and its traffic.
	Diagnostics Kind = "diagnostics"
	// Listing is a file that lists what else is on the server.
	Listing Kind = "listing"
)

// File is one path on the list, what it is, and how it is recognised.
type File struct {
	Path string `json:"path"`
	What string `json:"what"`
	Kind Kind   `json:"kind"`

	matches func([]byte) bool
}

var (
	gitHead   = regexp.MustCompile(`^(ref: refs/[^\s]+|[0-9a-f]{40}|[0-9a-f]{64})\s*$`)
	envLine   = regexp.MustCompile(`(?m)^\s*(export\s+)?[A-Z][A-Z0-9_]*\s*=`)
	htpasswd  = regexp.MustCompile(`^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$5\$|\$6\$|[./0-9A-Za-z]{13}$)`)
	htmlStart = regexp.MustCompile(`(?i)^\s*(<!doctype|<html|<head|<body|<\?xml)`)
)

// Files is the list. Fixed, and the whole of what is asked.
var Files = []File{
	{Path: "/.git/HEAD", What: "a Git repository", Kind: Source, matches: func(b []byte) bool {
		return gitHead.Match(bytes.TrimSpace(b))
	}},
	{Path: "/.git/config", What: "a Git repository's settings", Kind: Source, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte("[core]")) && bytes.Contains(b, []byte("repositoryformatversion"))
	}},
	{Path: "/.svn/wc.db", What: "a Subversion working copy", Kind: Source, matches: func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("SQLite format 3\x00"))
	}},
	{Path: "/.env", What: "an environment file of settings and secrets", Kind: Secrets, matches: func(b []byte) bool {
		return !htmlStart.Match(b) && len(envLine.FindAll(b, 3)) >= 2
	}},
	{Path: "/.aws/credentials", What: "cloud access keys", Kind: Secrets, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte("aws_access_key_id"))
	}},
	{Path: "/wp-config.php.bak", What: "a copy of WordPress's settings with its database password", Kind: Secrets, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte("DB_PASSWORD")) && bytes.Contains(b, []byte("define("))
	}},
	{Path: "/.htpasswd", What: "a password file", Kind: Secrets, matches: func(b []byte) bool {
		lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
		if len(lines) == 0 || len(bytes.TrimSpace(lines[0])) == 0 {
			return false
		}
		for _, l := range lines {
			if l = bytes.TrimSpace(l); len(l) > 0 && !htpasswd.Match(l) {
				return false
			}
		}
		return true
	}},
	{Path: "/server-status", What: "Apache's status page of current requests", Kind: Diagnostics, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte("Apache Server Status for"))
	}},
	{Path: "/phpinfo.php", What: "PHP's configuration page", Kind: Diagnostics, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte("phpinfo()")) && bytes.Contains(b, []byte("PHP Version"))
	}},
	{Path: "/actuator/env", What: "a Spring Boot application's settings", Kind: Secrets, matches: func(b []byte) bool {
		return bytes.Contains(b, []byte(`"propertySources"`))
	}},
	{Path: "/.DS_Store", What: "a macOS folder index naming the files beside it", Kind: Listing, matches: func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("\x00\x00\x00\x01Bud1"))
	}},
}

// Exposed is one file that was served.
type Exposed struct {
	Path string `json:"path"`
	What string `json:"what"`
	Kind Kind   `json:"kind"`
}

// Result is what was found.
type Result struct {
	Asked   bool      `json:"asked"`
	Paths   int       `json:"paths"`
	Exposed []Exposed `json:"exposed,omitempty"`

	// Unanswered is how many paths got no answer at all, so a clean result
	// says how much of the list it covers (R4).
	Unanswered int `json:"unanswered,omitempty"`

	Reason string `json:"reason,omitempty"`
}

// Prober asks.
type Prober struct {
	// Dial opens connections. Nil selects safedial, port 443 only.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots judges the site's certificate. Nil means the system store.
	Roots *x509.CertPool

	Timeout time.Duration
}

// Probe asks the host for each file on the list.
func (p *Prober) Probe(ctx context.Context, host string) Result {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := p.client()
	out := Result{Asked: true, Paths: len(Files)}
	found := make([]bool, len(Files))
	var answered, untrusted bool
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, f := range Files {
		wg.Add(1)
		go func() {
			defer wg.Done()
			served, err := fetch(ctx, client, "https://"+net.JoinHostPort(host, "443")+f.Path, f.matches)
			mu.Lock()
			defer mu.Unlock()
			var unknown *tls.CertificateVerificationError
			switch {
			case errors.As(err, &unknown):
				untrusted = true
				out.Unanswered++
			case err != nil:
				out.Unanswered++
			default:
				answered = true
				found[i] = served
			}
		}()
	}
	wg.Wait()

	switch {
	case untrusted && !answered:
		return Result{Asked: true, Paths: len(Files), Reason: "the site's certificate does not verify, so nothing was read from it"}
	case !answered:
		return Result{Asked: true, Paths: len(Files), Reason: "the site could not be reached over HTTPS"}
	}
	for i, f := range Files {
		if found[i] {
			out.Exposed = append(out.Exposed, Exposed{Path: f.Path, What: f.What, Kind: f.Kind})
		}
	}
	return out
}

// fetch asks for one path and says whether it is the file. A non-200 answer
// is an answer, and not the file; only a failure to get any answer is an
// error.
func fetch(ctx context.Context, client *http.Client, url string, matches func([]byte) bool) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil && len(buf) == 0 {
		return false, nil
	}
	served := matches(buf)
	clear(buf)
	return served, nil
}

func (p *Prober) client() *http.Client {
	dial := p.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: defaultTimeout, AllowedPorts: []string{"443"}}
		dial = d.DialContext
	}
	roots, _ := truststore.Resolve(p.Roots)
	return &http.Client{
		// A redirect is the site saying the file is somewhere else, or
		// nowhere; either way it is not this file served here.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:         dial,
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: defaultTimeout,
		},
	}
}
