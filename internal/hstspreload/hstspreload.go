// Package hstspreload asks whether a host is on the HSTS preload list.
//
// A site that sends Strict-Transport-Security is reached over HTTPS from the
// second visit on; one on the preload list is reached that way from the
// first, because the list is built into the browser. Chrome keeps the list,
// Firefox and Safari build theirs from it, and hstspreload.org is where it is
// submitted to and read from — the source, asked directly.
//
// Guarded as everything else that leaves this machine is: safedial, HTTPS on
// port 443, no redirect, no proxy, a small answer refused rather than cut,
// and only the four states the service defines are believed.
package hstspreload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	endpoint       = "https://hstspreload.org/api/v2/status"
	maxAnswer      = 16 << 10
	defaultTimeout = 10 * time.Second
)

// UserAgent identifies this client, as everything else here does.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// Status is what the list says of a host.
type Status struct {
	// Asked is false when nothing was asked.
	Asked bool `json:"asked"`

	// State is "preloaded", "pending", "rejected" or "unknown", the last
	// meaning the host is not on the list.
	State string `json:"state,omitempty"`

	// PreloadedDomain is the entry that covers the host, which may be a
	// parent of it, and Bulk whether it was added through the submission form.
	PreloadedDomain string `json:"preloadedDomain,omitempty"`
	Bulk            bool   `json:"bulk,omitempty"`

	// Reason says why nothing was established.
	Reason string `json:"reason,omitempty"`
}

// Client asks the preload list.
type Client struct {
	// Endpoint is the status address. Empty means hstspreload.org's.
	Endpoint string

	// Dial opens connections. Nil selects safedial, port 443 only.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots judges the service's certificate. Nil means the system store.
	Roots *x509.CertPool

	Timeout time.Duration
}

// Status asks the list about one host.
func (c *Client) Status(ctx context.Context, host string) Status {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || !strings.Contains(host, ".") {
		return Status{Asked: true, Reason: "the name is not one the list could hold"}
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := c.Endpoint
	if address == "" {
		address = endpoint
	}
	u, err := url.Parse(address)
	if err != nil {
		return Status{Asked: true, Reason: "the list's address could not be read"}
	}
	u.RawQuery = url.Values{"domain": {host}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Status{Asked: true, Reason: "the list's address could not be requested"}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return Status{Asked: true, Reason: "the preload list could not be reached"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Status{Asked: true, Reason: "the preload list did not answer"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(body) > maxAnswer {
		return Status{Asked: true, Reason: "the preload list's answer could not be read"}
	}

	var raw struct {
		Name            string `json:"name"`
		Status          string `json:"status"`
		PreloadedDomain string `json:"preloadedDomain"`
		Bulk            bool   `json:"bulk"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return Status{Asked: true, Reason: "the preload list's answer was not in the form this reads"}
	}

	out := Status{Asked: true, Bulk: raw.Bulk}
	switch raw.Status {
	case "preloaded", "pending", "rejected", "unknown":
		out.State = raw.Status
	default:
		return Status{Asked: true, Reason: "the preload list's answer was not in the form this reads"}
	}

	// The covering entry is believed only if it covers this host: the host
	// itself, or a parent on a label boundary.
	if d := strings.ToLower(strings.TrimSuffix(raw.PreloadedDomain, ".")); d != "" && (d == host || strings.HasSuffix(host, "."+d)) {
		out.PreloadedDomain = d
	}
	return out
}

func (c *Client) client() *http.Client {
	dial := c.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: defaultTimeout, AllowedPorts: []string{"443"}}
		dial = d.DialContext
	}
	roots, _ := truststore.Resolve(c.Roots)
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:         dial,
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: defaultTimeout,
		},
	}
}
