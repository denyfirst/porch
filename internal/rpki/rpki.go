// Package rpki asks whether the routes to a domain's addresses are signed.
//
// An address is reachable because some network announces the block it is in,
// and nothing in the routing system stops a different network announcing it
// instead — which is how traffic for a whole service is taken. RPKI lets the
// holder of a block sign which network may announce it (a ROA), and networks
// that validate drop an announcement the signature contradicts (RFC 6811).
//
// So for each address there are three answers: the route is signed and
// matches (valid); it is signed and does not match (invalid, and dropped by
// validating networks); or nobody signed it (not found, and anybody's
// announcement is as good as the real one's).
//
// # Asking the source
//
// RIPE NCC, the regional internet registry for Europe, publishes both halves
// through RIPEstat: which prefix and origin network the routing system shows
// for an address, and how that pair validates against the signed ROAs of all
// five registries. It is asked directly, about the addresses only.
//
// # What is guarded
//
// The addresses come from the measured zone, so each is parsed as an address
// before it is put in a query, and nothing it says reaches a URL unescaped.
// The answers are bounded, and every prefix and network number is parsed
// rather than repeated. safedial, HTTPS on port 443, no redirect, no proxy.
package rpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	endpoint       = "https://stat.ripe.net/data/"
	maxAnswer      = 256 << 10
	maxAddresses   = 8
	maxOrigins     = 4
	defaultTimeout = 15 * time.Second
)

// UserAgent identifies this client, as everything else here does.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// States a route can be in.
const (
	Valid    = "valid"
	Invalid  = "invalid"
	NotFound = "not-found"
	NoRoute  = "no-route"
)

// Route is what was established for one address.
type Route struct {
	Address string `json:"address"`

	// Prefix and Origins are what the routing system shows: the block the
	// address is announced in and the networks announcing it.
	Prefix  string   `json:"prefix,omitempty"`
	Origins []string `json:"origins,omitempty"`

	// State is Valid, Invalid, NotFound or NoRoute; empty when Reason says
	// why nothing was established.
	State string `json:"state,omitempty"`

	Reason string `json:"reason,omitempty"`
}

// Client asks RIPEstat.
type Client struct {
	// Endpoint is the data API's base address. Empty means RIPEstat's.
	Endpoint string

	// Dial opens connections. Nil selects safedial, port 443 only.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots judges the service's certificate. Nil means the system store.
	Roots *x509.CertPool

	Timeout time.Duration
}

// Check establishes the route state of each address, at most eight.
//
// Addresses in one announced block are asked about once.
func (c *Client) Check(ctx context.Context, addresses []string) []Route {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type pair struct{ prefix, origin string }
	validated := map[pair]string{}

	var out []Route
	seen := map[netip.Addr]bool{}
	for _, raw := range addresses {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || seen[addr] {
			continue
		}
		seen[addr] = true
		if len(out) >= maxAddresses {
			break
		}
		r := Route{Address: addr.String()}

		prefix, origins, reason := c.networkInfo(ctx, addr)
		switch {
		case reason != "":
			r.Reason = reason
		case !prefix.IsValid() || len(origins) == 0:
			r.State = NoRoute
		default:
			r.Prefix, r.Origins = prefix.String(), origins
			r.State = Valid
			for _, origin := range origins {
				key := pair{r.Prefix, origin}
				state, ok := validated[key]
				if !ok {
					state, reason = c.validate(ctx, origin, prefix)
					if reason != "" {
						r.State, r.Reason = "", reason
						break
					}
					validated[key] = state
				}
				// The worst of the origins: one network announcing the block
				// in contradiction of its signature is the one that is dropped.
				if rank(state) > rank(r.State) {
					r.State = state
				}
			}
		}
		out = append(out, r)
	}
	return out
}

func rank(state string) int {
	switch state {
	case Invalid:
		return 3
	case NotFound:
		return 2
	case Valid:
		return 1
	}
	return 0
}

// networkInfo asks which block the address is announced in, and by whom.
func (c *Client) networkInfo(ctx context.Context, addr netip.Addr) (netip.Prefix, []string, string) {
	var raw struct {
		Status string `json:"status"`
		Data   struct {
			ASNs   []string `json:"asns"`
			Prefix string   `json:"prefix"`
		} `json:"data"`
	}
	if reason := c.get(ctx, "network-info", url.Values{"resource": {addr.String()}}, &raw); reason != "" {
		return netip.Prefix{}, nil, reason
	}
	if raw.Status != "ok" {
		return netip.Prefix{}, nil, "RIPEstat did not answer the question"
	}
	if raw.Data.Prefix == "" {
		return netip.Prefix{}, nil, ""
	}
	prefix, err := netip.ParsePrefix(raw.Data.Prefix)
	if err != nil || !prefix.Contains(addr) {
		return netip.Prefix{}, nil, "RIPEstat's answer was not in the form this reads"
	}
	var origins []string
	for _, a := range raw.Data.ASNs {
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(a), "AS"), 10, 32)
		if err != nil {
			return netip.Prefix{}, nil, "RIPEstat's answer was not in the form this reads"
		}
		if len(origins) < maxOrigins {
			origins = append(origins, strconv.FormatUint(n, 10))
		}
	}
	sort.Strings(origins)
	return prefix.Masked(), origins, ""
}

// validate asks how an origin and prefix validate against the signed ROAs.
func (c *Client) validate(ctx context.Context, origin string, prefix netip.Prefix) (string, string) {
	var raw struct {
		Status string `json:"status"`
		Data   struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	q := url.Values{"resource": {origin}, "prefix": {prefix.String()}}
	if reason := c.get(ctx, "rpki-validation", q, &raw); reason != "" {
		return "", reason
	}
	if raw.Status != "ok" {
		return "", "RIPEstat did not answer the question"
	}
	switch s := strings.ToLower(raw.Data.Status); {
	case s == "valid":
		return Valid, ""
	case strings.HasPrefix(s, "invalid"):
		// invalid_asn and invalid_length are both a contradiction of the
		// signature, and both are dropped.
		return Invalid, ""
	case s == "unknown" || s == "not-found" || s == "notfound":
		return NotFound, ""
	}
	return "", "RIPEstat's answer was not in the form this reads"
}

// get fetches one data call into v, and says why not where it could not.
func (c *Client) get(ctx context.Context, call string, q url.Values, v any) string {
	base := c.Endpoint
	if base == "" {
		base = endpoint
	}
	u, err := url.Parse(base + call + "/data.json")
	if err != nil {
		return "RIPEstat's address could not be read"
	}
	q.Set("sourceapp", "porch")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "RIPEstat's address could not be requested"
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return "RIPEstat could not be reached"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "RIPEstat did not answer the question"
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(body) > maxAnswer {
		return "RIPEstat's answer could not be read"
	}
	if err := json.Unmarshal(body, v); err != nil {
		return "RIPEstat's answer was not in the form this reads"
	}
	return ""
}

var errRedirect = errors.New("rpki: redirect")

func (c *Client) client() *http.Client {
	dial := c.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: defaultTimeout, AllowedPorts: []string{"443"}}
		dial = d.DialContext
	}
	roots, _ := truststore.Resolve(c.Roots)
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
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
