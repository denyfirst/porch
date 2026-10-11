// Package rdap reads a domain's registration from the registry that holds it.
//
// Registration is the part of a domain nothing in its DNS can show: when it
// runs out, whether it can be moved to another registrar without its owner's
// say, and who it is registered through. A domain that lapses takes every
// service under it with it, and one that can be transferred quietly is one a
// stolen registrar password is enough to lose. Both are answered by the
// registry, in the protocol ICANN has required of every generic top-level
// registry since 2025: RDAP (RFC 9082, RFC 9083).
//
// # Asking the source
//
// Which registry answers for a top-level domain is published by IANA as one
// file, read whole, so IANA learns nothing about which domain is being looked
// at. The registry is then asked about the domain, and learns that somebody
// looked at a registration it holds. Nothing in between.
//
// # What is guarded
//
// The addresses come from IANA's file, not from the domain being measured, but
// they are dialled as everything else here is: safedial refuses private,
// loopback and reserved destinations, HTTPS on port 443 only, no redirect is
// followed, no proxy, and every answer is size-capped and refused rather than
// truncated. What a registry writes is cleaned before it reaches a report.
package rdap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/display"
	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	// bootstrapURL is IANA's list of the registries that run RDAP.
	bootstrapURL = "https://data.iana.org/rdap/dns.json"

	// keepBootstrap is how long the list is kept before it is read again. It
	// changes a few times a year.
	keepBootstrap = 24 * time.Hour

	// maxBootstrap and maxAnswer bound what is read. IANA's list is tens of
	// kilobytes and a registration a few.
	maxBootstrap = 1 << 20
	maxAnswer    = 256 << 10

	// maxLabels bounds how many names are asked on the way to the one the
	// registry holds: example.com, then www.example.com, and so on.
	maxLabels = 4

	// maxField bounds one string from a registry.
	maxField = 128

	defaultTimeout = 10 * time.Second
)

// UserAgent identifies this client, as everything else here does.
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

// Registration is what the registry holds for a domain.
type Registration struct {
	// Asked is false when no registry was asked at all.
	Asked bool `json:"asked"`

	// Domain is the name the registry answered for: the registered domain,
	// which may be shorter than the name scanned.
	Domain string `json:"domain,omitempty"`

	// Registry is the host that answered.
	Registry string `json:"registry,omitempty"`

	// Registrar is who the domain is registered through, as the registry
	// names it.
	Registrar string `json:"registrar,omitempty"`

	Created time.Time `json:"created,omitzero"`
	Expires time.Time `json:"expires,omitzero"`
	Changed time.Time `json:"changed,omitzero"`

	// Statuses are the registry's status values, as RFC 8056 writes them.
	Statuses []string `json:"statuses,omitempty"`

	// DelegationSigned is the registry's word on whether the domain's
	// delegation carries DNSSEC.
	DelegationSigned bool `json:"delegationSigned"`

	// Reason says why nothing was established. Empty on success.
	Reason string `json:"reason,omitempty"`
}

// Has reports whether the registry gave this status.
func (r Registration) Has(status string) bool {
	for _, s := range r.Statuses {
		if s == status {
			return true
		}
	}
	return false
}

// TransferLocked is whether the registrar has locked the domain against
// transfer (RFC 8056 "client transfer prohibited"), or the registry has.
func (r Registration) TransferLocked() bool {
	return r.Has("client transfer prohibited") || r.Has("server transfer prohibited")
}

// RegistryLocked is whether the registry itself refuses changes, which no
// registrar account can undo: transfer, update and deletion all prohibited at
// the server.
func (r Registration) RegistryLocked() bool {
	return r.Has("server transfer prohibited") && r.Has("server update prohibited") &&
		r.Has("server delete prohibited")
}

// Client asks registries about domains.
type Client struct {
	// Dial opens connections. Nil selects safedial, port 443 only.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots judges the servers' certificates. Nil means the system store,
	// loaded explicitly (R7).
	Roots *x509.CertPool

	// Timeout bounds one lookup, every request of it.
	Timeout time.Duration

	// Bootstrap is the address of IANA's list. Empty means IANA's own.
	Bootstrap string

	// Now is the clock. Nil means the real one.
	Now func() time.Time

	mu       sync.Mutex
	services map[string]string
	fetched  time.Time
	tried    time.Time
}

// retryBootstrap is how long a failure to read IANA's list stands before it is
// read again, so a list that cannot be fetched is not fetched on every scan.
const retryBootstrap = 5 * time.Minute

// errNotFound is a registry saying it holds no such name, which is how a
// subdomain is told from the registered domain above it.
var errNotFound = errors.New("rdap: not found")

// Lookup reads the registration of the domain a name belongs to.
func (c *Client) Lookup(ctx context.Context, name string) Registration {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	labels := strings.Split(name, ".")
	if name == "" || len(labels) < 2 {
		return Registration{Asked: true, Reason: "the name has no registered domain to ask about"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	base, reason := c.serviceFor(ctx, labels[len(labels)-1])
	if reason != "" {
		return Registration{Asked: true, Reason: reason}
	}
	host := ""
	if u, err := url.Parse(base); err == nil {
		host = u.Hostname()
	}

	// From the shortest name up, so the registry is told no more of the name
	// than the domain it holds: example.com before www.example.com.
	for n := 2; n <= len(labels) && n <= maxLabels+1; n++ {
		domain := strings.Join(labels[len(labels)-n:], ".")
		got, err := c.domain(ctx, base, domain)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return Registration{Asked: true, Registry: host, Reason: err.Error()}
		}
		got.Asked, got.Domain, got.Registry = true, domain, host
		return got
	}
	return Registration{Asked: true, Registry: host,
		Reason: "the registry holds no registration for this name or the domains above it"}
}

// serviceFor finds the registry that answers for a top-level domain.
func (c *Client) serviceFor(ctx context.Context, tld string) (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stale := c.services == nil || c.now().Sub(c.fetched) > keepBootstrap
	if stale && c.now().Sub(c.tried) >= retryBootstrap {
		c.tried = c.now()
		services, err := c.readBootstrap(ctx)
		if err != nil {
			if c.services == nil {
				return "", "IANA's list of registries could not be read"
			}
			// The list kept from before is a day or so old, and registries
			// rarely move: better than no answer.
		} else {
			c.services, c.fetched = services, c.now()
		}
	}
	if c.services == nil {
		return "", "IANA's list of registries could not be read"
	}
	base, ok := c.services[tld]
	if !ok {
		return "", "the registry for ." + tld + " publishes no RDAP service"
	}
	return base, ""
}

// readBootstrap reads IANA's file: a list of services, each a list of
// top-level domains and the addresses that answer for them.
func (c *Client) readBootstrap(ctx context.Context) (map[string]string, error) {
	address := c.Bootstrap
	if address == "" {
		address = bootstrapURL
	}
	body, err := c.get(ctx, address, maxBootstrap, "application/json")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, service := range raw.Services {
		if len(service) != 2 {
			continue
		}
		base := ""
		for _, u := range service[1] {
			// HTTPS only, and the first one listed: IANA lists http beside
			// https for some registries, and a registration read in the clear
			// is one anybody on the path could have written.
			if parsed, err := url.Parse(u); err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil {
				base = u
				break
			}
		}
		if base == "" {
			continue
		}
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		for _, tld := range service[0] {
			out[strings.ToLower(tld)] = base
		}
	}
	if len(out) == 0 {
		return nil, errors.New("rdap: an empty list")
	}
	return out, nil
}

// answer is what this reads of a domain object (RFC 9083 §5.3).
type answer struct {
	ObjectClass string   `json:"objectClassName"`
	LDHName     string   `json:"ldhName"`
	Status      []string `json:"status"`
	Events      []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Entities []entity `json:"entities"`
}

type entity struct {
	Roles []string        `json:"roles"`
	VCard json.RawMessage `json:"vcardArray"`
}

// domain asks the registry about one name.
func (c *Client) domain(ctx context.Context, base, domain string) (Registration, error) {
	body, err := c.get(ctx, base+"domain/"+url.PathEscape(domain), maxAnswer, "application/rdap+json")
	if err != nil {
		return Registration{}, err
	}
	var a answer
	if err := json.Unmarshal(body, &a); err != nil || a.ObjectClass != "domain" {
		return Registration{}, errors.New("the registry's answer was not in the form this reads")
	}
	if !strings.EqualFold(strings.TrimSuffix(a.LDHName, "."), domain) {
		// An answer about some other name is not an answer about this one.
		return Registration{}, errors.New("the registry answered about a different name")
	}

	var out Registration
	for _, s := range a.Status {
		if len(out.Statuses) >= 16 {
			break
		}
		if s = clean(strings.ToLower(s)); s != "" {
			out.Statuses = append(out.Statuses, s)
		}
	}
	for _, e := range a.Events {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.Date))
		if err != nil {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			out.Created = t.UTC()
		case "expiration":
			out.Expires = t.UTC()
		case "last changed":
			out.Changed = t.UTC()
		}
	}
	if a.SecureDNS != nil {
		out.DelegationSigned = a.SecureDNS.DelegationSigned
	}
	for _, e := range a.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				out.Registrar = clean(fullName(e.VCard))
			}
		}
	}
	return out, nil
}

// fullName reads the fn property of a jCard (RFC 7095): an array whose second
// element is a list of properties, each [name, parameters, type, value].
func fullName(raw json.RawMessage) string {
	var card []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, value string
		if json.Unmarshal(p[0], &name) != nil || name != "fn" {
			continue
		}
		if json.Unmarshal(p[3], &value) == nil {
			return value
		}
	}
	return ""
}

// get fetches one document, refusing anything but a 200 and anything larger
// than limit.
func (c *Client) get(ctx context.Context, address string, limit int64, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("the registry's address could not be requested")
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", accept+", application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, errors.New("the registry could not be reached")
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest:
		// 400 is how some registries refuse a name that is a suffix rather
		// than a domain, such as co.uk, which is asked on the way to
		// example.co.uk.
		return nil, errNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("the registry is rate limiting this lookup")
	case resp.StatusCode != http.StatusOK:
		return nil, errors.New("the registry did not answer the lookup")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("the registry's answer could not be read")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("the registry's answer is larger than this reads")
	}
	return body, nil
}

func (c *Client) client() *http.Client {
	dial := c.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: defaultTimeout, AllowedPorts: []string{"443"}}
		dial = d.DialContext
	}
	roots, _ := truststore.Resolve(c.Roots)
	return &http.Client{
		// A registry that redirects is pointing somewhere this did not
		// choose; the lookup is reported as not established instead.
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

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// clean bounds a registry's string and strips what should not travel: control
// characters dropped, format characters marked (R10).
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxField {
		s = s[:maxField]
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return display.Mark(b.String())
}
