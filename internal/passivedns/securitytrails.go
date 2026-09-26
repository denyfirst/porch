package passivedns

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecurityTrails reads one register's list of the names it has seen under a
// domain.
//
// One request, and the answer is labels rather than whole names: a search for
// example.com comes back with `www`, `mail`, `dev`, and this puts the domain
// back on the end of each. It carries no dates, which is why this package
// reports none — see the note on Found.Names.
type SecurityTrails struct {
	// Endpoint is the base address of the register's API. Empty means its own.
	Endpoint string

	// Token is the operator's key. Required: without one this asks nothing at
	// all, rather than sending the domain to a company that will refuse the
	// question anyway. A disclosure that buys no answer is the worst trade
	// available.
	//
	// Read from the environment by whoever builds this, never from a command
	// line: a credential on a command line is a credential in a shell history
	// and in every process listing on the machine.
	Token string

	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the register's certificate is judged against.
	// Nil means the system store, loaded explicitly (R7).
	Roots *x509.CertPool

	// Timeout bounds the search.
	Timeout time.Duration
}

// securityTrailsEndpoint is the register's own address.
const securityTrailsEndpoint = "https://api.securitytrails.com/v1"

// securityTrailsAnswer is the part of the answer this reads.
//
// The labels and nothing else. The register returns a count and a metadata
// object beside them; a count this program did not derive from the names it
// kept would disagree with the list under it the first time a name was dropped
// for belonging to somebody else.
type securityTrailsAnswer struct {
	Subdomains []string `json:"subdomains"`
}

// Under asks the register what it has observed under a domain.
func (s *SecurityTrails) Under(ctx context.Context, domain string) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Register: "securitytrails", Reason: "no domain was given to search under"}
	}
	if s.Token == "" {
		return Found{Asked: true, Register: "securitytrails",
			Reason: "no key was configured for the passive register, so it was not asked"}
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	address, err := url.Parse(s.endpoint())
	if err != nil {
		return Found{Asked: true, Register: "securitytrails", Reason: "the register's address could not be read"}
	}
	address.Path = strings.TrimSuffix(address.Path, "/") + "/domain/" + url.PathEscape(domain) + "/subdomains"

	// Every name it holds, including the ones it has stopped seeing. What a
	// name is doing now is a question asked of the name itself, not of a
	// register's opinion about whether it is still interesting — and a name
	// that stopped resolving last year is exactly the kind an operator is
	// looking for.
	query := url.Values{}
	query.Set("children_only", "false")
	query.Set("include_inactive", "true")
	address.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return Found{Asked: true, Register: "securitytrails", Reason: "the register's address could not be requested"}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", s.Token)

	resp, err := registerClient(s.Dial, s.Roots, s.timeout()).Do(req)
	if err != nil {
		return Found{Asked: true, Register: "securitytrails", Reason: "the passive register could not be reached"}
	}
	defer resp.Body.Close()

	if reason := reasonFor(resp.StatusCode); reason != "" {
		return Found{Asked: true, Register: "securitytrails", Reason: reason}
	}
	if resp.StatusCode == http.StatusNotFound {
		return Found{Asked: true, Register: "securitytrails"}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Found{Asked: true, Register: "securitytrails", Reason: "the register's answer could not be read"}
	}
	if len(body) > maxBody {
		return Found{Asked: true, Register: "securitytrails",
			Reason: "the register's answer is larger than this reads, so the inventory would be short"}
	}

	var raw securityTrailsAnswer
	if err := json.Unmarshal(body, &raw); err != nil {
		return Found{Asked: true, Register: "securitytrails", Reason: "the register's answer was not in the form this reads"}
	}

	got := newCollector(domain)
	for _, label := range raw.Subdomains {
		// A label, not a name. An empty one would put the domain itself in the
		// list as though it had been discovered, and a label carrying its own
		// trailing dot would produce `www..example.com`.
		label = strings.Trim(strings.TrimSpace(label), ".")
		if label == "" {
			continue
		}
		got.keep(label + "." + domain)
	}
	return got.result("securitytrails")
}

func (s *SecurityTrails) endpoint() string {
	if s.Endpoint == "" {
		return securityTrailsEndpoint
	}
	return s.Endpoint
}

func (s *SecurityTrails) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return defaultTimeout
}
