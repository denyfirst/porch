package ctsearch

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

// CertSpotter reads SSLMate's index of the public logs.
//
// # Why there is a second monitor
//
// internal/ctsearch has said since it was written that the monitor is
// replaceable — "a monitor that goes away, changes its interface, or that an
// operator would rather not use is a substitution rather than a rewrite". That
// was an argument on paper until 2026-09-25, when crt.sh answered 502 to every
// request for a whole day and the inventory mode could not be demonstrated at
// all. A claim about substitutability that has never been exercised is a claim
// nobody has checked, including whoever made it.
//
// So there are two, with different owners, different infrastructure and
// different answer formats. An operator whose monitor is down has somewhere to
// go, and the interface has been shown to fit something it was not written
// around.
//
// # It answers in pages, and that is the thing to get right
//
// One request returns at most a hundred issuances. A reader that took the first
// page and stopped would produce an inventory that is short without saying so —
// sorted, dated, plausible, and missing most of a large estate. That is the one
// failure this mode cannot survive, so pages are followed to a bound and the
// answer says when the bound was reached.
type CertSpotter struct {
	// Endpoint is the address to query. Empty means SSLMate's.
	//
	// A base address rather than a template: this monitor takes several
	// parameters and builds its own paging cursor, so a format string with the
	// name in it could not express the second request.
	Endpoint string

	// Token is an API key, if the operator has one. Empty asks anonymously,
	// which SSLMate allows at a lower rate.
	//
	// Sent as a bearer credential and never written anywhere: it identifies
	// the person running this to the monitor, which is a disclosure they chose
	// by setting it, and it has no business in a report (I6).
	Token string

	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the monitor's certificate is judged against.
	// Nil means the system store, loaded explicitly (R7).
	Roots *x509.CertPool

	// Timeout bounds the whole search, every page of it.
	Timeout time.Duration
}

const (
	// certSpotterEndpoint is SSLMate's address for issuances.
	certSpotterEndpoint = "https://api.certspotter.com/v1/issuances"

	// maxPages bounds how far a paged answer is followed.
	//
	// A hundred issuances a page, so this reads up to five thousand
	// certificates. An estate larger than that is one where the count matters
	// more than the list, and the answer says it was cut rather than pretending
	// the list is complete.
	maxPages = 50
)

// certSpotterEntry is one issuance as SSLMate writes it.
//
// Its own type rather than the crt.sh one: the two monitors agree on nothing
// but the idea. This one carries the names already split into an array and
// identifies a certificate by its hash rather than a serial, which is the
// better key of the two — a serial is unique per issuer and a hash is unique.
type certSpotterEntry struct {
	ID        string   `json:"id"`
	SHA256    string   `json:"cert_sha256"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
}

// SearchEstate asks which names under a domain appear in logged certificates.
//
// The same answer shape the other monitor produces, so that everything above
// this — the filtering, the counting, the report and the sentence about what it
// cannot show — is written once.
func (c *CertSpotter) SearchEstate(ctx context.Context, domain string) Estate {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return Estate{Asked: true, Reason: "no domain was given to search under"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	var all []entry
	after := ""

	for page := 0; ; page++ {
		if page >= maxPages {
			// Stopped rather than followed forever, and said so below. An
			// inventory that is quietly short is the failure this mode cannot
			// survive (R4).
			out := collect(all, domain)
			out.Truncated = true
			return out
		}

		got, next, reason := c.page(ctx, domain, after)
		if reason != "" {
			return Estate{Asked: true, Domain: domain, Reason: reason}
		}
		if len(got) == 0 {
			break
		}
		all = append(all, got...)
		if next == "" {
			break
		}
		after = next
	}

	return collect(all, domain)
}

// page fetches one page and says where the next one starts.
func (c *CertSpotter) page(ctx context.Context, domain, after string) (got []entry, next, reason string) {
	address, err := url.Parse(c.endpoint())
	if err != nil {
		return nil, "", "the monitor's address could not be read"
	}
	query := url.Values{}
	query.Set("domain", domain)
	query.Set("include_subdomains", "true")
	query.Add("expand", "dns_names")
	query.Add("expand", "not_before")
	query.Add("expand", "not_after")
	if after != "" {
		query.Set("after", after)
	}
	address.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return nil, "", "the monitor's address could not be requested"
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, "", "the certificate transparency monitor could not be reached"
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Its own sentence. This monitor answers anonymous callers at a low
		// rate, and "did not answer the search" would send an operator looking
		// for a fault in their network or in the domain.
		return nil, "", "the monitor is rate limiting this search; it allows more with an API key"
	case resp.StatusCode != http.StatusOK:
		return nil, "", "the certificate transparency monitor did not answer the search"
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, "", "the monitor's answer could not be read"
	}
	if len(body) > maxBody {
		return nil, "", "the monitor's answer is larger than this reads, so the inventory would be short"
	}

	var raw []certSpotterEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", "the monitor's answer was not in the form this reads"
	}

	for _, e := range raw {
		got = append(got, entry{
			// The hash, as the identity a certificate is deduplicated on. This
			// monitor returns the precertificate and the certificate as one
			// issuance, but a page boundary can still repeat one.
			SerialNumber: e.SHA256,
			NameValue:    strings.Join(e.DNSNames, "\n"),
			NotBefore:    e.NotBefore,
			NotAfter:     e.NotAfter,
		})
		next = e.ID
	}
	return got, next, ""
}

func (c *CertSpotter) endpoint() string {
	if c.Endpoint == "" {
		return certSpotterEndpoint
	}
	return c.Endpoint
}

func (c *CertSpotter) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

// client is built the same way the other monitor's is, so that a search of
// either goes through the same refusal of private destinations and the same
// trust store.
func (c *CertSpotter) client() *http.Client {
	return monitorClient(c.Dial, c.Roots)
}
