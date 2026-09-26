package passivedns

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// VirusTotal reads the second register, which answers in pages.
//
// There are two implementations here for the reason there are two certificate
// monitors: a dependency described as replaceable and never replaced is a
// claim nobody has checked, including whoever made it. These two have
// different owners, different collection and different answer formats, and
// everything above them — the label boundary, the bounds, the report and the
// sentence about what a register cannot show — is written once.
//
// # The paging is the part to get right
//
// One request returns a page and a cursor. A reader that took the first page
// and stopped would return a list that is sorted, plausible and missing most
// of a large estate, with nothing about it looking wrong. Pages are followed
// to a bound, the bound is reported, and a cursor that does not move ends the
// walk rather than spinning on it.
type VirusTotal struct {
	// Endpoint is the base address of the register's API. Empty means its own.
	Endpoint string

	// Token is the operator's key. Required: without one this asks nothing,
	// rather than naming the domain to a company that will refuse the question
	// anyway.
	Token string

	// Dial opens the connection. Nil selects safedial.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the register's certificate is judged against.
	Roots *x509.CertPool

	// Timeout bounds the whole search, every page of it.
	Timeout time.Duration
}

const (
	// virusTotalEndpoint is the register's own address.
	virusTotalEndpoint = "https://www.virustotal.com/api/v3"

	// virusTotalPage is how many names one request asks for.
	virusTotalPage = 40
)

// virusTotalAnswer is the part of a page this reads: the names, and where the
// next page starts.
type virusTotalAnswer struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
}

// Under asks the register what it has observed under a domain.
func (v *VirusTotal) Under(ctx context.Context, domain string) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Register: "virustotal", Reason: "no domain was given to search under"}
	}
	if v.Token == "" {
		return Found{Asked: true, Register: "virustotal",
			Reason: "no key was configured for the passive register, so it was not asked"}
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout())
	defer cancel()

	got := newCollector(domain)
	client := registerClient(v.Dial, v.Roots, v.timeout())
	cursor := ""

	for page := 0; ; page++ {
		if page >= maxPages {
			// Stopped rather than followed forever, and said so. An inventory
			// that is quietly short is the failure this mode cannot survive.
			out := got.result("virustotal")
			out.Truncated = true
			return out
		}

		names, next, reason := v.page(ctx, client, domain, cursor)
		if reason != "" {
			// A page that failed after earlier pages answered is still a
			// failure: what came back is part of an estate, and reporting part
			// of one as the whole is the thing being avoided everywhere else
			// here (R4).
			return Found{Asked: true, Register: "virustotal", Reason: reason}
		}
		for _, name := range names {
			got.keep(name)
		}
		if next == "" || next == cursor || len(names) == 0 {
			break
		}
		cursor = next
	}

	return got.result("virustotal")
}

// page fetches one page and says where the next one starts.
func (v *VirusTotal) page(ctx context.Context, client *http.Client, domain, cursor string) (names []string, next, reason string) {
	address, err := url.Parse(v.endpoint())
	if err != nil {
		return nil, "", "the register's address could not be read"
	}
	address.Path = strings.TrimSuffix(address.Path, "/") + "/domains/" + url.PathEscape(domain) + "/subdomains"

	query := url.Values{}
	query.Set("limit", strconv.Itoa(virusTotalPage))
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	address.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return nil, "", "the register's address could not be requested"
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", v.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "the passive register could not be reached"
	}
	defer resp.Body.Close()

	if reason := reasonFor(resp.StatusCode); reason != "" {
		return nil, "", reason
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, "", "the register's answer could not be read"
	}
	if len(body) > maxBody {
		return nil, "", "the register's answer is larger than this reads, so the inventory would be short"
	}

	var raw virusTotalAnswer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", "the register's answer was not in the form this reads"
	}

	for _, d := range raw.Data {
		names = append(names, d.ID)
	}
	return names, raw.Meta.Cursor, ""
}

func (v *VirusTotal) endpoint() string {
	if v.Endpoint == "" {
		return virusTotalEndpoint
	}
	return v.Endpoint
}

func (v *VirusTotal) timeout() time.Duration {
	if v.Timeout > 0 {
		return v.Timeout
	}
	return defaultTimeout
}
