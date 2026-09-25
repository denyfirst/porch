package ctsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Estate is the names under one domain that appear in publicly logged
// certificates.
//
// # What this is, and what it is not
//
// It is a reading of a public register. Every publicly trusted certificate is
// submitted to append-only logs before a browser will accept it, and the names
// a certificate covers are written in it. So the names here were published by
// whoever obtained the certificate — they are not guessed, and finding them
// sends nothing to the estate itself (N7).
//
// It is not a list of the estate's hosts, and a report that let somebody read
// it as one would be worse than no report. Three kinds of name are missing from
// it and no amount of searching will produce them:
//
//   - A host with no publicly trusted certificate is never logged. Plain HTTP,
//     a service that is not HTTPS at all, or anything behind a private
//     authority leaves no trace here.
//   - A wildcard certificate covers hosts without naming them. `*.example.com`
//     in a log tells a reader that the hosts exist and nothing about what they
//     are called, which is exactly what a wildcard is for.
//   - A name logged before a monitor's history begins, or dropped from it.
//
// Every one of those is a name a port scan would find and this will not. The
// two methods answer different questions and the honest report says which
// question it answered — Wildcards and the sentence policy builds from it are
// there for that reason, and they are not decoration.
type Estate struct {
	// Asked reports that the search was made. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Domain is the domain searched under, folded.
	Domain string `json:"domain,omitempty"`

	// Names are the distinct names found, sorted, each with when it was first
	// and last covered.
	Names []Name `json:"names,omitempty"`

	// Distinct is how many distinct names were found, which is not len(Names)
	// when the list was cut.
	Distinct int `json:"distinct"`

	// Truncated is set when more names were found than are listed.
	Truncated bool `json:"truncated,omitempty"`

	// Wildcards is how many of the names are wildcards.
	//
	// Counted rather than merely listed because it is the measure of how much
	// this search could not see: an estate covered by one wildcard shows one
	// name here and may run a hundred hosts.
	Wildcards int `json:"wildcards,omitempty"`

	// Certificates is how many distinct certificates were read, by serial.
	Certificates int `json:"certificates,omitempty"`

	// Foreign is how many names the monitor returned that are not under this
	// domain, and were therefore dropped.
	//
	// Kept as a count because it is evidence about the answer rather than about
	// the estate: a certificate covering example.com and somebody-else.test
	// returns both, and listing the second under this domain's inventory would
	// be this program inventing an estate boundary that the certificate does
	// not draw.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established. Empty on success.
	Reason string `json:"reason,omitempty"`
}

// Name is one name found, and the window the logs show it in.
type Name struct {
	// Name is the name as it was logged, folded and cleaned.
	Name string `json:"name"`

	// Wildcard is whether it covers hosts without naming them.
	Wildcard bool `json:"wildcard,omitempty"`

	// FirstSeen is the earliest start of a certificate covering it, and
	// LastSeen the latest expiry.
	//
	// LastSeen is the useful one. A name whose newest certificate expired two
	// years ago is either gone or was renewed under a wildcard, and an operator
	// reading an inventory of their own estate wants to know which names stopped
	// being maintained. Neither reading is asserted here: the report gives the
	// date and says what it is.
	FirstSeen time.Time `json:"firstSeen,omitempty"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

const (
	// maxEstateNames bounds the inventory. Large, because here the names are
	// the answer rather than a detail beside a certificate — an estate of a few
	// hundred names is ordinary and cutting it at the bound used for one
	// certificate's subject list would drop most of it.
	maxEstateNames = 2000

	// maxEstateEntryNames bounds the names read from one certificate. A
	// certificate carrying a thousand names is a shared one, and the names on
	// it that belong to this domain are kept up to this many.
	maxEstateEntryNames = 500
)

// SearchEstate asks the monitor which names under a domain appear in logged
// certificates.
//
// One request. The identity searched is "%.domain", which is the monitor's
// wildcard for anything under it, and the apex itself is kept when a
// certificate names it.
//
// Every name the monitor returns is checked against the domain before it is
// kept. A certificate may cover names in several estates at once — that is what
// a shared certificate is — and reporting the others here would be this program
// drawing an estate boundary the certificate does not draw.
func (c *CRTSh) SearchEstate(ctx context.Context, domain string) Estate {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	out := Estate{Asked: true, Domain: domain}
	if domain == "" {
		return Estate{Asked: true, Reason: "no domain was given to search under"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	address := fmt.Sprintf(c.endpoint(), url.QueryEscape("%."+domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		out.Reason = "the monitor's address could not be requested"
		return out
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		out.Reason = "the certificate transparency monitor could not be reached"
		return out
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out.Reason = "the certificate transparency monitor did not answer the search"
		return out
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		out.Reason = "the monitor's answer could not be read"
		return out
	}
	if len(body) > maxBody {
		// Refused rather than cut. A partial answer here is an inventory with
		// names missing from it, and an inventory that is quietly short is the
		// one thing this must never produce (R4).
		out.Reason = "the monitor's answer is larger than this reads, so the inventory would be short"
		return out
	}

	var raw []entry
	if err := json.Unmarshal(body, &raw); err != nil {
		out.Reason = "the monitor's answer was not in the form this reads"
		return out
	}

	return collect(raw, domain)
}

// collect turns what the monitor said into the inventory.
func collect(raw []entry, domain string) Estate {
	out := Estate{Asked: true, Domain: domain}

	found := map[string]*Name{}
	serials := map[string]bool{}

	for _, e := range raw {
		serial := strings.ToLower(strings.TrimSpace(e.SerialNumber))
		if serial == "" || serials[serial] {
			// Every certificate is logged twice, once as a precertificate and
			// once as itself. Counting both would double the number of
			// certificates reported.
			continue
		}
		serials[serial] = true
		out.Certificates++

		from, until := stamp(e.NotBefore), stamp(e.NotAfter)

		for i, n := range strings.FieldsFunc(e.NameValue, func(r rune) bool {
			return r == '\n' || r == '\r'
		}) {
			if i >= maxEstateEntryNames {
				out.Truncated = true
				break
			}
			name := strings.ToLower(clean(strings.TrimSuffix(strings.TrimSpace(n), ".")))
			if name == "" {
				continue
			}
			if !under(name, domain) {
				out.Foreign++
				continue
			}

			at, seen := found[name]
			if !seen {
				if len(found) >= maxEstateNames {
					out.Truncated = true
					continue
				}
				at = &Name{Name: name, Wildcard: strings.HasPrefix(name, "*.")}
				found[name] = at
			}
			if !from.IsZero() && (at.FirstSeen.IsZero() || from.Before(at.FirstSeen)) {
				at.FirstSeen = from
			}
			if until.After(at.LastSeen) {
				at.LastSeen = until
			}
		}
	}

	for _, at := range found {
		if at.Wildcard {
			out.Wildcards++
		}
		out.Names = append(out.Names, *at)
	}
	out.Distinct = len(out.Names)

	// Sorted so that two runs of the same search read the same, and by name
	// rather than by date: an inventory is read by looking for a name.
	sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Name < out.Names[j].Name })
	return out
}

// under reports whether a name belongs to the domain searched.
//
// The apex itself, or something under a label boundary. The boundary is the
// whole of it: "notexample.com" ends with "example.com" as text and is a
// different estate, and a check written with HasSuffix alone would put somebody
// else's host in an inventory a security team acts on.
func under(name, domain string) bool {
	if name == domain {
		return true
	}
	return strings.HasSuffix(name, "."+domain)
}
