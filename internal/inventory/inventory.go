// Package inventory brings a domain's names together from the sources that
// named them.
//
// # Why the source is a column and not a footnote
//
// Two sources answer the same question differently and neither is complete. A
// certificate log holds the names somebody obtained a publicly trusted
// certificate for, and nothing else: a host on plain HTTP, or behind a private
// authority, or covered by a wildcard, is not in it. A domain's own records
// hold the hosts its mail, its sender policy and its delegation have to name,
// and nothing else: a web server that takes no mail is in none of them.
//
// So the union is a better inventory than either, and the union without
// provenance is a worse report than either. An operator reading a list acts on
// it, and what they do next depends entirely on which source named a host:
//
//   - A name only a log has is a host somebody obtained a certificate for. If
//     nothing answers it, the certificate is the thing to look at.
//   - A name only the records have is a host the domain publishes itself. It
//     may be plain HTTP, or a mail server that never needed a certificate.
//   - A name both have is the ordinary, well-kept case, and it is the one that
//     needs no time spent on it — which is worth as much in a report as a
//     finding is.
//
// Without the column a reader cannot tell those apart, and the list becomes
// forty names with nothing to sort them by.
//
// # What this does not decide
//
// Nothing here grades, drops or ranks a name. It is a merge: the names each
// source established, deduplicated, each carrying what named it and the window
// a log covered it in. Whether a name is worth acting on is the reader's, and
// no document says which names an estate ought to have (R21).
package inventory

import (
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
)

// Source is what named a host.
//
// Short, because it is a column beside every name in a report and a reader
// runs an eye down it. The long form of each is in the package that produced
// it.
type Source string

const (
	// FromCertificate: a publicly logged certificate covers it.
	FromCertificate Source = "certificate"

	// FromMX: the domain's mail is delivered to it.
	FromMX Source = "MX"

	// FromSPF: the domain's sender policy allows it to send as the domain.
	FromSPF Source = "SPF"

	// FromNS: it answers for the zone, and is under the domain itself.
	FromNS Source = "NS"
)

// order is the order sources are listed in beside one name.
//
// Fixed rather than the order they were read, so that two runs of the same
// inventory read the same and a difference between two reports is a difference
// in the estate.
var order = []Source{FromCertificate, FromMX, FromSPF, FromNS}

// Name is one host, everything that named it, and the window a log covered it
// in.
type Name struct {
	// Name is the host, folded and without its trailing dot.
	Name string `json:"name"`

	// Wildcard is whether it covers hosts without naming them. Only a
	// certificate carries one: no record names a wildcard host.
	Wildcard bool `json:"wildcard,omitempty"`

	// Sources are what named it, in a fixed order.
	Sources []Source `json:"sources"`

	// FirstSeen and LastSeen are the window the logs show it in, where a log
	// showed it at all. A name only the records named has neither, and a
	// report must not invent one for it (R17).
	FirstSeen time.Time `json:"firstSeen,omitempty"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

// Reading is what one source established.
//
// Kept per source rather than folded into one verdict, because a merged
// inventory with half its sources missing looks exactly like a complete one. A
// monitor that is down and a domain that publishes nothing produce the same
// empty list, and only this says which happened (R4).
type Reading struct {
	// Asked reports that the source was read at all.
	Asked bool `json:"asked"`

	// Named is how many of the names in the inventory this source named. A
	// name an MX and a sender policy both named is counted once: the question
	// a reader has is how much of the list this source is answerable for.
	Named int `json:"named"`

	// Foreign is how many names this source carried that belong to other
	// domains, and were therefore not listed.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// Established reports that this source was read and answered.
func (r Reading) Established() bool { return r.Asked && r.Reason == "" }

// Inventory is the names under one domain, from every source that was read.
type Inventory struct {
	// Domain is the domain asked about, folded.
	Domain string `json:"domain,omitempty"`

	// Names are the distinct hosts, sorted by name. An inventory is read by
	// looking for a name.
	Names []Name `json:"names,omitempty"`

	// Distinct is how many there are.
	Distinct int `json:"distinct"`

	// Wildcards is how many of them name no host, which is the measure of how
	// much a certificate log could not see.
	Wildcards int `json:"wildcards,omitempty"`

	// Certificates is how many distinct certificates were read.
	Certificates int `json:"certificates,omitempty"`

	// Truncated is set where a source found more than it listed.
	Truncated bool `json:"truncated,omitempty"`

	// Logs is what the certificate transparency monitor established, and
	// Records what the domain's own MX, sender policy and delegation did.
	Logs    Reading `json:"logs"`
	Records Reading `json:"records"`
}

// Established reports that at least one source was read and answered.
//
// The whole inventory is silence rather than an empty estate without it: an
// unreachable monitor and a resolver that answered nothing produce the same
// empty list as a domain with no names, and presenting that as an inventory is
// the most comfortable wrong answer this mode can give (R4).
func (i Inventory) Established() bool { return i.Logs.Established() || i.Records.Established() }

// Merge builds one inventory out of what each source said.
//
// The domain is passed rather than taken from either source, because a source
// that failed before it got anywhere carries no domain and the report is still
// about one.
func Merge(domain string, e ctsearch.Estate, d dnsnames.Found) Inventory {
	out := Inventory{
		Domain:       fold(domain),
		Certificates: e.Certificates,
		Truncated:    e.Truncated,
		Logs:         Reading{Asked: e.Asked, Foreign: e.Foreign, Reason: e.Reason},
		Records:      Reading{Asked: d.Asked, Foreign: d.Foreign, Reason: d.Reason},
	}
	if out.Domain == "" {
		out.Domain = fold(e.Domain)
	}

	found := map[string]*Name{}
	at := func(raw string) *Name {
		name := fold(raw)
		if name == "" {
			return nil
		}
		if n, seen := found[name]; seen {
			return n
		}
		n := &Name{Name: name}
		found[name] = n
		return n
	}

	for _, n := range e.Names {
		host := at(n.Name)
		if host == nil {
			continue
		}
		host.Sources = append(host.Sources, FromCertificate)
		host.Wildcard = host.Wildcard || n.Wildcard

		// The widest window any certificate covering it gives. A merge must
		// not narrow what one source established.
		if !n.FirstSeen.IsZero() && (host.FirstSeen.IsZero() || n.FirstSeen.Before(host.FirstSeen)) {
			host.FirstSeen = n.FirstSeen
		}
		if n.LastSeen.After(host.LastSeen) {
			host.LastSeen = n.LastSeen
		}
	}

	for _, n := range d.Names {
		host := at(n.Name)
		if host == nil {
			continue
		}
		for _, s := range n.Sources {
			host.Sources = append(host.Sources, sourceOf(s))
		}
	}

	for _, host := range found {
		host.Sources = sorted(host.Sources)
		if host.Wildcard {
			out.Wildcards++
		}

		fromLog := names(host, FromCertificate)
		if fromLog > 0 {
			out.Logs.Named++
		}
		if fromLog < len(host.Sources) {
			out.Records.Named++
		}
		out.Names = append(out.Names, *host)
	}

	out.Distinct = len(out.Names)
	sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Name < out.Names[j].Name })
	return out
}

// Hosts are the names something could resolve.
//
// A wildcard is left out because it is not a name: nothing resolves
// `*.example.com`, and putting it through a resolver would produce a failure
// that reads as a fault in the estate.
func (i Inventory) Hosts() []string {
	var out []string
	for _, n := range i.Names {
		if !n.Wildcard {
			out = append(out, n.Name)
		}
	}
	return out
}

// sourceOf is the short form of a record source.
//
// A source this does not know is carried through under its own name rather
// than dropped. A name is the thing a reader acts on, and losing one because a
// record type was added to the reader and not here would be the worst
// available way to find out (R4).
func sourceOf(s dnsnames.Source) Source {
	switch s {
	case dnsnames.FromMX:
		return FromMX
	case dnsnames.FromSPF:
		return FromSPF
	case dnsnames.FromNS:
		return FromNS
	}
	return Source(s)
}

// sorted puts one name's sources in the fixed order, dropping repeats.
//
// A source this does not know the order of goes after the ones it does, in the
// order it arrived, so an unknown source is last rather than lost.
func sorted(in []Source) []Source {
	var out []Source
	seen := map[Source]bool{}

	for _, want := range order {
		for _, s := range in {
			if s == want && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// names counts how many times one source named a host.
func names(n *Name, want Source) int {
	var count int
	for _, s := range n.Sources {
		if s == want {
			count++
		}
	}
	return count
}

// fold is one spelling of a name, so that two sources naming the same host
// produce one entry rather than two.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
