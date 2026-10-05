// Package dmarcreports reads where a DMARC record asks for its reports, and
// asks whether the places it names have agreed to receive them.
//
// # Why the addresses are read rather than counted
//
// A DMARC record's rua= tag is how a domain finds out who is sending as it.
// Until 2026-09-28 this project reduced the tag to a boolean — reports are
// asked for, or they are not — and that threw away the two things an operator
// most needs to know about it.
//
// The first is plain: where the reports go. A tag pointing at an analytics
// vendor the domain stopped paying, or at the mailbox of somebody who has
// left, is reporting that exists on paper.
//
// The second is a measurement that cannot be made at all without the value,
// and it is the reason this package exists. RFC 7489 §7.1 says that when a
// report destination is outside the domain being reported on, the receiver
// must not send anything there until the destination has said it will accept
// it — by publishing a DMARC record at
//
//	<domain-being-reported-on>._report._dmarc.<destination-domain>
//
// A domain that points rua= at a vendor and never has that record published
// gets no reports at all, while its record says it asked for them. Nothing in
// the domain's own DNS looks wrong. It is the exact shape of fault this
// project exists to find: a correct-looking configuration that does nothing.
//
// # What it sends
//
// One TXT lookup per distinct external destination domain, to the resolver the
// rest of the check already uses. Nothing is sent to the destination, no mail
// is composed, and the addresses are not contacted in any way.
package dmarcreports

import (
	"context"
	"sort"
	"strings"

	"github.com/denyfirst/porch/internal/display"
)

const (
	// maxDestinations bounds how many report addresses one record may name.
	//
	// RFC 7489 sets no limit. A record naming forty is not a domain receiving
	// forty sets of reports, and each external one here is a DNS lookup, so
	// the ones past this are counted rather than followed.
	maxDestinations = 8

	// maxURI bounds one URI before it is parsed. The record is written by
	// whoever is being measured.
	maxURI = 253 + 64 + 16

	// reportPrefix is the label RFC 7489 §7.1 puts the authorisation under.
	reportPrefix = "_report._dmarc."
)

// Destination is one place a record asks for reports.
type Destination struct {
	// Domain is where the reports would go. Always present for a destination
	// this package understood, and it is the part a report may always name: a
	// domain is not a person.
	Domain string `json:"domain"`

	// Mailbox is the address in full, where the caller asked for it.
	//
	// Empty where it was withheld rather than absent, which is why Kind exists
	// beside it: a reader must not have to tell "no mailbox" from "a mailbox
	// this deployment does not print" by the emptiness of a field (R4).
	Mailbox string `json:"mailbox,omitempty"`

	// Kind is the URI scheme, folded. RFC 7489 §6.2 defines mailto: and leaves
	// room for others; anything else is carried through as what it said rather
	// than dropped, because a destination this package does not understand is
	// still a destination the domain named.
	Kind string `json:"kind,omitempty"`

	// External reports that the destination is outside the domain being
	// reported on, which is what brings §7.1 into it.
	External bool `json:"external,omitempty"`

	// Checked reports that the authorisation record was looked for, and
	// Authorised what was found. Both are meaningless for a destination that
	// is not external, and Checked is false where the lookup did not happen —
	// which is not the same as a destination that refused (R4).
	Checked    bool `json:"checked,omitempty"`
	Authorised bool `json:"authorised,omitempty"`

	// Reason says why the authorisation could not be established, where it
	// could not. A resolver that would not answer is not a destination that
	// declined.
	Reason string `json:"reason,omitempty"`
}

// Found is what a record's rua= tag named.
type Found struct {
	// Asked reports that a tag was read at all.
	Asked bool `json:"asked"`

	// Destinations are the places named, in the order the record gave them.
	Destinations []Destination `json:"destinations,omitempty"`

	// Dropped is how many the record named past the bound, or in a form this
	// package could not read as a URI at all.
	Dropped int `json:"dropped,omitempty"`
}

// Resolver is the one lookup this needs.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) (values []string, err error)
}

// Read parses a rua= tag into the places it names.
//
// domain is the domain the record belongs to, and it decides one thing: which
// destinations are somebody else's. Nothing is looked up here; Verify does
// that, so that a caller with no resolver still gets the list.
func Read(domain, tag string) Found {
	domain = fold(domain)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return Found{}
	}

	out := Found{Asked: true}
	for _, raw := range strings.Split(tag, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if len(raw) > maxURI {
			out.Dropped++
			continue
		}
		if len(out.Destinations) >= maxDestinations {
			out.Dropped++
			continue
		}

		// RFC 7489 §6.2 allows a maximum report size after the URI, written
		// as an exclamation mark and a size. It is not part of the address.
		uri, _, _ := strings.Cut(raw, "!")

		kind, rest, ok := strings.Cut(uri, ":")
		if !ok {
			// A bare address is not what the tag takes, and guessing that it
			// meant mailto: would be this package inventing a destination.
			out.Dropped++
			continue
		}
		kind = fold(kind)
		rest = strings.TrimSpace(rest)

		at := destinationOf(kind, rest)
		if !isHostname(at) {
			out.Dropped++
			continue
		}

		d := Destination{Domain: at, Kind: kind, External: !under(at, domain)}
		if kind == "mailto" {
			d.Mailbox = clean(rest)
		}
		out.Destinations = append(out.Destinations, d)
	}
	return out
}

// destinationOf is the domain a URI points at.
// isHostname accepts what can be a host's name and nothing else.
//
// The destination is asked about in DNS and repeated in the report, and until
// 2026-10-05 it was neither checked nor marked: a tag of "http:" followed by an
// escape sequence reached the command line's terminal as a domain, acting on
// it (audit 2026-10-05, F6). The record is often a reporting provider's, behind
// a CNAME at _dmarc. A name that is not one is a destination this cannot read,
// so it is counted with the others it could not.
func isHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

func destinationOf(kind, rest string) string {
	switch kind {
	case "mailto":
		_, host, ok := strings.Cut(rest, "@")
		if !ok {
			return ""
		}
		return fold(host)
	case "https", "http":
		host := strings.TrimPrefix(rest, "//")
		host, _, _ = strings.Cut(host, "/")
		host, _, _ = strings.Cut(host, "?")
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		return fold(host)
	default:
		return ""
	}
}

// Verify asks each external destination whether it has agreed to receive
// reports for this domain, as RFC 7489 §7.1 requires a receiver to.
//
// One lookup per distinct external domain rather than per destination: two
// addresses at one vendor are authorised by one record, and asking twice would
// be two questions for one answer.
//
// A destination inside the domain is left alone. §7.1 exists because a domain
// cannot volunteer somebody else's mailbox to receive its mail; it does not
// apply where the domain is naming itself.
func Verify(ctx context.Context, r Resolver, domain string, found Found) Found {
	if r == nil || !found.Asked {
		return found
	}
	domain = fold(domain)

	type answer struct {
		authorised bool
		reason     string
	}
	asked := map[string]answer{}

	out := found
	out.Destinations = make([]Destination, len(found.Destinations))
	copy(out.Destinations, found.Destinations)

	for i := range out.Destinations {
		d := &out.Destinations[i]
		if !d.External {
			continue
		}

		got, seen := asked[d.Domain]
		if !seen {
			values, err := r.LookupTXT(ctx, domain+"."+reportPrefix+d.Domain)
			switch {
			case err != nil:
				// A resolver that would not answer is not a destination that
				// declined, and the two send an operator to opposite places
				// (R4). The reason names no resolver and no address (I6).
				got = answer{reason: "the authorisation record could not be read"}
			default:
				got = answer{authorised: authorises(values)}
			}
			asked[d.Domain] = got
		}

		d.Checked = true
		d.Authorised = got.authorised
		d.Reason = got.reason
	}
	return out
}

// Unauthorised are the external destinations that will receive nothing, as
// distinct from the ones nothing could be established about.
//
// Sorted and deduplicated, because the sentence a report writes from this
// names domains and a vendor named twice is one vendor.
func (f Found) Unauthorised() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range f.Destinations {
		if d.External && d.Checked && d.Reason == "" && !d.Authorised && !seen[d.Domain] {
			seen[d.Domain] = true
			out = append(out, d.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// Unread are the external destinations whose authorisation could not be
// established, which is silence rather than a refusal.
func (f Found) Unread() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range f.Destinations {
		if d.External && d.Reason != "" && !seen[d.Domain] {
			seen[d.Domain] = true
			out = append(out, d.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// WithoutMailboxes drops the addresses and keeps everything else.
//
// A domain is not a person and a mailbox is, so a deployment that scans names
// nobody proved anything about reports where the reports go without carrying
// somebody's address into a report a stranger asked for. Everything the
// finding rests on survives: the destination's domain, whether it is external,
// and whether it has agreed.
func (f Found) WithoutMailboxes() Found {
	out := f
	out.Destinations = make([]Destination, len(f.Destinations))
	copy(out.Destinations, f.Destinations)
	for i := range out.Destinations {
		out.Destinations[i].Mailbox = ""
	}
	return out
}

// authorises reports whether a record at the §7.1 name agrees.
//
// RFC 7489 §7.1 asks for "a valid DMARC record" there, and in practice the
// record published is the minimum one: v=DMARC1. Anything announcing itself as
// DMARC is taken as agreement, because the tags after it describe the
// reporting relationship rather than qualifying it.
func authorises(values []string) bool {
	for _, v := range values {
		if strings.HasPrefix(fold(strings.TrimSpace(v)), "v=dmarc1") {
			return true
		}
	}
	return false
}

// under reports whether a destination belongs to the domain reporting on
// itself.
//
// RFC 7489 §7.1 says "the same domain". Receivers differ on whether a
// subdomain counts, and the two readings fail in opposite directions: the
// strict one reports a fault at domains that have none, the loose one misses
// one. This takes the loose reading — a subdomain of the domain is not
// external — because a scanner that invents a finding is worse than one that
// reports fewer, and the note beside it says which reading was taken (R17).
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func fold(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// clean bounds an address and strips what no address may carry.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxURI {
		s = s[:maxURI]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	// And what C0 does not cover: C1, which terminals read as CSI, and the
	// format characters that make a reader misread (R10).
	return display.Mark(b.String())
}
