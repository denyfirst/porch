// Package nsecnames reads the names a signed zone hands out by proving what
// does not exist.
//
// # The source that is public and nobody notices
//
// A zone signed with DNSSEC has to be able to prove that a name does not
// exist, and the plain way of doing it is NSEC: at every name the zone holds,
// a record naming the next name in it (RFC 4034 §4). A resolver asking about a
// name that is absent gets one of these back, and it names two real hosts in
// order to do it.
//
// Follow them from the apex and the zone lists itself. Nothing is guessed,
// nothing is tried, and every name comes out of a record the zone published
// and serves to anybody who asks — which is exactly why RFC 5155 added NSEC3,
// and why the DNS check in this project already reports a signed zone without
// NSEC3PARAM as one that can be walked. Until now it reported that and offered
// no way to see what it exposes, which is a warning with nothing to do about
// it: the same gap the zone-transfer note had before internal/zonenames.
//
// # Whose zone may be walked
//
// The asker's own. Reading somebody else's estate out of their negative
// answers is enumeration however public each record is, and the rule is the
// one internal/zonenames takes: a service walks a domain it has been shown
// control of, and the command line walks one an operator says is theirs.
//
// # What it costs, and what it cannot do
//
// One query per name in the zone, to the resolver the rest of the mode already
// uses. That is the honest cost and it is why the bounds below are what they
// are. A zone using NSEC3 cannot be walked this way at all, which is the point
// of NSEC3 — and an unsigned zone has no NSEC records to follow, so the
// commonest answer here is that there is nothing to read.
package nsecnames

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

const (
	// defaultTimeout bounds the whole walk, every query in it.
	defaultTimeout = 60 * time.Second

	// maxNames bounds what one zone may contribute, and with it the walk.
	//
	// One bound rather than two, and that is the result of an investigation
	// rather than an omission. A second bound on the number of questions was
	// written here first, against a zone that answers every query with a name
	// this walk has already seen — and it was unreachable. Every turn of the
	// loop either adds a name nobody has seen, which counts against this, or
	// meets one that has been seen and returns. There is no path that asks a
	// question without doing one of the two.
	//
	// It is gone rather than kept for safety, because a bound that cannot fire
	// is a line that reads as protection and provides none — and the next
	// person to change the loop would have believed it.
	maxNames = 20000

	// maxName is the longest a name may be, from RFC 1035.
	maxName = 253
)

// Found is what a zone's own absence proofs listed.
type Found struct {
	// Asked reports that a walk was tried. Everything below is silence rather
	// than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the hosts the walk passed through, folded and sorted.
	Names []string `json:"names,omitempty"`

	// Wildcards is how many of the names the zone holds are wildcards.
	//
	// Counted rather than listed, because nothing resolves `*.example.com` and
	// putting it in a list of hosts would produce a lookup that fails and
	// reads as a fault in the estate. It is worth counting because a wildcard
	// in the walk says the same thing a wildcard certificate says: there are
	// hosts here this list does not name.
	Wildcards int `json:"wildcards,omitempty"`

	// Foreign is how many names the walk reached that are not under the domain
	// asked about. A walk that leaves the zone is a delegation or a broken
	// chain of next names, and it stops there.
	Foreign int `json:"foreign,omitempty"`

	// Truncated is set where the walk was stopped at a bound rather than
	// because it came round to the apex.
	Truncated bool `json:"truncated,omitempty"`

	// Reason says why nothing was established, where nothing was. A zone using
	// NSEC3, an unsigned zone and a resolver that would not answer are three
	// different nothings and a reader has to be able to tell them apart.
	Reason string `json:"reason,omitempty"`
}

// Resolver is the one question this needs.
type Resolver interface {
	LookupNSEC(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
}

// Reader walks a zone's absence proofs.
type Reader struct {
	// Resolver asks the questions. Required.
	Resolver Resolver

	// Timeout bounds the whole walk.
	Timeout time.Duration
}

// Under walks the zone from its apex and returns the names it passed through.
//
// The walk is the zone's own ordering: each NSEC record names the next name,
// and the last one names the apex, which is how it knows it has come round. A
// zone that never comes round is stopped at a bound and says so.
func (r *Reader) Under(ctx context.Context, domain string) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}
	if r == nil || r.Resolver == nil {
		return Found{Asked: true, Reason: "nothing here can ask for an absence proof"}
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	// The apex first. Its own record is the start of the chain, and its
	// absence is the answer for most zones: one that is not signed publishes
	// none, and one that uses NSEC3 publishes the hashed kind instead.
	first, err := r.Resolver.LookupNSEC(ctx, domain)
	if err != nil {
		return Found{Asked: true, Reason: "the zone's absence proofs could not be read"}
	}
	if len(first.NSEC) == 0 {
		return Found{Asked: true, Reason: "this zone publishes no plain absence proofs, so there " +
			"is no chain to follow: it is either unsigned or uses the hashed kind"}
	}

	out := Found{Asked: true}
	seen := map[string]bool{domain: true}

	next := fold(clean(first.NSEC[0].Next))
	for {
		switch {
		case next == "" || next == domain:
			// Come round to the apex, which is where a whole zone ends.
			sort.Strings(out.Names)
			return out

		case len(seen) >= maxNames:
			out.Truncated = true
			sort.Strings(out.Names)
			return out

		case !under(next, domain):
			// Off the end of the zone. A chain that leaves the domain is a
			// delegation or a zone that is answering for something else, and
			// following it would put another estate's names in this report.
			out.Foreign++
			sort.Strings(out.Names)
			return out

		case seen[next]:
			// A name already passed through. The chain is not advancing, so
			// there is no more of it to read and the list is what it is.
			out.Truncated = true
			sort.Strings(out.Names)
			return out
		}

		seen[next] = true
		if strings.HasPrefix(next, "*.") {
			// Nothing resolves a wildcard, so it is counted rather than listed
			// — and it is counted because it says there are hosts here the
			// list does not name.
			out.Wildcards++
		} else {
			out.Names = append(out.Names, next)
		}

		answer, err := r.Resolver.LookupNSEC(ctx, next)
		if err != nil || len(answer.NSEC) == 0 {
			// The chain stops here. Not a failure of the walk: a name may have
			// gone between one query and the next, and what was read is read.
			// It is cut rather than complete, and says so.
			out.Truncated = true
			sort.Strings(out.Names)
			return out
		}
		next = fold(clean(answer.NSEC[0].Next))
	}
}

// under reports whether a name belongs to the zone being walked.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// fold is one spelling of a name, so that a name from here and a name from
// another source are one entry.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// clean bounds a name and strips what no name may carry.
//
// The next name comes out of a record served by whoever runs the zone, which
// on a walk of the asker's own estate is the asker — and on any other is not.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxName {
		s = s[:maxName]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (r *Reader) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}
