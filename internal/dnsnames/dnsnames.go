// Package dnsnames reads the names a domain's own records already name.
//
// # The cheapest honest source there is
//
// A zone publishes host names in the course of doing ordinary things. An MX
// record names the machine that takes the mail. A sender policy names the hosts
// allowed to send it. A delegation names the servers that answer for the zone.
// None of that is hidden, none of it is guessed at, and a resolver hands it over
// to anybody who asks — which is what those records are for.
//
// So this is the first source to read and the last one anybody thinks of.
// Certificate logs and passive registers are third parties with their own
// coverage and their own gaps; these records are the domain's own statements
// about itself, they cost three lookups, and nothing but the domain's own
// resolver is asked.
//
// # What it does not do
//
// It does not follow a sender policy's includes. Those name other people's
// infrastructure almost every time — a mail provider, a marketing service — and
// walking them would turn three lookups into thirty to collect names that are
// then dropped for belonging to somebody else.
//
// It keeps only names under the domain asked about, on a label boundary.
// `ns8451.hostgator.com` answers for a zone without being part of the estate
// that zone describes, and putting it in an inventory somebody acts on would be
// this program drawing a boundary the records do not draw. Those are counted,
// so that a reader can see the question was asked.
package dnsnames

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// Source is the record that named a host.
type Source string

const (
	// FromMX is a mail exchanger: the machine that takes the domain's mail.
	FromMX Source = "MX record"

	// FromSPF is a host the domain's sender policy allows to send as it.
	FromSPF Source = "SPF record"

	// FromNS is a server that answers for the zone. Usually somebody else's,
	// and kept only where it is not.
	FromNS Source = "NS record"
)

// Name is one host a record named, and the record that named it.
type Name struct {
	// Name is the host, folded and without its trailing dot.
	Name string `json:"name"`

	// Sources are the records that named it, in the order they were read. A
	// host named by two records is one host with two reasons to exist, and
	// both are worth a reader's time: an exchanger that is also in the sender
	// policy is the ordinary arrangement, and one that is in neither is the
	// thing worth asking about.
	Sources []Source `json:"sources"`
}

// Found is what the domain's own records named.
type Found struct {
	// Asked reports that the records were read. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the hosts under this domain, sorted.
	Names []Name `json:"names,omitempty"`

	// Foreign is how many names these records carried that belong to other
	// domains, and were therefore not listed.
	//
	// A count rather than a list, for the reason the certificate inventory
	// keeps one: a mail provider's servers are evidence about the answer, not
	// part of the estate this describes.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established, where nothing was. Empty where
	// the records were read, including where they named nothing.
	Reason string `json:"reason,omitempty"`
}

// Resolver is what this asks. internal/dnsclient.Client is the one there is,
// and it is called from one goroutine at a time here.
type Resolver interface {
	LookupMX(ctx context.Context, name string) (dnsclient.MXAnswer, error)
	LookupTXT(ctx context.Context, name string) (dnsclient.TXTAnswer, error)
	LookupNS(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
}

const (
	defaultTimeout = 10 * time.Second

	// maxNames bounds what one domain's records may contribute. A sender
	// policy with a thousand mechanisms is a policy no mail server evaluates
	// either.
	maxNames = 200
)

// Reader reads a domain's own records for the names in them.
type Reader struct {
	// Resolver answers the lookups. Required: which resolver answers decides
	// what the answer means.
	Resolver Resolver

	// Timeout bounds all three lookups together. Zero means ten seconds.
	Timeout time.Duration
}

// Under reads what a domain's own records name.
//
// Three lookups, and a failure in one does not lose the other two: a domain
// with no MX still has a sender policy worth reading, and reporting nothing
// because one record type was unavailable would be throwing away what was
// established to report what was not.
func (r *Reader) Under(ctx context.Context, domain string) Found {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	out := Found{Asked: true}
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	found := map[string][]Source{}
	var foreign int

	keep := func(raw string, source Source) {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if name == "" || name == "." || name == domain {
			// The domain itself is not a discovery, and a null MX is a
			// statement rather than a host.
			return
		}
		if !under(name, domain) {
			foreign++
			return
		}
		if len(found) >= maxNames {
			return
		}
		for _, had := range found[name] {
			if had == source {
				return
			}
		}
		found[name] = append(found[name], source)
	}

	var reached bool

	if answer, err := r.Resolver.LookupMX(ctx, domain); err == nil {
		reached = true
		for _, mx := range answer.Records {
			keep(mx.Host, FromMX)
		}
	}

	if answer, err := r.Resolver.LookupTXT(ctx, domain); err == nil {
		reached = true
		for _, value := range answer.Values {
			for _, name := range senderPolicyNames(value) {
				keep(name, FromSPF)
			}
		}
	}

	if answer, err := r.Resolver.LookupNS(ctx, domain); err == nil {
		reached = true
		for _, ns := range answer.NS {
			keep(ns, FromNS)
		}
	}

	if !reached {
		// Every lookup failed, which is a fact about the resolver rather than
		// about the domain. Saying the records named nothing would be the
		// reassuring wrong answer (R4).
		return Found{Asked: true, Reason: "the domain's own records could not be read"}
	}

	out.Foreign = foreign
	for name, sources := range found {
		out.Names = append(out.Names, Name{Name: name, Sources: sources})
	}
	sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Name < out.Names[j].Name })
	return out
}

// senderPolicyNames pulls the host names out of one sender policy record.
//
// The mechanisms that carry a name, and no others. A policy is a list of terms
// and most of them are not names: `ip4:` and `ip6:` carry addresses, `all` is a
// verdict, and the qualifiers in front of any of them say what happens rather
// than where.
//
// The includes are read for the name they carry and not followed. Following
// them would turn three lookups into thirty, and what they name is almost
// always somebody else's infrastructure — which this drops anyway.
func senderPolicyNames(record string) []string {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
		return nil
	}

	var out []string
	for _, term := range strings.Fields(record) {
		// A qualifier sits in front of a mechanism and says what happens when
		// it matches, which is not a question about names.
		term = strings.TrimLeft(term, "+-~?")

		name, ok := policyName(term)
		if ok && name != "" {
			out = append(out, name)
		}
	}
	return out
}

// policyName is the name one term carries, where it carries one.
func policyName(term string) (string, bool) {
	lower := strings.ToLower(term)

	for _, prefix := range []string{"include:", "a:", "mx:", "exists:", "ptr:", "redirect="} {
		if strings.HasPrefix(lower, prefix) {
			value := term[len(prefix):]
			// A mechanism may carry a prefix length — `a:example.com/24` —
			// which is about addresses rather than about the name.
			if i := strings.Index(value, "/"); i >= 0 {
				value = value[:i]
			}
			return value, true
		}
	}
	return "", false
}

// under reports whether a name belongs to the domain asked about.
//
// The same label boundary the certificate inventory draws, and for the same
// reason: `notexample.com` ends with `example.com` as text and is a different
// estate. A wrong name in an inventory is worse than a missing one.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func (r *Reader) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}
