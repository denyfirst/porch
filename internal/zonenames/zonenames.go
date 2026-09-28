// Package zonenames reads the names a zone hands over when it is asked for
// itself.
//
// # The only source that is complete, and the one that usually refuses
//
// Every other source of names is a sample. A certificate log holds what
// somebody obtained a certificate for; a domain's own records hold the hosts
// its mail and delegation have to name; a passive register holds what resolvers
// happened to see; a reverse record names one address. A zone transfer holds
// the zone: every name in it, from the server that is authoritative for them,
// with nothing guessed and nothing inferred.
//
// It is also the source that almost always says no. A zone is handed to the
// secondaries its operator named and to nobody else, which is correct — the
// DNS check in this project reports a zone that transfers to anybody as a
// finding. So this is for the operator who can open a transfer to their own
// installation, or who runs the name server themselves, and for everybody else
// it is a line in the report saying the servers refused.
//
// # Whose zone may be read
//
// Only the asker's own. internal/dnsclient.AskTransfer, which the DNS check
// uses, deliberately reads no records at all: the zone belongs to the scanned
// party and a scanner holding one would be the thing it warns about. Reading
// is different, and it is allowed on one condition — the estate is the
// reader's. A service asks only about a domain it has been shown control of,
// and the command line asks only when an operator passes the flag that says
// this zone is mine.
//
// # What it sends
//
// One question of type AXFR, over TCP, to a server the zone itself names. It
// stops at the first server that answers with the zone: a transfer that
// succeeded is the zone, and asking the other three for the same list would be
// three more transfers for nothing.
package zonenames

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// Found is what a zone handed over.
type Found struct {
	// Asked reports that a transfer was tried. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the hosts in the zone, folded and sorted.
	Names []string `json:"names,omitempty"`

	// Servers is how many name servers were asked and Refused how many
	// declined. A zone where every server refused is the ordinary, correct
	// case, and the report says so rather than leaving a reader to wonder
	// whether the question was put.
	Servers int `json:"servers"`
	Refused int `json:"refused"`

	// From is the server that handed the zone over, where one did.
	From string `json:"from,omitempty"`

	// Foreign is how many names the zone carried that are not under the
	// domain asked about. A zone holding another domain's records is
	// unusual and is counted rather than listed, as everywhere else here.
	Foreign int `json:"foreign,omitempty"`

	// Truncated is set where the transfer was cut at a bound.
	Truncated bool `json:"truncated,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// Resolver finds the servers a zone names and where they are.
// internal/dnsclient.Client is the one there is.
type Resolver interface {
	LookupNS(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupAddresses(ctx context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error)
}

// Transferer asks one server for a whole zone.
type Transferer interface {
	Transfer(ctx context.Context, server, zone string) (names []string, truncated bool, err error)
}

const (
	// defaultTimeout bounds the whole attempt, every server in it.
	defaultTimeout = 30 * time.Second

	// maxServers bounds how many of a zone's servers are asked.
	//
	// A zone names two to four. More than this is a zone whose delegation is
	// the finding, and asking twelve servers for the same refusal is twelve
	// connections for one answer.
	maxServers = 6

	// maxNames bounds what one zone may contribute, past the bound the
	// transfer itself already applies.
	maxNames = 20000
)

// Reader asks a zone for itself.
type Reader struct {
	// Resolver finds the servers to ask. Required.
	Resolver Resolver

	// Transfer asks one of them for the zone. Nil uses the resolver, where it
	// can do both — internal/dnsclient.Client can.
	Transfer Transferer

	// Timeout bounds the whole attempt.
	Timeout time.Duration
}

// Under asks the zone's own servers for the zone.
func (r *Reader) Under(ctx context.Context, domain string) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}

	transfer := r.transferer()
	if transfer == nil {
		return Found{Asked: true, Reason: "nothing here can ask for a zone transfer"}
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	delegation, err := r.Resolver.LookupNS(ctx, domain)
	if err != nil || len(delegation.NS) == 0 {
		// Not "the zone refused": nobody was asked. A domain whose delegation
		// cannot be read is a fact about the lookup rather than about the zone
		// (R4).
		return Found{Asked: true, Reason: "the servers this zone is delegated to could not be read"}
	}

	out := Found{Asked: true}
	for i, server := range delegation.NS {
		if i >= maxServers {
			break
		}
		server = fold(server)
		if server == "" {
			continue
		}
		out.Servers++

		for _, address := range r.addresses(ctx, server) {
			names, truncated, err := transfer.Transfer(ctx, address, domain)
			switch {
			case errors.Is(err, dnsclient.ErrNoTransfer):
				// The ordinary answer, and the correct one. Counted per
				// server rather than per address: a server that refuses on
				// one address refuses.
				out.Refused++

			case err != nil:
				// Unreachable, or an answer this does not read. Try the next
				// address, then the next server: one broken server is not a
				// zone that will not transfer.
				continue

			default:
				out.From = server
				out.Truncated = truncated
				out.keep(names, domain)
				return out
			}
			break
		}
	}

	if out.Servers == 0 {
		return Found{Asked: true, Reason: "the servers this zone is delegated to could not be read"}
	}
	return out
}

// keep takes the names a transfer produced.
//
// Everything a server sends is untrusted, whoever runs it: folded, bounded,
// stripped of what no name may carry, and held to the label boundary. A zone
// that carries another domain's records is counted rather than listed.
func (f *Found) keep(names []string, domain string) {
	found := map[string]bool{}

	for _, raw := range names {
		name := fold(clean(raw))
		if name == "" || name == domain {
			// The zone's own apex arrives on every record in it; it is the
			// domain that was asked about rather than something found.
			continue
		}
		if !under(name, domain) {
			f.Foreign++
			continue
		}
		if found[name] {
			continue
		}
		if len(found) >= maxNames {
			f.Truncated = true
			break
		}
		found[name] = true
	}

	for name := range found {
		f.Names = append(f.Names, name)
	}
	sort.Strings(f.Names)
}

// addresses are where one name server can be reached.
func (r *Reader) addresses(ctx context.Context, server string) []string {
	var out []string
	for _, qtype := range []uint16{dnsclient.TypeA, dnsclient.TypeAAAA} {
		answer, err := r.Resolver.LookupAddresses(ctx, server, qtype)
		if err != nil {
			continue
		}
		for _, addr := range answer.Addresses {
			out = append(out, net.JoinHostPort(addr.String(), "53"))
			if len(out) >= 4 {
				return out
			}
		}
	}
	return out
}

// under reports whether a name belongs to the zone asked about.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// fold is one spelling of a name, so that two sources naming one host produce
// one entry.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// clean bounds a name and strips what no name may carry.
func clean(s string) string {
	const maxName = 253

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

func (r *Reader) transferer() Transferer {
	if r.Transfer != nil {
		return r.Transfer
	}
	if t, ok := r.Resolver.(Transferer); ok {
		return t
	}
	return nil
}

func (r *Reader) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}
