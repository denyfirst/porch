// Package liveness says whether a name answers right now.
//
// # Why a list of names is not an answer
//
// Every source of names is a record of the past. A certificate log holds names
// that were covered once, a passive register holds names somebody once looked
// up, and a zone holds whatever nobody has got round to deleting. Handed to an
// operator as an inventory, all three say the same misleading thing: that this
// is their estate.
//
// It usually is not. A name from five years ago, for a service that was shut
// down four years ago, is noise in a report somebody has to act on — and worse
// than noise, because time is spent establishing that it is nothing.
//
// So every name gets a status, and the status is about now: it answers, or it
// resolves and nothing answers, or it points somewhere nothing may dial, or it
// does not resolve at all. An operator reads the first column and knows what to
// do.
//
// # What is sent, and what is not
//
// One resolution per name, and at most one connection to each address that a
// resolution produced — opened and closed, carrying nothing. No request is
// made, no protocol is spoken, nothing is guessed: every name here came from a
// record that named it.
//
// An address nothing may dial is never dialled. That covers the private and
// reserved ranges, and it is the case that matters most in practice: a resolver
// inside an organisation answers its own names with internal addresses, so a
// scan run from a desk reports the inside while reading as though it had
// measured the outside. Here that is a status of its own rather than a timeout.
package liveness

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/safedial"
)

// Status is what a name is doing now.
type Status string

const (
	// Live: it resolves to an address anybody can reach, and something
	// answered there.
	Live Status = "live"

	// Silent: it resolves to a reachable address and nothing answered on any
	// port asked. The name is published and the service behind it is not
	// running, or is not on a port this looked at, or is firewalled to
	// somewhere other than here.
	Silent Status = "silent"

	// Internal: every address it resolves to is one nothing may dial —
	// private, loopback, link-local or reserved. From here it cannot be
	// measured, and what a resolver elsewhere would answer may differ.
	Internal Status = "internal"

	// Gone: it does not resolve. A name that a certificate once covered and
	// that nothing answers for is the ordinary state of an estate that has
	// been tidied, and it is the state a report should not present as a host.
	Gone Status = "gone"

	// Dangling: it is an alias, and the name it points at does not resolve.
	//
	// Reported as what it is and nothing more. Whether somebody else can claim
	// the target depends on what that target is and who runs it, which this
	// has not established and will not guess at (R17).
	Dangling Status = "dangling"

	// Unchecked: nothing was established, and the reason says why.
	Unchecked Status = "unchecked"
)

// Name is one name and what it is doing.
type Name struct {
	// Name is the name asked about.
	Name string `json:"name"`

	// Status is what it is doing now.
	Status Status `json:"status"`

	// Addresses are what it resolved to, in the order the resolver gave them.
	//
	// Kept because this is an operator reading their own estate, and the
	// address is the first thing they need to act: it says which machine, which
	// provider, and whether it is theirs at all.
	Addresses []netip.Addr `json:"addresses,omitempty"`

	// Alias is what a CNAME at the name points to, where the name is one.
	Alias string `json:"alias,omitempty"`

	// Answered are the ports that accepted a connection.
	Answered []string `json:"answered,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// Resolver is what this asks for addresses. internal/dnsclient.Client is the
// one there is.
type Resolver interface {
	LookupAddresses(ctx context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error)
}

// DialFunc matches net.Dialer.DialContext and safedial.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const (
	// defaultTimeout bounds one name: its lookups and its connections.
	defaultTimeout = 10 * time.Second

	// defaultParallel bounds how many names are in flight.
	//
	// An estate is tens to hundreds of names, and doing them one at a time
	// would make a report take minutes. Bounded so that a large estate does not
	// become a burst of connections nobody asked for — least of all the
	// operator, whose own firewall is watching.
	defaultParallel = 8

	// maxNames bounds an inventory. Past this the answer is about the size of
	// the estate rather than about any name in it.
	maxNames = 2000
)

// defaultPorts are the two a name is asked on.
//
// The two a browser uses, and no others. A port sweep is a different
// instrument: it guesses at services, which is the thing this project does not
// do, and it turns one connection per name into thousands.
var defaultPorts = []string{"443", "80"}

// Checker asks what a set of names is doing.
type Checker struct {
	// Resolver answers the lookups. Required: which resolver answers decides
	// what the report means, and one picked here would hide that.
	Resolver Resolver

	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	Dial DialFunc

	// Timeout bounds one name. Zero means ten seconds.
	Timeout time.Duration

	// Parallel bounds how many names are in flight. Zero means eight.
	Parallel int

	// Ports are the ports a name is asked on. Nil means 443 and 80.
	Ports []string
}

// Check says what each name is doing now.
//
// The answer is in the order the names were given, so that a caller which
// sorted them keeps its order and one that did not can still line the answer up
// with what it asked.
func (c *Checker) Check(ctx context.Context, names []string) []Name {
	if len(names) > maxNames {
		names = names[:maxNames]
	}

	out := make([]Name, len(names))
	var wg sync.WaitGroup
	slots := make(chan struct{}, c.parallel())

	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()

			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				out[i] = Name{Name: name, Status: Unchecked, Reason: "the scan ran out of time before this name was reached"}
				return
			}

			out[i] = c.one(ctx, name)
		}(i, name)
	}

	wg.Wait()
	return out
}

// one establishes what a single name is doing.
func (c *Checker) one(ctx context.Context, name string) Name {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	out := Name{Name: name, Status: Unchecked}
	if name == "" {
		out.Reason = "no name was given"
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	answer, err := c.Resolver.LookupAddresses(ctx, name, dnsclient.TypeA)
	if err != nil {
		// The shape of the failure only. A resolver names addresses and
		// internal types in its errors, and this reaches a report (I6).
		out.Reason = "the name could not be looked up"
		return out
	}
	addresses := answer.Addresses

	// The other family, asked separately, because a name may publish only one
	// and an estate that answers on IPv6 alone is one this must not call gone.
	if six, err := c.Resolver.LookupAddresses(ctx, name, dnsclient.TypeAAAA); err == nil {
		addresses = append(addresses, six.Addresses...)
		if len(six.Alias) > 0 && len(answer.Alias) == 0 {
			answer.Alias = six.Alias
		}
	}

	if len(answer.Alias) > 0 {
		out.Alias = strings.ToLower(strings.TrimSuffix(answer.Alias[0], "."))
	}

	out.Addresses = addresses
	if len(addresses) == 0 {
		// An alias whose target resolves to nothing is a different fact from a
		// name that simply does not exist, and the difference is the one an
		// operator acts on.
		if out.Alias != "" {
			out.Status = Dangling
			return out
		}
		out.Status = Gone
		return out
	}

	var reachable []netip.Addr
	for _, addr := range addresses {
		if safedial.CheckAddr(addr) == nil {
			reachable = append(reachable, addr)
		}
	}
	if len(reachable) == 0 {
		// Never dialled, and said as its own state rather than left to time
		// out. This is what an organisation's own resolver answers for its own
		// names, so a scan run from a desk inside it lands here — and a report
		// that said "nothing answered" would be describing the office network
		// as the state of the estate (R4).
		out.Status = Internal
		return out
	}

	for _, port := range c.ports() {
		if c.answers(ctx, reachable[0], port) {
			out.Answered = append(out.Answered, port)
		}
	}
	sort.Strings(out.Answered)

	if len(out.Answered) > 0 {
		out.Status = Live
	} else {
		out.Status = Silent
	}
	return out
}

// answers reports whether one address accepted a connection on one port.
//
// Opened and closed, carrying nothing. No protocol is spoken and no request is
// made: what is being established is that something is listening, which is the
// whole of what "live" claims.
func (c *Checker) answers(ctx context.Context, addr netip.Addr, port string) bool {
	conn, err := c.dial()(ctx, "tcp", net.JoinHostPort(addr.String(), port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *Checker) dial() DialFunc {
	if c.Dial != nil {
		return c.Dial
	}
	d := &safedial.Dialer{Timeout: c.timeout(), AllowedPorts: c.ports()}
	return d.DialContext
}

func (c *Checker) ports() []string {
	if len(c.Ports) > 0 {
		return c.Ports
	}
	return defaultPorts
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c *Checker) parallel() int {
	if c.Parallel > 0 {
		return c.Parallel
	}
	return defaultParallel
}
