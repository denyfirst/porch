// Package ptrnames reads the names the operator's own addresses answer to.
//
// # The source that starts from the estate's other half
//
// Every other source starts from a name. This one starts from an address
// range the operator says is theirs and asks what each address answers to,
// which finds a host from the other direction: a machine whose name is in no
// certificate, in no record the domain publishes, and in no register, but
// whose reverse record its own network kept up to date.
//
// It is also the source that most needs saying out loud what it is *not*. It
// is not a scan: nothing is sent to any of the addresses, and the only
// questions are reverse lookups to the resolver this installation already
// asks about everything else. It invents no name — a reverse record is a name
// somebody published for that address (N7).
//
// # Why the range has to be named, and why it is small
//
// Nothing here can establish that a range belongs to whoever asked. A domain
// can be proven with a record in its zone; an address range cannot, not by
// anything this project can check. So the range is typed by the operator on
// their own machine, and this is **not offered by the service at all** —
// a service answering it would be a reverse-scanner for whoever asked, which
// is the thing the whole inventory endpoint exists not to be.
//
// The bound follows from the same place. A /16 is sixty-five thousand
// questions to somebody's resolver, which is a burst nobody asked for and
// which is how an operator gets rate-limited off their own DNS. Anything
// larger than the bound is refused rather than cut: a quietly shortened answer
// is the one thing an inventory must never produce (R4).
package ptrnames

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// Found is what the addresses answered to.
type Found struct {
	// Asked reports that the ranges were read. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the hosts under the domain, folded and sorted.
	Names []string `json:"names,omitempty"`

	// Addresses is how many were asked and Answered how many had a reverse
	// record at all. Both, because the difference is the shape of the range:
	// a /24 with four answers is four machines and two hundred and fifty-two
	// addresses nobody has named.
	Addresses int `json:"addresses"`
	Answered  int `json:"answered"`

	// Foreign is how many reverse records named a host under another domain.
	// Counted rather than listed, as everywhere else: a provider's own name
	// for a leased address is evidence about the answer rather than part of
	// this estate.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// Resolver is what this asks. internal/dnsclient.Client is the one there is,
// and it is called from several goroutines at once.
type Resolver interface {
	LookupPTR(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
}

const (
	// defaultTimeout bounds one address.
	defaultTimeout = 5 * time.Second

	// defaultParallel bounds how many addresses are in flight.
	//
	// The pace internal/liveness keeps. A resolver answering a burst of
	// reverse lookups from one client is a resolver that starts refusing
	// them, and the operator's own is usually the one being asked.
	defaultParallel = 8

	// maxAddresses bounds one run: every range together.
	//
	// Four thousand and ninety-six, which is sixteen /24s, and past it the
	// answer is refused rather than cut. An operator with more than that to
	// inventory has a range their provider can list for them, and a list is a
	// better source than four times as many questions.
	maxAddresses = 4096

	// smallestIPv4, smallestIPv6 are the widest prefixes that may be walked.
	//
	// IPv6 is the sharper limit and the reason one exists at all: a /64 is
	// eighteen quintillion addresses, so walking one is not slow, it is
	// impossible, and a tool that accepted the flag and then ran for a week
	// would be lying about what it does.
	smallestIPv4 = 20
	smallestIPv6 = 116
)

// Reader walks the ranges an operator named.
type Reader struct {
	// Resolver answers the lookups. Required: which resolver answers decides
	// what the report means, and a reverse zone is often answered by the
	// operator's own.
	Resolver Resolver

	// Timeout bounds one address. Zero means five seconds.
	Timeout time.Duration

	// Parallel bounds how many addresses are in flight. Zero means eight.
	Parallel int
}

// Under asks every address in the ranges what it answers to, and keeps the
// names under the domain.
func (r *Reader) Under(ctx context.Context, domain string, ranges []netip.Prefix) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}
	if len(ranges) == 0 {
		return Found{}
	}

	addresses, err := Addresses(ranges)
	if err != nil {
		return Found{Asked: true, Reason: err.Error()}
	}

	out := Found{Asked: true, Addresses: len(addresses)}
	if len(addresses) == 0 {
		return out
	}

	answers := make([][]string, len(addresses))
	slots := make(chan struct{}, r.parallel())
	var wg sync.WaitGroup

	for i, addr := range addresses {
		wg.Add(1)
		go func(i int, addr netip.Addr) {
			defer wg.Done()

			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}

			answers[i] = r.one(ctx, addr)
		}(i, addr)
	}
	wg.Wait()

	found := map[string]bool{}
	for _, names := range answers {
		if len(names) == 0 {
			continue
		}
		out.Answered++

		for _, raw := range names {
			name := fold(clean(raw))
			if name == "" {
				continue
			}
			if !under(name, domain) {
				out.Foreign++
				continue
			}
			found[name] = true
		}
	}

	for name := range found {
		out.Names = append(out.Names, name)
	}
	sort.Strings(out.Names)
	return out
}

// one asks a single address what it answers to.
func (r *Reader) one(ctx context.Context, addr netip.Addr) []string {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	answer, err := r.Resolver.LookupPTR(ctx, Reverse(addr))
	if err != nil {
		return nil
	}
	return answer.PTR
}

// Addresses is every address in the ranges, refused where there are too many.
//
// Exported because the refusal is worth making before anything is asked: an
// operator who typed a /16 finds out when they press return rather than after
// sixty-five thousand questions have gone to their resolver.
func Addresses(ranges []netip.Prefix) ([]netip.Addr, error) {
	var out []netip.Addr

	for _, p := range ranges {
		if !p.IsValid() {
			return nil, fmt.Errorf("that is not an address range")
		}
		p = p.Masked()

		smallest := smallestIPv4
		if p.Addr().Is6() {
			smallest = smallestIPv6
		}
		if p.Bits() < smallest {
			return nil, fmt.Errorf("a range wider than /%d is more questions than a resolver should be asked; name a narrower one", smallest)
		}

		for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
			if len(out) >= maxAddresses {
				return nil, fmt.Errorf("the ranges hold more than %d addresses between them, which is refused rather than cut short", maxAddresses)
			}
			out = append(out, addr)
			if !addr.Next().IsValid() {
				break
			}
		}
	}
	return out, nil
}

// Reverse is the name an address is asked about under.
//
// `4.3.2.1.in-addr.arpa` for IPv4, and the nibble form under `ip6.arpa` for
// IPv6, which is RFC 3596 §2.5 and is the only form a resolver answers.
func Reverse(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}

	b := addr.As16()
	var name strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&name, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	name.WriteString("ip6.arpa")
	return name.String()
}

// under reports whether a name belongs to the domain asked about.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// fold is one spelling of a name, so that two sources naming one host produce
// one entry.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// clean bounds a name and strips what no name may carry.
//
// A reverse record is written by whoever runs the address, which in a leased
// range is not the operator reading the report.
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

func (r *Reader) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}

func (r *Reader) parallel() int {
	if r.Parallel > 0 {
		return r.Parallel
	}
	return defaultParallel
}
