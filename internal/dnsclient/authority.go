package dnsclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Authority reads a name from the servers that hold it, reached from the root,
// and asks no resolver on the way.
//
// # Why a proof of control needs it
//
// Verification read the challenge record through this machine's resolver, or
// the one -resolver named, and took its answer as the zone's. A resolver says
// whatever it is configured to say. On 2026-09-29 a resolver started on the
// same server as a proven installation answered for a domain nobody there
// controlled, carrying the token that installation expected, and the domain was
// scanned. A resolver somebody else runs — one handed out by DHCP, one whose
// cache was poisoned, one on a path an attacker sits on — can do the same for
// whoever uses the installation. The record is the proof, and the proof was
// only as good as the most convenient server to forge it.
//
// So the challenge is read from the zone's own servers. The walk starts at the
// root servers, whose addresses are carried in this binary, follows each
// delegation down to the servers that hold the zone, and asks them. A resolver
// is not consulted at all; what it would have said does not matter.
//
// # How it asks
//
// One label at a time (RFC 9156, query name minimisation). The root is asked
// only about the top-level domain and the top-level domain only about the
// domain, so neither learns which name under it this installation is proving —
// and a delegation is read from the reply to exactly the question it answers,
// which is the owner check parseReferral already makes.
//
// Every question goes through AskServer's machinery: over TCP, through the
// guard that refuses private, loopback and reserved destinations (a zone names
// its own servers, so its owner chooses where this connects), with a random
// identifier and randomised case, so a reply that does not echo the exact bytes
// was written by something that did not see them.
//
// # What it trusts, and what it does not
//
// Addresses a referral carries for its servers are used only for names inside
// the zone that sent the referral. The root may say where the servers of com
// are; com's servers may say where ns1.example.com is; neither may say where
// a server of some other zone is, because that is how a reply claims authority
// it does not have. Other names are looked up by the same walk.
//
// A record is read only where its owner is the name that was asked about. An
// alias is followed by a fresh walk from the root to its target, never by
// believing records for the target that arrived in the same reply.
//
// # What it cannot defend against
//
// Somebody who can answer in place of the zone's servers — who controls the
// network this machine sends from, which the person administering it does —
// can still answer for a zone that is not signed. DNSSEC is what closes that,
// and it is not checked here: -verification-requires-dnssec is the operator's
// answer, and it asks for the resolver's word as well as this.
type Authority struct {
	// Client asks each server: its Dial and Timeout are what every question
	// uses. Required.
	Client *Client

	// Roots replaces the root servers, for tests. Empty means RootServers.
	Roots []netip.Addr
}

// RootServers are the root name servers' addresses, as IANA publishes them in
// the root hints file (named.root), with b.root-servers.net at the addresses it
// moved to on 2023-11-27.
//
// Carried rather than looked up, because looking them up means asking a
// resolver, which is the thing this walk exists not to trust. They change
// rarely and announce it years ahead; a stale entry costs one server that does
// not answer, and the walk moves on to the next. IPv4 first, because a
// container without IPv6 fails those dials slowly.
var RootServers = []netip.Addr{
	netip.MustParseAddr("198.41.0.4"),     // a
	netip.MustParseAddr("170.247.170.2"),  // b
	netip.MustParseAddr("192.33.4.12"),    // c
	netip.MustParseAddr("199.7.91.13"),    // d
	netip.MustParseAddr("192.203.230.10"), // e
	netip.MustParseAddr("192.5.5.241"),    // f
	netip.MustParseAddr("192.112.36.4"),   // g
	netip.MustParseAddr("198.97.190.53"),  // h
	netip.MustParseAddr("192.36.148.17"),  // i
	netip.MustParseAddr("192.58.128.30"),  // j
	netip.MustParseAddr("193.0.14.129"),   // k
	netip.MustParseAddr("199.7.83.42"),    // l
	netip.MustParseAddr("202.12.27.33"),   // m
	netip.MustParseAddr("2001:503:ba3e::2:30"),
	netip.MustParseAddr("2801:1b8:10::b"),
	netip.MustParseAddr("2001:500:2::c"),
	netip.MustParseAddr("2001:500:2d::d"),
	netip.MustParseAddr("2001:500:a8::e"),
	netip.MustParseAddr("2001:500:2f::f"),
	netip.MustParseAddr("2001:500:12::d0d"),
	netip.MustParseAddr("2001:500:1::53"),
	netip.MustParseAddr("2001:7fe::53"),
	netip.MustParseAddr("2001:503:c27::2:30"),
	netip.MustParseAddr("2001:7fd::1"),
	netip.MustParseAddr("2001:500:9f::42"),
	netip.MustParseAddr("2001:dc3::35"),
}

const (
	// authorityMaxQueries bounds one lookup. A walk to a name three labels
	// down is four questions; a delegation whose servers have no glue adds a
	// walk per server looked up. A zone that needs more than this is either
	// broken or built to make this program ask, and both are answered by
	// stopping.
	authorityMaxQueries = 48

	// authorityMaxServers is how many servers one question is put to before
	// the walk gives up on it. A delegation may name a dozen.
	authorityMaxServers = 6

	// authorityMaxAliases is how many aliases a challenge may pass through.
	authorityMaxAliases = 4

	// authorityMaxDepth is how deep looking up a server's own address may go:
	// a delegation to a server whose name is in a zone whose servers also need
	// looking up.
	authorityMaxDepth = 2
)

// errAuthorityBudget is a walk that ran out of questions.
var errAuthorityBudget = errors.New("dnsclient: the zone could not be reached from the root within the questions allowed")

// LookupChallenge reads the TXT records at name from the servers that hold it.
//
// existed is false where one of those servers, answering with authority, said
// the name does not exist. An error is a walk that could not finish, which is
// not the same as a name without a record, for the reason verify.Covers gives.
func (a *Authority) LookupChallenge(ctx context.Context, name string) (values []string, existed bool, err error) {
	if a == nil || a.Client == nil {
		return nil, false, errors.New("dnsclient: no client to ask the zone's servers with")
	}
	w := &authorityWalk{a: a}
	return w.txt(ctx, name, 0)
}

// authorityWalk is one lookup, and the questions it has asked so far.
type authorityWalk struct {
	a       *Authority
	queries int
}

// heldAnswer is what one server said, read strictly: records only where their
// owner is the name asked about.
type heldAnswer struct {
	authoritative bool
	exists        bool
	referral      []string
	glue          map[string][]netip.Addr
	txt           []string
	alias         string
	addresses     []netip.Addr
}

func (w *authorityWalk) roots() []netip.Addr {
	if len(w.a.Roots) > 0 {
		return w.a.Roots
	}
	return RootServers
}

// txt reads the TXT records at name, following an alias with a fresh walk.
func (w *authorityWalk) txt(ctx context.Context, name string, aliases int) ([]string, bool, error) {
	name = foldText(name)
	servers, exists, err := w.holders(ctx, name, 0)
	if err != nil || !exists {
		return nil, exists, err
	}

	ans, err := w.ask(ctx, servers, name, TypeTXT)
	if err != nil {
		return nil, false, err
	}
	if !ans.authoritative {
		return nil, false, errors.New("dnsclient: the servers holding the zone did not answer for it")
	}
	if !ans.exists {
		return nil, false, nil
	}
	if len(ans.txt) == 0 && ans.alias != "" {
		if aliases >= authorityMaxAliases {
			return nil, false, errors.New("dnsclient: the challenge passes through more aliases than are followed")
		}
		return w.txt(ctx, ans.alias, aliases+1)
	}
	return ans.txt, true, nil
}

// holders walks from the root to the servers that hold the zone name is in.
//
// exists is false where a server holding a zone above said, with authority,
// that a name on the way does not exist: nothing below it can.
func (w *authorityWalk) holders(ctx context.Context, name string, depth int) ([]netip.Addr, bool, error) {
	labels := strings.Split(name, ".")
	servers := w.roots()
	zone := ""

	for i := len(labels) - 1; i >= 0; i-- {
		child := strings.Join(labels[i:], ".")

		ans, err := w.ask(ctx, servers, child, TypeNS)
		if err != nil {
			return nil, false, err
		}
		if !ans.exists {
			if !ans.authoritative {
				return nil, false, errors.New("dnsclient: a server said a name does not exist without holding the zone it is in")
			}
			return nil, false, nil
		}

		if len(ans.referral) == 0 {
			// No delegation: the name is held by the servers already asked,
			// which is only an answer if they said so with authority.
			if !ans.authoritative {
				return nil, false, errors.New("dnsclient: a server neither answered for a name nor delegated it")
			}
			continue
		}

		next := inZoneGlue(ans, zone)
		if len(next) == 0 {
			for _, server := range ans.referral {
				if len(next) > 0 || w.queries >= authorityMaxQueries {
					break
				}
				found, err := w.addresses(ctx, server, depth+1)
				if err == nil {
					next = found
				}
			}
		}
		if len(next) == 0 {
			return nil, false, fmt.Errorf("dnsclient: none of the servers %s is delegated to could be reached", child)
		}
		servers, zone = next, child
	}
	return servers, true, nil
}

// addresses looks up a server's own addresses by the same walk.
func (w *authorityWalk) addresses(ctx context.Context, host string, depth int) ([]netip.Addr, error) {
	if depth > authorityMaxDepth {
		return nil, errors.New("dnsclient: a server's address is further from the root than is followed")
	}
	host = foldText(host)
	servers, exists, err := w.holders(ctx, host, depth)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("dnsclient: a delegation names a server that does not exist")
	}

	var out []netip.Addr
	for _, qtype := range []uint16{TypeA, TypeAAAA} {
		ans, err := w.ask(ctx, servers, host, qtype)
		if err != nil || !ans.authoritative {
			continue
		}
		out = append(out, ans.addresses...)
	}
	if len(out) == 0 {
		return nil, errors.New("dnsclient: a delegation names a server with no address")
	}
	return orderAddresses(out), nil
}

// ask puts one question to the servers in turn until one answers.
func (w *authorityWalk) ask(ctx context.Context, servers []netip.Addr, name string, qtype uint16) (heldAnswer, error) {
	last := errors.New("dnsclient: no server to ask")
	for i, server := range servers {
		if i >= authorityMaxServers {
			break
		}
		if w.queries >= authorityMaxQueries {
			return heldAnswer{}, errAuthorityBudget
		}
		w.queries++

		qctx, cancel := context.WithTimeout(ctx, w.a.Client.timeout())
		ans, err := w.askOne(qctx, server, name, qtype)
		cancel()
		if err == nil {
			return ans, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return heldAnswer{}, last
}

// askOne asks one server one question, without recursion, and reads the reply
// strictly.
func (w *authorityWalk) askOne(ctx context.Context, server netip.Addr, name string, qtype uint16) (heldAnswer, error) {
	id, err := randomUint16()
	if err != nil {
		return heldAnswer{}, fmt.Errorf("dnsclient: generating a query id: %w", err)
	}
	question, err := encodeName(name, true)
	if err != nil {
		return heldAnswer{}, err
	}

	raw, err := w.a.Client.askServerRaw(ctx, server.String(), buildQueryWith(id, question, qtype, false))
	if err != nil {
		return heldAnswer{}, err
	}

	// The header, the echoed question and the response code, and a
	// delegation read from the authority section with its owner checked
	// against the question.
	r, err := parseReferral(raw, id, question, qtype)
	if err != nil {
		return heldAnswer{}, err
	}
	out := heldAnswer{
		authoritative: r.authoritative,
		exists:        r.existed,
		referral:      r.referral,
		glue:          r.glue,
	}
	if !r.existed {
		return out, nil
	}

	out.txt, out.alias, out.addresses, err = exactAnswers(raw, question, qtype)
	return out, err
}

// exactAnswers reads the answer section for records owned by the name that was
// asked about and nothing else.
//
// Stricter than parseAnswers, which accepts records along a CNAME chain the
// reply draws: from a resolver that is how an alias is answered, but a server
// answering with authority for one zone has no authority over the zone an
// alias points into, and a record for the target in its reply is the shape of
// a poisoned cache. The alias is returned instead, for a walk of its own.
func exactAnswers(raw, question []byte, qtype uint16) (txt []string, alias string, addrs []netip.Addr, err error) {
	want := foldName(question)
	offset := headerLen + len(question) + 4
	count := int(binary.BigEndian.Uint16(raw[6:8]))

	for i := 0; i < count; i++ {
		owner, next, err := readName(raw, offset)
		if err != nil {
			return nil, "", nil, err
		}
		offset = next
		if offset+10 > len(raw) {
			return nil, "", nil, errors.New("dnsclient: a record ends before its header does")
		}
		rrType := binary.BigEndian.Uint16(raw[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10
		if offset+rdLength > len(raw) {
			return nil, "", nil, errors.New("dnsclient: a record announces more data than the reply holds")
		}
		rdata := raw[offset : offset+rdLength]
		rdataAt := offset
		offset += rdLength

		if !bytes.Equal(foldName(owner), want) {
			continue
		}

		switch {
		case rrType == TypeCNAME:
			target, _, err := readName(raw, rdataAt)
			if err != nil {
				return nil, "", nil, err
			}
			alias = nameText(foldName(target))
		case rrType == TypeTXT && qtype == TypeTXT:
			value, err := parseTXT(rdata)
			if err != nil {
				return nil, "", nil, err
			}
			txt = append(txt, value)
		case rrType == TypeA && qtype == TypeA:
			addr, err := parseAddress(rdata, 4)
			if err != nil {
				return nil, "", nil, err
			}
			addrs = append(addrs, addr)
		case rrType == TypeAAAA && qtype == TypeAAAA:
			addr, err := parseAddress(rdata, 16)
			if err != nil {
				return nil, "", nil, err
			}
			addrs = append(addrs, addr)
		}
	}
	return txt, alias, addrs, nil
}

// inZoneGlue is the glue a referral carried for servers inside the zone that
// sent it. The root holds every name, so its glue is all in zone.
func inZoneGlue(ans heldAnswer, zone string) []netip.Addr {
	var out []netip.Addr
	for _, server := range ans.referral {
		if zone != "" && server != zone && !strings.HasSuffix(server, "."+zone) {
			continue
		}
		out = append(out, ans.glue[server]...)
	}
	return orderAddresses(out)
}

// orderAddresses puts IPv4 before IPv6 and drops repeats and anything that is
// not a usable address.
func orderAddresses(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Is4() && !out[j].Is4() })
	return out
}

// foldText lowers a name and drops a trailing dot.
func foldText(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
