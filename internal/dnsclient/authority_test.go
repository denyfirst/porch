package dnsclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// zoneServer answers one question the way a server holding a zone does.
type zoneServer func(t *testing.T, qname string, qtype uint16) heldReply

// heldReply is what a fake server sends back: its flags and three sections.
type heldReply struct {
	flags      uint16
	answer     []record
	authority  []record
	additional []record
}

const (
	flagsAuthoritative = 0x8400 // a response, authoritative, no error
	flagsReferral      = 0x8000 // a response, not authoritative, no error
	flagsNXDomain      = 0x8403 // a response, authoritative, no such name
)

// hierarchy is a set of fake servers keyed by address, and a record of every
// question each was asked.
type hierarchy struct {
	t       *testing.T
	servers map[string]zoneServer

	mu    sync.Mutex
	asked []string // "address name type", in order
}

func (h *hierarchy) dial(_ context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != serverPort || network != "tcp" {
		return nil, errors.New("a name server is asked over tcp on port 53")
	}
	serve, ok := h.servers[host]
	if !ok {
		return nil, errors.New("nothing listens there")
	}

	client, server := net.Pipe()
	go func() {
		defer server.Close() //nolint:errcheck // the test half of a pipe
		var length [2]byte
		if _, err := readFull(server, length[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := readFull(server, query); err != nil {
			return
		}
		end, err := skipName(query, headerLen)
		if err != nil {
			return
		}
		question := query[headerLen:end]
		qtype := binary.BigEndian.Uint16(query[end : end+2])
		qname := nameText(foldName(question))

		h.mu.Lock()
		h.asked = append(h.asked, host+" "+qname+" "+typeName(qtype))
		h.mu.Unlock()

		r := serve(h.t, qname, qtype)
		reply := sections(binary.BigEndian.Uint16(query[0:2]), r.flags, question, qtype, r.answer, r.authority, r.additional)
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
		_, _ = server.Write(append(framed, reply...))
	}()
	return client, nil
}

func (h *hierarchy) questions() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.asked...)
}

func typeName(qtype uint16) string {
	switch qtype {
	case TypeNS:
		return "NS"
	case TypeTXT:
		return "TXT"
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	}
	return "?"
}

// sections builds a reply with all three record sections.
func sections(id, flags uint16, question []byte, qtype uint16, answer, authority, additional []record) []byte {
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(answer)))
	binary.BigEndian.PutUint16(msg[8:10], uint16(len(authority)))
	binary.BigEndian.PutUint16(msg[10:12], uint16(len(additional)))
	msg = append(msg, question...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	for _, section := range [][]record{answer, authority, additional} {
		for _, r := range section {
			msg = append(msg, r.name...)
			msg = binary.BigEndian.AppendUint16(msg, r.rrType)
			msg = binary.BigEndian.AppendUint16(msg, classIN)
			msg = binary.BigEndian.AppendUint32(msg, 300)
			msg = binary.BigEndian.AppendUint16(msg, uint16(len(r.rdata)))
			msg = append(msg, r.rdata...)
		}
	}
	return msg
}

func addrRecord(t *testing.T, owner, address string) record {
	t.Helper()
	a := netip.MustParseAddr(address)
	if a.Is4() {
		b := a.As4()
		return record{name(t, owner), TypeA, b[:]}
	}
	b := a.As16()
	return record{name(t, owner), TypeAAAA, b[:]}
}

// delegate is a referral to child, naming its servers and carrying glue.
func delegate(t *testing.T, child string, servers map[string]string) heldReply {
	t.Helper()
	r := heldReply{flags: flagsReferral}
	for ns, addr := range servers {
		r.authority = append(r.authority, record{name(t, child), TypeNS, nsRecord(t, ns)})
		if addr != "" {
			r.additional = append(r.additional, addrRecord(t, ns, addr))
		}
	}
	return r
}

// holds answers with authority and nothing, which is how a server holding a
// zone answers a question about a name in it with no such record.
func holds() heldReply { return heldReply{flags: flagsAuthoritative} }

const (
	rootAddr    = "192.0.2.1"
	comAddr     = "192.0.2.2"
	exampleAddr = "192.0.2.3"
	netAddr     = "192.0.2.4"
	proofsAddr  = "192.0.2.5"
	strayAddr   = "192.0.2.66"
	resolverIP  = "192.0.2.53"
)

// estate is root, com, and example.com, where the challenge carries token.
func estate(t *testing.T, token string) *hierarchy {
	h := &hierarchy{t: t, servers: map[string]zoneServer{}}
	h.servers[rootAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		switch qname {
		case "com":
			return delegate(t, "com", map[string]string{"a.gtld.test": comAddr})
		case "net":
			return delegate(t, "net", map[string]string{"b.gtld.test": netAddr})
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[comAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "example.com" {
			// A server outside com named with an address com has no
			// authority to give. Its glue must not be used.
			return delegate(t, "example.com", map[string]string{
				"ns1.example.com": exampleAddr,
				"ns.stray.net":    strayAddr,
			})
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[exampleAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "_porch-challenge.example.com" && qtype == TypeTXT {
			return heldReply{flags: flagsAuthoritative, answer: []record{
				{name(t, qname), TypeTXT, txtRecord(token)},
			}}
		}
		if qname == "_porch-challenge.example.com" || qname == "example.com" {
			return holds()
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[strayAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		t.Errorf("a server named only by glue from outside its zone was asked about %s", qname)
		return heldReply{flags: flagsAuthoritative, answer: []record{{name(t, qname), TypeTXT, txtRecord("forged")}}}
	}
	h.servers[resolverIP] = func(t *testing.T, qname string, qtype uint16) heldReply {
		t.Errorf("the resolver was asked about %s", qname)
		return heldReply{flags: 0x8180, answer: []record{{name(t, qname), TypeTXT, txtRecord("forged")}}}
	}
	return h
}

func walker(h *hierarchy) *Authority {
	return &Authority{
		Client: &Client{Server: net.JoinHostPort(resolverIP, "53"), Dial: h.dial},
		Roots:  []netip.Addr{netip.MustParseAddr(rootAddr)},
	}
}

// The challenge is read from the servers that hold the zone, reached from the
// root, and the resolver this machine is configured with is never asked.
//
// On 2026-09-29 a resolver started on the same server as a proven installation
// answered for a domain nobody there controlled, carrying the expected token,
// and the domain was scanned. The resolver here would answer "forged" for
// every name, and fails the test if it is asked at all.
func TestTheChallengeIsReadFromTheZonesOwnServersAndNoResolver(t *testing.T) {
	h := estate(t, "porch-verification=abc")
	values, existed, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com")
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if !existed || strings.Join(values, ",") != "porch-verification=abc" {
		t.Errorf("the walk read %v (existed %v)", values, existed)
	}

	// One label at a time: the root learns only the top-level domain, and com
	// only the domain. Neither is told which name under it is being proven.
	for _, q := range h.questions() {
		host, rest, _ := strings.Cut(q, " ")
		switch host {
		case rootAddr:
			if rest != "com NS" {
				t.Errorf("the root was asked %q", rest)
			}
		case comAddr:
			if rest != "example.com NS" {
				t.Errorf("com was asked %q", rest)
			}
		}
	}
}

// A name that does not exist, said with authority by a server holding the
// zone, is a name without a record rather than a failure.
func TestANameTheZoneSaysDoesNotExistHasNoRecord(t *testing.T) {
	h := estate(t, "porch-verification=abc")
	values, existed, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.nowhere.com")
	if err != nil {
		t.Fatalf("a name that does not exist was a failure: %v", err)
	}
	if existed || len(values) != 0 {
		t.Errorf("a name that does not exist read %v (existed %v)", values, existed)
	}

	// Said without authority, it is not believed.
	h.servers[rootAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		return heldReply{flags: 0x8003}
	}
	if _, _, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com"); err == nil {
		t.Error("a server without authority was believed that a name does not exist")
	}
}

// An alias is followed by a walk of its own, from the root, and records for its
// target that arrive in the same reply are not believed.
//
// A server answering with authority for example.com has none over the zone the
// alias points into; a record for the target in its reply is the shape of a
// poisoned cache.
func TestAnAliasIsWalkedFromTheRootAndNotBelieved(t *testing.T) {
	h := estate(t, "unused")
	h.servers[exampleAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "_porch-challenge.example.com" && qtype == TypeTXT {
			return heldReply{flags: flagsAuthoritative, answer: []record{
				{name(t, qname), TypeCNAME, nsRecord(t, "_porch.proofs.net")},
				{name(t, "_porch.proofs.net"), TypeTXT, txtRecord("porch-verification=poisoned")},
			}}
		}
		return holds()
	}
	h.servers[netAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "proofs.net" {
			return delegate(t, "proofs.net", map[string]string{"ns.proofs.net": proofsAddr})
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[proofsAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "_porch.proofs.net" && qtype == TypeTXT {
			return heldReply{flags: flagsAuthoritative, answer: []record{
				{name(t, qname), TypeTXT, txtRecord("porch-verification=real")},
			}}
		}
		return holds()
	}

	values, _, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com")
	if err != nil {
		t.Fatalf("the alias was not followed: %v", err)
	}
	if strings.Join(values, ",") != "porch-verification=real" {
		t.Errorf("the alias read %v, want the target's own servers' answer", values)
	}
}

// An address a referral carries for a server outside the referring zone is not
// used: the server's own zone is asked where it is.
//
// com may say where ns1.example.com is, because com holds example.com's
// delegation. It has no authority over stray.net, and an address it hands out
// for a server there is how a reply claims authority it does not have. Here
// that address is a forger's, and the real one is only in stray.net.
func TestGlueFromOutsideItsZoneIsNotBelieved(t *testing.T) {
	h := estate(t, "porch-verification=abc")
	h.servers[comAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "example.com" {
			return delegate(t, "example.com", map[string]string{"ns.stray.net": strayAddr})
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[netAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "stray.net" {
			return delegate(t, "stray.net", map[string]string{"ns1.stray.net": proofsAddr})
		}
		return heldReply{flags: flagsNXDomain}
	}
	h.servers[proofsAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "ns.stray.net" && qtype == TypeA {
			return heldReply{flags: flagsAuthoritative, answer: []record{addrRecord(t, qname, exampleAddr)}}
		}
		return holds()
	}

	values, _, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com")
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if strings.Join(values, ",") != "porch-verification=abc" {
		t.Errorf("the walk read %v", values)
	}
}

// A delegation that never arrives anywhere is bounded, and ends in an error
// rather than in an answer.
func TestAWalkThatNeverEndsIsBounded(t *testing.T) {
	h := estate(t, "unused")
	// com refers every question back to itself, forever.
	h.servers[comAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		return delegate(t, qname, map[string]string{"loop.gtld.test": ""})
	}
	h.servers[rootAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		if qname == "com" {
			return delegate(t, "com", map[string]string{"a.gtld.test": comAddr})
		}
		// The server com delegates to is looked up by the walk, and leads
		// back into com.
		return delegate(t, qname, map[string]string{"a.gtld.test": comAddr})
	}
	_, _, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com")
	if err == nil {
		t.Fatal("a walk with no end returned an answer")
	}
	if n := len(h.questions()); n > authorityMaxQueries {
		t.Errorf("the walk asked %d questions, more than its bound of %d", n, authorityMaxQueries)
	}

	// And a delegation naming more servers than anybody runs, none of which
	// can be found, costs the bound and no more. The depth limit alone does
	// not stop this one: each server is a short walk that fails, and there are
	// sixty of them.
	h = estate(t, "unused")
	h.servers[comAddr] = func(t *testing.T, qname string, qtype uint16) heldReply {
		servers := map[string]string{}
		for i := 0; i < 60; i++ {
			servers["ns"+string(rune('a'+i%26))+string(rune('a'+i/26))+".nowhere.test"] = ""
		}
		return delegate(t, qname, servers)
	}
	if _, _, err := walker(h).LookupChallenge(context.Background(), "_porch-challenge.example.com"); err == nil {
		t.Fatal("a delegation to servers that do not exist returned an answer")
	}
	// The number itself, not the constant: a test that read the bound from the
	// code it checks would move with any change to it, and one did.
	if n := len(h.questions()); n > 48 {
		t.Errorf("sixty unreachable servers cost %d questions, more than the bound of 48", n)
	}
}

// The walk asks through the guard when nothing replaces it, because a zone
// names its own servers and so chooses where this connects.
func TestTheWalkIsDialledThroughTheGuard(t *testing.T) {
	a := &Authority{Client: &Client{}, Roots: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	_, _, err := a.LookupChallenge(context.Background(), "_porch-challenge.example.com")
	if err == nil {
		t.Fatal("a root on loopback was asked")
	}
}

// The root servers carried are the thirteen, each by IPv4 and IPv6, IPv4
// first.
func TestTheRootServersAreCarried(t *testing.T) {
	v4, v6 := 0, 0
	for i, a := range RootServers {
		if a.Is4() {
			v4++
			if v6 > 0 {
				t.Errorf("an IPv4 root at %d follows an IPv6 one", i)
			}
		} else {
			v6++
		}
		if a.IsPrivate() || a.IsLoopback() || !a.IsGlobalUnicast() {
			t.Errorf("%s is not a public address", a)
		}
	}
	if v4 != 13 || v6 != 13 {
		t.Errorf("%d IPv4 and %d IPv6 roots, want 13 of each", v4, v6)
	}
}
