package dnsclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/denyfirst/porch/internal/safedial"
)

// ServerAnswer is what one name server said when it was asked directly.
//
// Three facts about the server sit beside the records, because each answers a
// question the records cannot. Whether it claims authority for the zone is
// what tells a delegation that works from one that only looks right.
// Whether it offers recursion says whether it will answer questions about
// other people's domains, which is what makes a server usable for an
// amplification attack. And a refusal is neither of those: a server that
// refuses the question said nothing about the zone at all (R4).
type ServerAnswer struct {
	// Authoritative is the AA bit: this server says the answer is its own
	// rather than something it learned.
	Authoritative bool

	// RecursionOffered is the RA bit: the server says it will go and find
	// answers it does not hold.
	RecursionOffered bool

	// Answered is false where the server refused the question or answered
	// with a failure. Nothing else in this struct describes the zone then.
	Answered bool

	// Existed is false where the server said the name does not exist.
	Existed bool

	// NS and SOA are what the answer section held, where the question asked
	// for them.
	NS  []string
	SOA []SOA

	// Referral is what the authority section named as serving the question,
	// which is how a server holding the parent zone answers a question about a
	// child: it points rather than answers, and Authoritative is clear.
	//
	// Apart from NS, because the two are different claims. NS is the zone's own
	// list, read from a server that holds the zone; Referral is the list its
	// parent hands out. A resolver starting from the root follows the second.
	Referral []string
}

// serverPort is the one port a name server is asked on.
const serverPort = "53"

// AskServer asks one name server directly, over TCP, and reports what it said
// about itself as well as what it answered.
//
// # Why a server is asked at all
//
// Everything else in this package asks a resolver, which is the whole of what
// a scan needs to read a zone. Three questions cannot be answered that way,
// because the resolver has already smoothed them over: whether each server the
// delegation names actually answers for the zone, whether the parent and the
// child agree about that list, and whether a server will answer questions
// about domains it has nothing to do with. A resolver that reached one working
// server reports a working zone.
//
// # Over TCP, deliberately
//
// Every name server is required to answer over TCP (RFC 7766), and the guard
// that refuses private, loopback and reserved destinations is written for TCP.
// The addresses asked here come out of the zone being measured, which means
// whoever is measured chooses them: without that guard a zone could point this
// scan at something inside the network it runs in, which is the arrangement
// safedial exists to prevent. UDP would be one round trip cheaper and would
// have to reimplement that guard.
//
// # What it sends
//
// One question, with recursion asked for only where the caller wants to know
// whether the server offers it. The identifier is random and the case of the
// question is randomised, as everywhere else here: a reply that does not echo
// the exact bytes was written by something that did not see them.
func (c *Client) AskServer(ctx context.Context, address, name string, qtype uint16, recursion bool) (ServerAnswer, error) {
	id, err := randomUint16()
	if err != nil {
		return ServerAnswer{}, fmt.Errorf("dnsclient: generating a query id: %w", err)
	}
	question, err := encodeName(name, true)
	if err != nil {
		return ServerAnswer{}, err
	}

	raw, err := c.askServerRaw(ctx, address, buildQueryWith(id, question, qtype, recursion))
	if err != nil {
		return ServerAnswer{}, err
	}

	// A question about name servers is read with the authority section, because
	// half the answers to it live there. A server that holds the zone puts them
	// in the answer section; a server that holds the zone above points at them
	// from the authority section instead, and both replies answer what was
	// asked.
	read := parseReply
	if qtype == TypeNS {
		read = parseReferral
	}

	reply, err := read(raw, id, question, qtype)
	out := ServerAnswer{
		Authoritative:    reply.authoritative,
		RecursionOffered: reply.recursionOffered,
		Existed:          reply.existed,
		NS:               reply.ns,
		SOA:              reply.soa,
		Referral:         reply.referral,
	}
	if err != nil {
		// A refusal, a failure, or a reply this could not read. The flags
		// above still describe what arrived; nothing below them describes the
		// zone, which is what Answered says.
		return out, err
	}
	out.Answered = true
	return out, nil
}

// askServerRaw sends one framed query to one server and returns the reply.
func (c *Client) askServerRaw(ctx context.Context, address string, query []byte) ([]byte, error) {
	conn, err := c.dialServer(ctx, net.JoinHostPort(address, serverPort))
	if err != nil {
		return nil, fmt.Errorf("dnsclient: reaching the name server: %w", err)
	}
	defer conn.Close() //nolint:errcheck // the reply is already read or the error already returned

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query))) // #nosec G115 -- a question is tens of bytes
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("dnsclient: sending the query: %w", err)
	}

	var length [2]byte
	if _, err := readFull(conn, length[:]); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the reply length: %w", err)
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size == 0 || size > maxMessage {
		return nil, fmt.Errorf("dnsclient: the server announced a reply of %d bytes", size)
	}

	raw := make([]byte, size)
	if _, err := readFull(conn, raw); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the reply: %w", err)
	}
	return raw, nil
}

// dialServer opens the connection to a name server.
//
// Through safedial rather than through the dialler the resolver path uses, and
// the difference is the point. A resolver is this machine's own configuration
// and is often on loopback; a name server here is an address published by the
// zone being measured, so it is a destination somebody else chose.
func (c *Client) dialServer(ctx context.Context, address string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, "tcp", address)
	}
	// The port is fixed above, so the allow list cannot be reached by anything
	// this package does today. It is here for the reason N3 gives about its two
	// locks: a guard that depends on its caller having chosen the right port is
	// a guard the next caller walks around.
	dialer := &safedial.Dialer{AllowedPorts: []string{serverPort}}
	return dialer.DialContext(ctx, "tcp", address)
}
