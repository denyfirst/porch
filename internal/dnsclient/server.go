package dnsclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

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

	// Glue holds the addresses that referral carried for the servers it named,
	// keyed by name and written as text.
	//
	// A server inside the zone it serves cannot be reached any other way, so
	// this copy is what a resolver starting at the root actually dials. The zone
	// publishes the same addresses itself, and the two can differ: then some
	// resolvers reach one machine and some the other.
	Glue map[string][]string
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
		Glue:             addressText(reply.glue),
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

// AskTransfer asks one server whether it will hand the whole zone to anybody
// who asks, and stops before it does.
//
// # Why the question is worth putting
//
// A server that grants AXFR to the internet gives up every name in the zone at
// once: the staging host, the build server, the thing behind the VPN — names
// that exist and that nobody publishes a link to. Nothing else in a scan shows
// it, because every other question here asks about a name somebody already
// knows. RFC 5936 does not call it a fault, and this does not either: section 5
// says an implementation ought to let an operator open transfers to all, while
// saying it must not be the default. So it is measured and reported, never
// graded (R21).
//
// # What it sends, and what it refuses to read
//
// One AXFR query, over the same TCP connection every other direct question
// uses and through the same guard. Then it reads the first thirty-odd bytes of
// the reply — the header and the echoed question — and closes the connection.
//
// That is the whole of it. The header says whether the server refused and
// whether records follow, which is the entire answer; the records themselves
// are the operator's own zone, and a scanner that read them would be holding
// the thing it is warning them about. The bytes are not parsed, not counted,
// not kept, and mostly not even read off the socket: closing the connection
// discards them, and a server sending a large zone stops when it does.
func (c *Client) AskTransfer(ctx context.Context, address, zone string) (bool, error) {
	id, err := randomUint16()
	if err != nil {
		return false, fmt.Errorf("dnsclient: generating a query id: %w", err)
	}
	question, err := encodeName(zone, true)
	if err != nil {
		return false, err
	}

	// The header, the question as it is echoed, and its type and class: what
	// the checks below need and nothing after it.
	want := headerLen + len(question) + 4

	head, err := c.askServerHead(ctx, address, buildQueryWith(id, question, TypeAXFR, false), want)
	if err != nil {
		return false, err
	}
	if len(head) < headerLen {
		return false, errors.New("dnsclient: the reply is shorter than a header")
	}

	// The same two checks every other reply passes before it is read at all: a
	// reply that answers another query, or echoes another question, was written
	// by something that did not see this one.
	if got := binary.BigEndian.Uint16(head[0:2]); got != id {
		return false, fmt.Errorf("dnsclient: the reply answers query %d, not %d", got, id)
	}
	flags := binary.BigEndian.Uint16(head[2:4])
	if flags&0x8000 == 0 {
		return false, errors.New("dnsclient: the reply is not marked as one")
	}
	if len(head) >= want {
		echoed := make([]byte, 0, len(question)+4)
		echoed = append(echoed, question...)
		echoed = binary.BigEndian.AppendUint16(echoed, TypeAXFR)
		echoed = binary.BigEndian.AppendUint16(echoed, classIN)
		if !bytes.Equal(head[headerLen:want], echoed) {
			return false, errors.New("dnsclient: the reply echoes a different question")
		}
	}

	const (
		rcodeNotImplemented = 4
		rcodeRefused        = 5
		rcodeNotAuthorised  = 9
	)
	switch rcode := flags & 0x000F; rcode {
	case 0:
	case rcodeRefused, rcodeNotAuthorised, rcodeNotImplemented:
		// The answer this question is looking for, and the good one. It travels
		// as an error because a refusal is one everywhere else here, and a
		// caller reads it as a zone that is not handed out rather than as a
		// measurement that failed. Three codes and not one: see ErrNoTransfer.
		return false, ErrNoTransfer
	default:
		return false, fmt.Errorf("dnsclient: the server answered with code %d", rcode)
	}

	// A transfer begins with records. A reply carrying none, and no refusal, is
	// a server that answered without starting one, and that is not a zone
	// anybody can read.
	return binary.BigEndian.Uint16(head[6:8]) > 0, nil
}

// askServerHead sends one query and reads at most the first want bytes of the
// reply before closing the connection.
//
// Separate from askServerRaw, which reads the whole message and bounds it at
// maxMessage. Neither behaviour is wanted here: a zone transfer's first message
// runs to tens of kilobytes, so the bound would report an open server as one
// that could not be read, and reading it would mean taking a copy of somebody's
// zone to decide whether it could be taken.
func (c *Client) askServerHead(ctx context.Context, address string, query []byte, want int) ([]byte, error) {
	conn, err := c.dialServer(ctx, net.JoinHostPort(address, serverPort))
	if err != nil {
		return nil, fmt.Errorf("dnsclient: reaching the name server: %w", err)
	}
	defer conn.Close() //nolint:errcheck // whatever is still coming is deliberately not read

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
	if size == 0 {
		return nil, errors.New("dnsclient: the server announced a reply of 0 bytes")
	}
	if size < want {
		want = size
	}

	head := make([]byte, want)
	if _, err := readFull(conn, head); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the reply: %w", err)
	}
	return head, nil
}

// addressText writes the glue as text, which is the shape every other address
// leaves this package in.
func addressText(glue map[string][]netip.Addr) map[string][]string {
	if len(glue) == 0 {
		return nil
	}
	out := make(map[string][]string, len(glue))
	for name, addresses := range glue {
		for _, addr := range addresses {
			out[name] = append(out[name], addr.String())
		}
	}
	return out
}
