package dnsclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
)

// nameServer is a name server that answers one framed query and records what
// it was asked, so a test can read the bits of the question as well as the
// answer.
type nameServer struct {
	flags   uint16
	records []record

	// asked holds the query as it arrived, for the test that reads the
	// recursion bit this client set.
	asked []byte

	// pointing puts the records in the authority section rather than the answer
	// section, which is how a server holding the zone above replies.
	pointing bool

	// refuse answers every query with REFUSED, which is what a server that
	// serves neither the zone nor recursion says.
	refuse bool
}

func (s *nameServer) dial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()

	return func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("a name server is asked over tcp")
		}
		if _, port, _ := net.SplitHostPort(address); port != serverPort {
			return nil, errors.New("a name server is asked on port 53")
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
			s.asked = append([]byte(nil), query...)

			end, err := skipName(query, headerLen)
			if err != nil {
				return
			}
			question := query[headerLen:end]
			qtype := binary.BigEndian.Uint16(query[end : end+2])

			flags := s.flags
			if s.refuse {
				flags = 0x8005 // a response, REFUSED
			}
			id := binary.BigEndian.Uint16(query[0:2])
			reply := message(id, flags, question, qtype, s.records...)
			if s.pointing {
				// A server of the zone above: the records go in the
				// authority section, whatever was asked for.
				reply = pointing(id, question, qtype, s.records...)
			}

			framed := make([]byte, 2+len(reply))
			binary.BigEndian.PutUint16(framed, uint16(len(reply)))
			copy(framed[2:], reply)
			_, _ = server.Write(framed)
		}()
		return client, nil
	}
}

// A server asked directly says what it holds and what it is: whether the
// answer is its own, and whether it will go and find answers it does not hold.
func TestAServerAskedDirectlySaysWhatItHoldsAndWhatItIs(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	// A well-behaved authoritative server: authoritative, no recursion.
	authoritative := &nameServer{
		flags: 0x8400,
		records: []record{
			{q, TypeSOA, soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
		},
	}
	c := &Client{Dial: authoritative.dial(t), Timeout: 3 * time.Second}

	got, err := c.AskServer(ctx, "192.0.2.53", "example.com", TypeSOA, false)
	if err != nil {
		t.Fatalf("AskServer: %v", err)
	}
	if !got.Answered || !got.Authoritative || got.RecursionOffered {
		t.Errorf("an authoritative server reads %+v", got)
	}
	if len(got.SOA) != 1 || got.SOA[0].Primary != "ns1.example.net" {
		t.Errorf("the record reads %+v", got.SOA)
	}

	// And the question carried no recursion bit, because what this asks is
	// what the server itself holds.
	if len(authoritative.asked) < 4 || binary.BigEndian.Uint16(authoritative.asked[2:4])&0x0100 != 0 {
		t.Error("the query asked the server to recurse")
	}

	// A server that offers recursion says so in the same bit every resolver
	// sets, and this reads it as what it is.
	open := &nameServer{flags: 0x8080, records: []record{{q, TypeSOA, soaRecord(t, "ns.other.test", "noc.other.test", 1, 1, 1, 1, 1)}}}
	c = &Client{Dial: open.dial(t), Timeout: 3 * time.Second}
	got, err = c.AskServer(ctx, "192.0.2.53", "example.com", TypeSOA, true)
	if err != nil {
		t.Fatalf("AskServer: %v", err)
	}
	if !got.RecursionOffered || got.Authoritative {
		t.Errorf("a recursing server reads %+v", got)
	}
	if len(open.asked) < 4 || binary.BigEndian.Uint16(open.asked[2:4])&0x0100 == 0 {
		t.Error("the query did not ask the server to recurse")
	}
}

// A server that refuses said nothing about the zone, and that is not a zone it
// does not serve (R4).
func TestAServerThatRefusesIsNotAnAnswerAboutTheZone(t *testing.T) {
	refusing := &nameServer{refuse: true}
	c := &Client{Dial: refusing.dial(t), Timeout: 3 * time.Second}

	got, err := c.AskServer(context.Background(), "192.0.2.53", "example.com", TypeSOA, false)
	if !errors.Is(err, ErrRefused) {
		t.Errorf("a refusal reads as %v", err)
	}
	if got.Answered {
		t.Errorf("a refusal was read as an answer: %+v", got)
	}
}

// The address a zone published is dialled through the guard that refuses
// private, loopback and reserved destinations.
//
// The addresses here come out of the zone being measured, so whoever is
// measured chooses them. Without the guard a zone could point this scan at
// something inside the network it runs in, which is what safedial exists to
// stop — and it is the reason a server is asked over TCP at all.
func TestAServerIsDialledThroughTheGuard(t *testing.T) {
	c := &Client{Timeout: 2 * time.Second}

	for _, address := range []string{"127.0.0.1", "10.0.0.53", "169.254.169.254", "::1"} {
		_, err := c.AskServer(context.Background(), address, "example.com", TypeSOA, false)
		if err == nil {
			t.Errorf("%s was dialled", address)
			continue
		}
		// The guard's own refusal, not merely a connection that failed:
		// nothing is listening on most of these addresses either, so an error
		// alone would pass with the guard removed.
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("%s was refused by something other than the guard: %v", address, err)
		}
	}
}

// pointing builds a referral: nothing in the answer section, the delegation in
// the authority section, and the authority bit clear. That is what a server
// holding the zone above sends when it is asked about a zone below it.
func pointing(id uint16, question []byte, qtype uint16, records ...record) []byte {
	msg := message(id, 0x8000, question, qtype) // a response, no error, not authoritative
	binary.BigEndian.PutUint16(msg[6:8], 0)     // no answers
	binary.BigEndian.PutUint16(msg[8:10], uint16(len(records)))

	for _, r := range records {
		msg = append(msg, r.name...)
		msg = binary.BigEndian.AppendUint16(msg, r.rrType)
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(r.rdata)))
		msg = append(msg, r.rdata...)
	}
	return msg
}

// A delegation is read from the authority section, because that is the only
// place it appears: a server holding the parent zone points at the child's
// servers rather than answering for them, and every measure this package took
// until now would have read that reply as empty.
func TestADelegationIsReadFromTheAuthoritySection(t *testing.T) {
	q := name(t, "example.com")
	other := name(t, "example.net")

	got, err := parseReferral(pointing(0x1234, q, TypeNS,
		record{q, TypeNS, nsRecord(t, "ns1.example.net")},
		record{q, TypeNS, nsRecord(t, "ns2.example.org")},
		// A record for a name nobody asked about, which a server may put there
		// and which answers nothing: the owner check applies in this section
		// exactly as it does in the answer section.
		record{other, TypeNS, nsRecord(t, "ns.somewhere.test")},
	), 0x1234, q, TypeNS)
	if err != nil {
		t.Fatalf("a referral was refused: %v", err)
	}
	if strings.Join(got.referral, ",") != "ns1.example.net,ns2.example.org" {
		t.Errorf("the referral reads %v", got.referral)
	}
	if len(got.ns) != 0 {
		t.Errorf("the authority section was read as an answer: %v", got.ns)
	}
	if got.authoritative {
		t.Error("a referral was read as an authoritative answer")
	}

	// And the same reply read the ordinary way carries none of it, because the
	// section is walked only where a caller asked for it.
	plain, err := parseReply(pointing(0x1234, q, TypeNS,
		record{q, TypeNS, nsRecord(t, "ns1.example.net")},
	), 0x1234, q, TypeNS)
	if err != nil {
		t.Fatalf("parseReply: %v", err)
	}
	if len(plain.referral) != 0 || len(plain.ns) != 0 {
		t.Errorf("a reply nobody asked the authority section of reads %v / %v", plain.referral, plain.ns)
	}
}

// A question about name servers is the one that reads the authority section,
// and asking a server anything else does not.
//
// The two shapes are one question: a server that holds the zone answers from
// the answer section, a server that holds the zone above points from the
// authority section, and both are what "which servers serve this name" gets
// back.
func TestOnlyAQuestionAboutServersReadsTheDelegation(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	// A server of the zone above: it points, and it points whatever it is
	// asked, so which section is read is this client's decision and not the
	// server's.
	parent := &nameServer{
		pointing: true,
		records:  []record{{q, TypeNS, nsRecord(t, "ns1.example.net")}},
	}
	c := &Client{Dial: parent.dial(t), Timeout: 3 * time.Second}

	delegated, err := c.AskServer(ctx, "192.0.2.53", "example.com", TypeNS, false)
	if err != nil {
		t.Fatalf("AskServer: %v", err)
	}
	if len(delegated.Referral) != 1 || delegated.Referral[0] != "ns1.example.net" {
		t.Errorf("a server of the zone above answered %+v", delegated)
	}

	// The same server, the same records, a different question: nothing is read
	// from that section, because nothing there answers what was asked.
	soa, err := c.AskServer(ctx, "192.0.2.53", "example.com", TypeSOA, false)
	if err == nil && len(soa.Referral) != 0 {
		t.Errorf("a question about the record at the top of the zone read a delegation: %+v", soa)
	}
}
