package dnsclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
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
			reply := message(binary.BigEndian.Uint16(query[0:2]), flags, question, qtype, s.records...)

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
