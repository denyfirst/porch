package dnsclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// transferServer hands a zone over in as many messages as it is given, which
// is how a real one sends it: the zone opens with its SOA, arrives in whatever
// number of messages the server chooses, and closes with the same SOA.
type transferServer struct {
	messages [][]record

	// refuse answers REFUSED, which is what almost every server does.
	refuse bool

	// notAuth answers NOTAUTH, which RFC 8945 gives for a transfer the asker
	// is not authorised for and which several providers send instead.
	notAuth bool
}

func (s *transferServer) dial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()

	return func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("a transfer is asked over tcp")
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

			end, err := skipName(query, headerLen)
			if err != nil {
				return
			}
			question := query[headerLen:end]
			qtype := binary.BigEndian.Uint16(query[end : end+2])
			id := binary.BigEndian.Uint16(query[0:2])

			if s.refuse || s.notAuth {
				flags := uint16(0x8005) // a response, REFUSED
				if s.notAuth {
					flags = 0x8009 // a response, NOTAUTH
				}
				write(server, message(id, flags, question, qtype))
				return
			}

			for _, records := range s.messages {
				write(server, message(id, 0x8400, question, qtype, records...))
			}
		}()
		return client, nil
	}
}

func write(conn net.Conn, reply []byte) {
	framed := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(framed, uint16(len(reply)))
	copy(framed[2:], reply)
	_, _ = conn.Write(framed)
}

// soaFor is the record a zone opens and closes with.
func soaFor(t *testing.T, zone string) record {
	t.Helper()
	return record{name(t, zone), TypeSOA,
		soaRecord(t, "ns1."+zone, "noc."+zone, 7, 7200, 3600, 1209600, 3600)}
}

// A zone is read from the server that hands it over, and the names in it are
// the names of its records.
//
// This is the one source that is complete when it works: no sample, no
// inference, every name from the server that is authoritative for it.
func TestAZoneIsReadFromTheServerThatHandsItOver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	zone := "example.com"
	handing := &transferServer{messages: [][]record{
		{
			soaFor(t, zone),
			{name(t, "www.example.com"), TypeA, []byte{192, 0, 2, 1}},
			{name(t, "mail.example.com"), TypeA, []byte{192, 0, 2, 2}},
		},
		{
			{name(t, "vpn.example.com"), TypeA, []byte{192, 0, 2, 3}},
			soaFor(t, zone),
		},
	}}

	c := &Client{Dial: handing.dial(t), Timeout: 3 * time.Second}
	names, truncated, err := c.Transfer(ctx, "192.0.2.53", zone)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if truncated {
		t.Error("a transfer that reached its closing record says it was cut")
	}

	// Every record's owner, in the order the zone sent them — including the
	// apex, which the caller filters rather than this.
	want := []string{"example.com", "www.example.com", "mail.example.com", "vpn.example.com", "example.com"}
	if len(names) != len(want) {
		t.Fatalf("the zone came back as %v", names)
	}
	for i := range want {
		if !strings.EqualFold(names[i], want[i]) {
			t.Errorf("name %d is %q, want %q", i, names[i], want[i])
		}
	}
}

// A server that refuses says so, and refusing is not a failure.
//
// It is what almost every server does, and correctly: a zone is handed to the
// secondaries its operator named. A caller has to be able to tell that apart
// from a server that could not be reached, because one of them is the zone
// working as intended and the other is a fact about the network.
func TestAServerThatRefusesATransferIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, s := range []*transferServer{{refuse: true}, {notAuth: true}} {
		c := &Client{Dial: s.dial(t), Timeout: 3 * time.Second}
		names, _, err := c.Transfer(ctx, "192.0.2.53", "example.com")

		if !errors.Is(err, ErrNoTransfer) {
			t.Errorf("a refusal came back as %v", err)
		}
		if len(names) != 0 {
			t.Errorf("a refusal produced names: %v", names)
		}
	}
}

// A transfer that stops part way through hands over what arrived, and says it
// was cut.
//
// Reporting nothing would throw away names the server did send; reporting them
// as a whole zone would be worse — an inventory that is quietly short is the
// one thing this must never produce (R4).
func TestATransferThatStopsPartWayThroughSaysItWasCut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	zone := "example.com"
	stopping := &transferServer{
		// No closing record, and the connection ends after it: a server that
		// stopped, which is what a timeout or a restart looks like from here.
		messages: [][]record{{
			soaFor(t, zone),
			{name(t, "www.example.com"), TypeA, []byte{192, 0, 2, 1}},
		}},
	}

	c := &Client{Dial: stopping.dial(t), Timeout: 3 * time.Second}
	names, truncated, err := c.Transfer(ctx, "192.0.2.53", zone)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if !truncated {
		t.Error("a transfer that never reached its closing record reads as whole")
	}
	if len(names) != 2 {
		t.Errorf("the names that did arrive are %v", names)
	}
}

// A record announcing more data than the message holds is refused, and takes
// no names with it.
//
// Everything in a transfer is written by whoever runs the server, including
// the lengths. A length read as given is a slice somebody else chose.
func TestATransferRecordCannotReachPastItsMessage(t *testing.T) {
	q := name(t, "example.com")

	// One record whose announced data runs past the end of the message.
	reply := message(1, 0x8400, q, TypeAXFR, record{q, TypeA, []byte{192, 0, 2, 1}})
	reply[len(reply)-5] = 0xff // the high byte of the record's length

	if _, _, err := transferNames(reply); err == nil {
		t.Error("a record reaching past its message was read")
	}
}
