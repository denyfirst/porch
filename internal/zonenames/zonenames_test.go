package zonenames

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// stubZone answers for a delegation and for the transfers asked of it, so no
// test here asks anybody anything.
type stubZone struct {
	mu sync.Mutex

	servers []string
	names   map[string][]string // server -> the zone it hands over
	failNS  bool

	asked []string
}

func (s *stubZone) LookupNS(context.Context, string) (dnsclient.ZoneAnswer, error) {
	if s.failNS {
		return dnsclient.ZoneAnswer{}, errors.New("resolver detail nobody should see")
	}
	return dnsclient.ZoneAnswer{NS: s.servers}, nil
}

func (s *stubZone) LookupAddresses(_ context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	if qtype != dnsclient.TypeA {
		return dnsclient.ZoneAnswer{}, nil
	}
	// One address each, derived from the name so a test can tell them apart.
	addr := netip.MustParseAddr("192.0.2." + octet(name))
	return dnsclient.ZoneAnswer{Addresses: []netip.Addr{addr}}, nil
}

func (s *stubZone) Transfer(_ context.Context, server, _ string) ([]string, bool, error) {
	s.mu.Lock()
	s.asked = append(s.asked, server)
	s.mu.Unlock()

	for name, zone := range s.names {
		if strings.HasPrefix(server, "192.0.2."+octet(name)+":") {
			return zone, false, nil
		}
	}
	return nil, false, dnsclient.ErrNoTransfer
}

func (s *stubZone) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// octet turns ns1.example.test into 1, so the stub resolver and the stub
// transfer agree on which server is which without a table between them.
func octet(name string) string {
	if i := strings.Index(name, "ns"); i >= 0 && len(name) > i+2 {
		return name[i+2 : i+3]
	}
	return "9"
}

// The zone hands over its own list, and it is the whole list.
//
// Every other source is a sample: a log holds what was certified, a register
// what was observed, a record what had to be published. This holds the zone.
func TestTheZoneHandsOverItsOwnList(t *testing.T) {
	zone := &stubZone{
		servers: []string{"ns1.example.test.", "ns2.example.test."},
		names: map[string][]string{
			"ns2.example.test": {
				"example.test",
				"www.example.test",
				"bitrix.example.test",
				"WWW.example.test.",
				"somebody-else.test",
			},
		},
	}

	got := (&Reader{Resolver: zone}).Under(context.Background(), "Example.TEST.")

	if got.Reason != "" {
		t.Fatalf("the transfer failed: %s", got.Reason)
	}
	if len(got.Names) != 2 || got.Names[0] != "bitrix.example.test" || got.Names[1] != "www.example.test" {
		t.Errorf("the zone came back as %v", got.Names)
	}

	// The apex is the domain that was asked about rather than something found,
	// and a name under another domain is counted rather than listed.
	if got.Foreign != 1 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 1", got.Foreign)
	}

	// The first server refused and the second answered, so one of each and the
	// name of the one that handed it over.
	if got.Servers != 2 || got.Refused != 1 || got.From != "ns2.example.test" {
		t.Errorf("the walk came back as servers=%d refused=%d from=%q",
			got.Servers, got.Refused, got.From)
	}

	// And nothing was asked after the transfer succeeded: a zone in hand is
	// the zone, and asking the rest is three more transfers for one answer.
	if n := len(zone.questions()); n != 2 {
		t.Errorf("%d servers were asked, want 2", n)
	}
}

// Every server refusing is the ordinary answer, and it is not a failure.
//
// A zone is handed to the secondaries its operator named and to nobody else —
// this project's own DNS check reports a zone that transfers to anybody as a
// finding. So the report says the servers were asked and refused, rather than
// saying something went wrong.
func TestEveryServerRefusingIsNotAFailure(t *testing.T) {
	zone := &stubZone{servers: []string{"ns1.example.test", "ns2.example.test"}}

	got := (&Reader{Resolver: zone}).Under(context.Background(), "example.test")

	if got.Reason != "" {
		t.Errorf("a zone that refused reports a failure: %s", got.Reason)
	}
	if !got.Asked {
		t.Error("a zone that refused reports that nothing was asked")
	}
	if got.Servers != 2 || got.Refused != 2 {
		t.Errorf("servers=%d refused=%d, want 2 and 2", got.Servers, got.Refused)
	}
	if len(got.Names) != 0 {
		t.Errorf("a refusal produced names: %v", got.Names)
	}
}

// A delegation that cannot be read is a fact about the lookup, not about the
// zone.
//
// Nothing was asked of any server, so saying the zone refused would be
// reporting a refusal nobody gave (R4).
func TestADelegationThatCannotBeReadIsNotARefusal(t *testing.T) {
	got := (&Reader{Resolver: &stubZone{failNS: true}}).Under(context.Background(), "example.test")

	if got.Reason == "" {
		t.Error("a delegation that could not be read reports no reason")
	}
	if got.Servers != 0 || got.Refused != 0 {
		t.Errorf("servers=%d refused=%d, want nothing asked", got.Servers, got.Refused)
	}
}

// What a server sends is cleaned before it is kept.
//
// A transfer is written by whoever runs the server, and a zone handed to
// anybody who asks is by definition one nobody is minding carefully.
func TestWhatAServerSendsIsCleanedBeforeItIsKept(t *testing.T) {
	zone := &stubZone{
		servers: []string{"ns1.example.test"},
		names: map[string][]string{
			"ns1.example.test": {
				"esc\x1b[31mape.example.test",
				"  spaced.example.test.  ",
				"UPPER.Example.Test",
			},
		},
	}

	got := (&Reader{Resolver: zone}).Under(context.Background(), "example.test")

	for _, name := range got.Names {
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%q carries a control character", name)
			}
		}
		if name != strings.ToLower(name) || strings.HasSuffix(name, ".") {
			t.Errorf("%q was kept unfolded, so one host could be listed twice", name)
		}
	}
	if len(got.Names) != 3 {
		t.Errorf("the names kept are %v", got.Names)
	}
}
