package liveness

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// stubResolver answers from a table, so no test here asks anybody anything.
type stubResolver struct {
	answers map[string]dnsclient.ZoneAnswer
	fail    map[string]bool
	asked   []string
}

func (s *stubResolver) LookupAddresses(_ context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	s.asked = append(s.asked, name)
	if s.fail[name] {
		return dnsclient.ZoneAnswer{}, errors.New("resolver said no, with detail nobody should see")
	}
	if qtype == dnsclient.TypeAAAA {
		// The stub publishes no IPv6 unless a case says otherwise, which it
		// does by putting the address under the same name.
		return dnsclient.ZoneAnswer{}, nil
	}
	return s.answers[name], nil
}

func addrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range list {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// Each state a name can be in is its own answer.
//
// The five are not shades of one thing. An operator reads the first column and
// acts: live needs checking, silent needs explaining, internal means this scan
// could not see it, gone means delete the record, dangling means somebody else
// may be able to claim what it points at. Collapsing any two of them into
// "nothing answered" is what makes an inventory unusable.
func TestEachStateIsItsOwnAnswer(t *testing.T) {
	resolver := &stubResolver{
		answers: map[string]dnsclient.ZoneAnswer{
			"live.example.test":     {Addresses: addrs(t, "93.184.216.34"), Existed: true},
			"silent.example.test":   {Addresses: addrs(t, "93.184.216.35"), Existed: true},
			"inside.example.test":   {Addresses: addrs(t, "172.23.0.11"), Existed: true},
			"mixed.example.test":    {Addresses: addrs(t, "10.0.0.1", "93.184.216.36"), Existed: true},
			"gone.example.test":     {},
			"dangling.example.test": {Alias: []string{"target.elsewhere.test."}},
		},
		fail: map[string]bool{"broken.example.test": true},
	}

	c := &Checker{
		Resolver: resolver,
		Timeout:  2 * time.Second,
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			// Only one address is listening, and only on 443.
			if address == "93.184.216.34:443" {
				return fakeConn{}, nil
			}
			return nil, errors.New("refused")
		},
	}

	got := c.Check(context.Background(), []string{
		"live.example.test", "silent.example.test", "inside.example.test",
		"mixed.example.test", "gone.example.test", "dangling.example.test",
		"broken.example.test",
	})

	want := map[string]Status{
		"live.example.test":     Live,
		"silent.example.test":   Silent,
		"inside.example.test":   Internal,
		"mixed.example.test":    Silent,
		"gone.example.test":     Gone,
		"dangling.example.test": Dangling,
		"broken.example.test":   Unchecked,
	}
	for _, n := range got {
		if want[n.Name] != n.Status {
			t.Errorf("%s reads as %q, want %q (%+v)", n.Name, n.Status, want[n.Name], n)
		}
	}

	// The order of the answer is the order of the question, so a caller that
	// sorted its names keeps its order.
	for i, name := range []string{
		"live.example.test", "silent.example.test", "inside.example.test",
		"mixed.example.test", "gone.example.test", "dangling.example.test",
		"broken.example.test",
	} {
		if got[i].Name != name {
			t.Errorf("answer %d is for %q, want %q", i, got[i].Name, name)
		}
	}

	// A name that is live says which port answered, because "it answers" and
	// "it answers on 80 only" are different things to act on.
	for _, n := range got {
		if n.Name == "live.example.test" {
			if len(n.Answered) != 1 || n.Answered[0] != "443" {
				t.Errorf("the live name answered on %v", n.Answered)
			}
		}
	}

	// And a resolver's own words never reach the report (I6).
	for _, n := range got {
		if n.Reason != "" && n.Reason != "the name could not be looked up" {
			t.Errorf("%s gave the reason %q", n.Name, n.Reason)
		}
	}
}

// An address nothing may dial is never dialled.
//
// This is the case an organisation's own resolver produces for its own names,
// and it is the one a scan run from a desk inside that organisation hits. A
// report that said "nothing answered" would be describing the office network as
// the state of the estate. It is also a refusal this must make for itself
// rather than leave to the dialler: a connection attempt to a private address
// is a connection attempt, whoever refuses it.
func TestNothingPrivateIsEverDialled(t *testing.T) {
	resolver := &stubResolver{answers: map[string]dnsclient.ZoneAnswer{
		"a.example.test": {Addresses: addrs(t, "172.23.0.11"), Existed: true},
		"b.example.test": {Addresses: addrs(t, "127.0.0.1"), Existed: true},
		"c.example.test": {Addresses: addrs(t, "169.254.10.1"), Existed: true},
		"d.example.test": {Addresses: addrs(t, "fd00::1"), Existed: true},
	}}

	var dialled []string
	c := &Checker{
		Resolver: resolver,
		Timeout:  2 * time.Second,
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialled = append(dialled, address)
			return nil, errors.New("refused")
		},
	}

	got := c.Check(context.Background(), []string{
		"a.example.test", "b.example.test", "c.example.test", "d.example.test",
	})

	for _, n := range got {
		if n.Status != Internal {
			t.Errorf("%s with only an unreachable address reads as %q", n.Name, n.Status)
		}
	}
	if len(dialled) != 0 {
		t.Errorf("addresses nothing may dial were dialled: %v", dialled)
	}
}

// An inventory larger than the bound is cut rather than followed forever.
func TestAnEstatePastTheBoundIsCut(t *testing.T) {
	resolver := &stubResolver{answers: map[string]dnsclient.ZoneAnswer{}}
	c := &Checker{Resolver: resolver, Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("refused")
		}}

	names := make([]string, maxNames+50)
	for i := range names {
		names[i] = "n.example.test"
	}
	if got := len(c.Check(context.Background(), names)); got != maxNames {
		t.Errorf("%d names came back, want the bound of %d", got, maxNames)
	}
}

// fakeConn is a connection that was accepted and is closed at once.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }
