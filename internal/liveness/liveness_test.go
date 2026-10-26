package liveness

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// stubResolver answers from a table, so no test here asks anybody anything.
//
// Locked, because Checker calls a resolver from several goroutines at once and
// a stub that is not safe for that is a stub testing something the real thing
// does not do. This one was not, and the race detector said so in CI after
// every gate passed on the machine it was written on.
type stubResolver struct {
	answers map[string]dnsclient.ZoneAnswer
	fail    map[string]bool

	mu    sync.Mutex
	asked []string
}

func (s *stubResolver) LookupAddresses(_ context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	s.mu.Lock()
	s.asked = append(s.asked, name)
	failed := s.fail[name]
	answer := s.answers[name]
	s.mu.Unlock()

	if failed {
		return dnsclient.ZoneAnswer{}, errors.New("resolver said no, with detail nobody should see")
	}
	if qtype == dnsclient.TypeAAAA {
		// The stub publishes no IPv6 unless a case says otherwise, which it
		// does by putting the address under the same name.
		return dnsclient.ZoneAnswer{}, nil
	}
	return answer, nil
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
			return nil, errRefused
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

	// Locked for the same reason the resolver above is: the dialler is called
	// from every goroutine a check runs in, so a recorder that is not safe for
	// that is recording a race rather than a dial.
	var mu sync.Mutex
	var dialled []string
	c := &Checker{
		Resolver: resolver,
		Timeout:  2 * time.Second,
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			mu.Lock()
			dialled = append(dialled, address)
			mu.Unlock()
			return nil, errRefused
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
			return nil, errRefused
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

// The names worth knocking on again are the ones something is listening on.
//
// A name that does not resolve has nothing to knock on, and one that resolves
// and answers nothing has nothing to hand over. Asking either spends a timeout
// to learn what the report already says.
func TestAnsweringAreTheNamesSomethingIsListeningOn(t *testing.T) {
	got := Answering([]Name{
		{Name: "live.example.test", Status: Live},
		{Name: "silent.example.test", Status: Silent},
		{Name: "gone.example.test", Status: Gone},
		{Name: "inside.example.test", Status: Internal},
		{Name: "moved.example.test", Status: Dangling},
		{Name: "unknown.example.test", Status: Unchecked},
		{Name: "also-live.example.test", Status: Live},
	})

	if len(got) != 2 || got[0] != "live.example.test" || got[1] != "also-live.example.test" {
		t.Errorf("the names to ask again are %v", got)
	}
}

// errRefused is a refusal as the dialler words one.
var errRefused = errors.New("dial tcp 192.0.2.1:443: connect: connection refused")

// Only a refusal, an answer, or a port's own silence settles a port; a route
// this machine lacks, or a name's time running out, settles nothing.
//
// Found in the 2026-10-25 review: every failure to connect, at the first
// address alone, read as "silent: nothing answered". A name published only on
// IPv6, asked from a machine with no IPv6 route, was reported silent.
func TestOnlyWhatWasAskedSettlesAPort(t *testing.T) {
	resolver := &stubResolver{answers: map[string]dnsclient.ZoneAnswer{
		"unroutable.example.test": {Addresses: addrs(t, "2a01:4f8::10"), Existed: true},
		"both.example.test":       {Addresses: addrs(t, "2a01:4f8::11", "93.184.216.40"), Existed: true},
		"dropped.example.test":    {Addresses: addrs(t, "93.184.216.41"), Existed: true},
	}}
	// Addresses this safedial will dial; the dialler below stands in for a
	// machine with no IPv6 route.
	unreachable := errors.New("dial tcp [2a01:4f8::10]:443: connect: network is unreachable")
	c := &Checker{
		Resolver: resolver,
		Timeout:  400 * time.Millisecond,
		Dial: func(ctx context.Context, _, address string) (net.Conn, error) {
			switch {
			case strings.HasPrefix(address, "[2a01:4f8::"):
				return nil, unreachable
			case strings.HasPrefix(address, "93.184.216.41:"):
				// A firewall that drops the attempt: nothing comes back.
				<-ctx.Done()
				return nil, ctx.Err()
			default:
				return nil, errRefused
			}
		},
	}
	got := c.Check(context.Background(), []string{"unroutable.example.test", "both.example.test", "dropped.example.test"})
	want := map[string]Status{
		// Nothing was asked that could answer: not silent.
		"unroutable.example.test": Unchecked,
		// The IPv6 address could not be reached; the IPv4 one refused, which
		// settles it.
		"both.example.test": Silent,
		// Each port stayed silent for its own share of the time, so both were
		// asked and both are settled.
		"dropped.example.test": Silent,
	}
	for _, n := range got {
		if n.Status != want[n.Name] {
			t.Errorf("%s reads as %q, want %q (%+v)", n.Name, n.Status, want[n.Name], n)
		}
		if n.Status == Unchecked && n.Reason == "" {
			t.Errorf("%s is unchecked and does not say why", n.Name)
		}
	}
}

// A port the scan's own time ran out on is not a port that stayed silent: the
// address was given less than its share, and nothing was settled.
func TestAPortTheScanRanOutOnIsNotSilent(t *testing.T) {
	resolver := &stubResolver{answers: map[string]dnsclient.ZoneAnswer{
		"late.example.test": {Addresses: addrs(t, "93.184.216.42"), Existed: true},
	}}
	c := &Checker{
		Resolver: resolver,
		Timeout:  4 * time.Second,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	// The scan's time, far shorter than a port's share of the name's.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	got := c.Check(ctx, []string{"late.example.test"})
	if len(got) != 1 || got[0].Status != Unchecked || got[0].Reason == "" {
		t.Errorf("a name the scan ran out of time on reads %+v, want unchecked with a reason", got)
	}
}

// A name with no IPv4 address whose IPv6 lookup failed is not gone: it may
// resolve on IPv6 alone.
func TestAFailedIPv6LookupIsNotAGoneName(t *testing.T) {
	c := &Checker{Resolver: sixFails{}, Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errRefused }}
	got := c.Check(context.Background(), []string{"v6only.example.test"})
	if got[0].Status == Gone || got[0].Reason == "" {
		t.Errorf("a name whose IPv6 lookup failed reads as %+v", got[0])
	}
}

// sixFails answers A with nothing and fails the AAAA question.
type sixFails struct{}

func (sixFails) LookupAddresses(_ context.Context, _ string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	if qtype == dnsclient.TypeAAAA {
		return dnsclient.ZoneAnswer{}, errors.New("no answer")
	}
	return dnsclient.ZoneAnswer{Existed: true}, nil
}
