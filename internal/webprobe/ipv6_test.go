package webprobe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// An address the zone published is counted as published, and only an address
// something may dial is dialled.
//
// The two halves are separate on purpose. A name that publishes one address in
// a range nothing may connect to has published an address — that is a fact
// about the zone, and a report saying "no address published" about it would be
// wrong in the direction that hides a misconfiguration. It has also published
// nothing this program will open a connection to, and the row says which of
// those two it is.
func TestWhichPublishedAddressesCanBeTried(t *testing.T) {
	addr := func(s string) netip.Addr {
		t.Helper()
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		return a
	}

	for _, c := range []struct {
		name            string
		addrs           []netip.Addr
		published, tria int
	}{
		{"nothing published", nil, 0, 0},
		{"one ordinary address", []netip.Addr{addr("2606:4700::1111")}, 1, 1},
		{
			// Published, and in the range RFC 3849 set aside for documentation.
			// Somebody has copied an example into their zone, which is a real
			// fault and not an absent record.
			"published and only in a documentation range",
			[]netip.Addr{addr("2001:db8::1")}, 1, 0,
		},
		{
			"published on a network nothing may reach",
			[]netip.Addr{addr("fd00::1"), addr("fe80::1"), addr("::1")}, 3, 0,
		},
		{
			"one of each",
			[]netip.Addr{addr("2001:db8::1"), addr("2606:4700::1111")}, 2, 1,
		},
		{
			// A resolver asked for ip6 can answer with a mapped IPv4 address.
			// Counting one would make a name with no AAAA record read as
			// having one, which is the opposite of what this row is for.
			"a mapped IPv4 address is not an IPv6 address",
			[]netip.Addr{addr("::ffff:93.184.216.34")}, 0, 0,
		},
	} {
		published, usable := usableIPv6(c.addrs)
		if published != c.published || len(usable) != c.tria {
			t.Errorf("%s: %d published and %d dialable, want %d and %d",
				c.name, published, len(usable), c.published, c.tria)
		}
		// And nothing that came back as dialable is something the dialler
		// would refuse. This is the half that must not drift: the list here is
		// what a connection is opened to.
		for _, a := range usable {
			if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
				t.Errorf("%s: %v came back as dialable", c.name, a)
			}
		}
	}
}

// A site answering over IPv6 with a certificate for the name is one thing, and
// answering with a certificate for something else is another.
//
// "Reachable and unusable" is a different piece of work from "unreachable" for
// whoever has to fix it, and the report says which. This runs over loopback,
// which is an address the dialler refuses in every real scan — usableIPv6
// keeps it out, and the dialler refuses it again — so the connection is made
// with the package's dial hook set, exactly as every other test here reaches a
// local listener.
func TestWhatAnIPv6HandshakeSaysAboutTheCertificate(t *testing.T) {
	srv, pool := ipv6Server(t)

	p := &Prober{
		RequestTimeout: 5 * time.Second,
		// The network is deliberately not passed through. The listener is on
		// loopback IPv4, and what is under test is what the handshake concludes
		// rather than which family the kernel opened.
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", srv)
		},
	}

	answered, verified, reason := p.handshakeOverIPv6(context.Background(), "example.com", netip.MustParseAddr("2606:4700::1111"), pool)
	if !answered || !verified || reason != "" {
		t.Errorf("a valid certificate read as answered=%v verified=%v reason=%q", answered, verified, reason)
	}

	// The same server, asked about a name its certificate does not cover.
	answered, verified, reason = p.handshakeOverIPv6(context.Background(), "other.example", netip.MustParseAddr("2606:4700::1111"), pool)
	if !answered {
		t.Error("a host that completed a connection read as not answering")
	}
	if verified {
		t.Error("a certificate for another name verified")
	}
	if reason == "" {
		t.Error("a failed verification gave no reason")
	}

	// Nothing answering at all is not the same as answering badly.
	dead := &Prober{
		RequestTimeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	}
	answered, verified, reason = dead.handshakeOverIPv6(context.Background(), "example.com", netip.MustParseAddr("2606:4700::1111"), pool)
	if answered || verified {
		t.Errorf("a host that refused the connection read as answered=%v verified=%v", answered, verified)
	}
	if reason == "" {
		t.Error("a refused connection gave no reason")
	}
	// And the reason says the shape of the failure without the address or what
	// the library said about it (I6).
	if reason != "the address did not answer on 443" {
		t.Errorf("the reason reads %q", reason)
	}
}

// ipv6Server starts a TLS listener for example.com and returns its address and
// the pool that verifies it.
func ipv6Server(t *testing.T) (addr string, pool *x509.CertPool) {
	t.Helper()

	p, address := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	if p.Roots == nil {
		t.Fatal("the test server came back without the pool that verifies it")
	}
	return address, p.Roots
}

// A failure to reach an IPv6 address is a fact about the site only where this
// machine could have reached it.
//
// The sabotage that found this gap replaced the line deciding it, in both
// directions, and nothing failed either time — so a scan from a machine with no
// IPv6 would have printed "did not answer" about every site in the world, and a
// scan from one with IPv6 would have excused every site that really was broken.
func TestWhoAFailedIPv6ConnectionIsAboutDependsOnThisMachine(t *testing.T) {
	const silent = "the address did not answer on 443"

	for _, c := range []struct {
		name           string
		answered       bool
		reason         string
		machineHasIPv6 bool
		want           bool
	}{
		{"nothing answered and this machine could have reached it", false, silent, true, false},
		{"nothing answered and this machine has no IPv6 at all", false, silent, false, true},
		{"the site answered, so this machine's network is beside the point", true, "", false, false},
		{"the site answered badly, which is still an answer", true, "the certificate presented over IPv6 did not verify for this name", false, false},
		{"nothing to explain", false, "", false, false},
	} {
		if got := unmeasurable(c.answered, c.reason, c.machineHasIPv6); got != c.want {
			t.Errorf("%s: read as unmeasurable=%v, want %v", c.name, got, c.want)
		}
	}
}

// A link-local address is not a route to anywhere.
//
// Every IPv6-capable interface has one whether or not a single packet can
// leave the machine. Counting it would make every machine look connected, and
// the distinction between "the site does not answer" and "this machine cannot
// ask" would stop existing without anything failing.
func TestWhatCountsAsThisMachineHavingIPv6(t *testing.T) {
	addrs := func(ss ...string) []netip.Addr {
		t.Helper()
		var out []netip.Addr
		for _, s := range ss {
			a, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("parsing %q: %v", s, err)
			}
			out = append(out, a)
		}
		return out
	}

	for _, c := range []struct {
		name  string
		addrs []netip.Addr
		want  bool
	}{
		{"no addresses at all", nil, false},
		{"IPv4 only", addrs("192.0.2.10", "10.0.0.4"), false},
		{"link-local only, which every capable interface has", addrs("fe80::1"), false},
		{"a global address", addrs("2001:4860:4860::8888"), true},
		{"link-local beside a global one", addrs("fe80::1", "2001:4860:4860::8888"), true},
		{"a mapped IPv4 address is not IPv6", addrs("::ffff:192.0.2.10"), false},
		{"a unique local address routes inside one site and not out of it", addrs("fd00::1"), true},
	} {
		if got := hasGlobalIPv6(c.addrs); got != c.want {
			t.Errorf("%s: read as %v, want %v", c.name, got, c.want)
		}
	}
}

// The measurement runs on a scan, and what it found reaches the report.
//
// Nothing asserted this, so the whole call could be deleted and every report
// would quietly read "not measured" — which is exactly the sentence that means
// this project did not look (R4). The resolver is the prober's own hook, so no
// query leaves this machine.
func TestTheIPv6MeasurementRunsOnAScanAndReachesTheReport(t *testing.T) {
	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	// The name resolves to one ordinary global address, and everything is
	// dialled to the listener whatever address is asked for.
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	p.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	got := report.IPv6
	if !got.Asked {
		t.Fatal("the scan did not measure IPv6 at all")
	}
	if got.Published != 1 || !got.Answered || !got.Verified {
		t.Errorf("the report carries %+v about a name that answers on its IPv6 address", got)
	}
	if got.NoRouteFromHere {
		t.Error("a scan that reached the address said this machine has no IPv6")
	}

	// And a name publishing nothing is a decision somebody made, not a failure
	// and not a silence.
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	report, err = p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}
	if !report.IPv6.Asked || report.IPv6.Published != 0 || report.IPv6.Reason != "" {
		t.Errorf("a name with no AAAA record read as %+v", report.IPv6)
	}
}
