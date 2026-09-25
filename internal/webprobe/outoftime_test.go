package webprobe

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// When the scan's own deadline passes, the three measurements that run last say
// so — and do not say the host was at fault.
//
// They share one budget with the two chains and they run after them, so a slow
// site spends the time and these are what go without. Before this, each of them
// reported the failure it saw: the security contact could not be fetched, the
// IPv6 address did not answer, the other form could not be reached. Three
// sentences about this program's clock, printed as findings about somebody
// else's server, in the part of the report an operator is most likely to act
// on (R4).
func TestAScanThatRanOutOfTimeSaysSoRatherThanBlamingTheHost(t *testing.T) {
	var mu sync.Mutex
	var reached int

	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	p.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}

	// A budget already spent. Probe takes the tighter of its own deadline and
	// the caller's, so this is the state a slow site leaves it in.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	report, err := p.Probe(ctx, "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	// Nothing here is a statement about the host.
	for _, says := range []string{
		report.SecurityTxt.Reason,
		report.IPv6.Reason,
		report.Counterpart.Reason,
	} {
		if says == "" {
			continue
		}
		if !strings.Contains(says, "ran out of time") {
			t.Errorf("a measurement that never ran says %q, which reads as a fault in the host", says)
		}
	}

	// And in particular, not the two sentences that would have been printed.
	if report.IPv6.Reason == "the address did not answer on 443" {
		t.Error("a scan with no time left reported the site as not answering over IPv6")
	}
	if report.IPv6.NoRouteFromHere {
		t.Error("a scan with no time left blamed this machine's network, which was never consulted")
	}
	if report.Counterpart.Reason == "could not be reached" {
		t.Error("a scan with no time left reported the other form of the name as unreachable")
	}

	// The two that were attempted still say they were: the difference between a
	// question nobody put and one that ran out of time is the whole point of
	// the sentence.
	//
	// The security contact is the exception, correctly. It is asked for only
	// where the secure chain answered, and with no time left it did not — so
	// that row reads "not looked for", which is true and is not a claim about
	// the host either.
	if !report.IPv6.Asked || !report.Counterpart.Asked {
		t.Errorf("a measurement that ran out of time reads as one nobody attempted: %+v %+v",
			report.IPv6, report.Counterpart)
	}
	if report.SecurityTxt.Asked {
		t.Errorf("the file was asked for although nothing answered: %+v", report.SecurityTxt)
	}

	// And no connection was opened that could not finish. A request this
	// program makes knowing it cannot complete is a line in somebody's log
	// bought for nothing.
	mu.Lock()
	n := reached
	mu.Unlock()
	if n != 0 {
		t.Errorf("%d requests were made with no time left to read the answers", n)
	}
}

// The security contact says the same thing where the deadline passes during the
// fetch rather than before it.
func TestTheSecurityContactSaysTheScanRanOutRatherThanThatTheFileIsMissing(t *testing.T) {
	// The root answers at once and the file never does, which is what a site
	// that has spent the scan's budget looks like from here. A slow connection
	// rather than a slow dial, because the transport keeps the chain's
	// connection alive and reuses it for this request — so a test that made the
	// third dial hang would find there was no third dial.
	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			hang(r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	p.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	// The whole scan is given less time than one request, so the budget that
	// runs out during the fetch is the scan's own rather than the per-request
	// one — which is the path this exists to check.
	p.TotalTimeout = 2 * time.Second
	p.RequestTimeout = 5 * time.Second

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}
	if got := report.SecurityTxt; got.Served {
		t.Fatalf("nothing answered and the file reads as published: %+v", got)
	}
	if got := report.SecurityTxt.Reason; !strings.Contains(got, "ran out of time") {
		t.Errorf("a fetch the scan ran out of time during reads %q, which is a claim about the site", got)
	}
}

// With no time left, nothing is looked up and nothing is dialled.
//
// Saying so in the report is half of it; the other half is not spending
// somebody else's resources to find out what the clock already says. A
// resolver query and three connections, each of which cannot finish, are a
// query and three lines in a log bought for nothing.
//
// The arrangement is the one a slow site produces: the secure chain answers,
// the plaintext chain hangs until the budget is gone, and everything that runs
// after the chains finds no time left. Two guards would otherwise cover for
// each other — a sabotage removing the one before the IPv6 lookup escaped,
// because the one after the handshake caught the same case and no test could
// tell that a lookup and a dial had happened anyway.
func TestNothingIsLookedUpOrDialledWithNoTimeLeft(t *testing.T) {
	var mu sync.Mutex
	var lookups int
	var dialled []string

	// A listener that accepts and answers nothing, for the plaintext chain to
	// spend the budget on.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	p.TotalTimeout = 2 * time.Second
	p.RequestTimeout = 5 * time.Second
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) {
		mu.Lock()
		lookups++
		mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	p.Dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, address)
		mu.Unlock()
		if strings.HasSuffix(address, ":"+plainPort) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", silent.Addr().String())
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	if !answered(report.Secure) {
		t.Fatal("the secure chain did not answer, so this tested something else")
	}

	mu.Lock()
	n := lookups
	tried := append([]string(nil), dialled...)
	mu.Unlock()

	if n != 0 {
		t.Errorf("%d IPv6 lookups were made with no time left to use the answer", n)
	}
	for _, address := range tried {
		if strings.HasPrefix(address, "www.") {
			t.Errorf("the other form of the name was dialled with no time left: %q", address)
		}
	}

	for what, says := range map[string]string{
		"the security contact": report.SecurityTxt.Reason,
		"IPv6":                 report.IPv6.Reason,
		"the other form":       report.Counterpart.Reason,
	} {
		if !strings.Contains(says, "ran out of time") {
			t.Errorf("%s reads %q, which is a claim about the host rather than about the clock", what, says)
		}
	}
}

// Whatever decides which names may be reached is not asked on behalf of a
// measurement that cannot finish.
//
// That decision is not free. An installation may have to resolve the name, or
// consult which estates it has been shown control of, and doing that for a
// question whose answer cannot be used is work spent for nothing. It is also
// the only observable difference the guard makes: the transport refuses a
// request on an expired context before it dials, so the connection would not
// have happened either way.
func TestTheReachDecisionIsNotAskedWithNoTimeLeft(t *testing.T) {
	var mu sync.Mutex
	var asked []string

	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	p.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	if _, err := p.Probe(ctx, "example.com", func(_ context.Context, host string) string {
		mu.Lock()
		asked = append(asked, host)
		mu.Unlock()
		return ""
	}); err != nil {
		t.Fatalf("probing: %v", err)
	}

	mu.Lock()
	names := append([]string(nil), asked...)
	mu.Unlock()
	for _, name := range names {
		if strings.HasPrefix(name, "www.") {
			t.Errorf("the deployment was asked whether it may reach %q, for a measurement with no time to make", name)
		}
	}
}

// The other form says the scan ran out where the deadline passes during its
// request rather than before it.
//
// The budget survives the chains, the security contact and the IPv6 lookup, and
// goes during this one — which is the only way to reach the second of the two
// guards, and the arrangement a genuinely slow site produces.
func TestTheOtherFormSaysTheScanRanOutWhenTheDeadlinePassesMidRequest(t *testing.T) {
	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "www.") {
			hang(r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	p.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	p.TotalTimeout = 2 * time.Second
	p.RequestTimeout = 5 * time.Second

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	got := report.Counterpart
	if got.Answered {
		t.Fatalf("a request that never completed reads as an answer: %+v", got)
	}
	if !strings.Contains(got.Reason, "ran out of time") {
		t.Errorf("the other form reads %q, which blames the name for this scan's clock", got.Reason)
	}
}

// hang holds a response until the client gives up, and then a little longer at
// most.
//
// Bounded rather than waiting only on the request's context. A handler blocked
// on that alone kept the test server's Close waiting for minutes: the client
// abandons the request at its own deadline, and on a kept-alive connection the
// server side is not always told. The bound is well past every deadline these
// tests set, so what is measured is still the client giving up.
func hang(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(4 * time.Second):
	}
}

// A deadline that passes during the IPv6 handshake is answered before this
// machine's own network is consulted.
//
// Without that order, a scan that ran out of time on a machine with no IPv6
// would report the one thing it is least entitled to claim: that the site does
// not answer over IPv6 and that nothing here could have checked. Two wrong
// sentences from one expired clock — and on a machine that does have IPv6, the
// first of them on its own.
func TestADeadlineDuringTheIPv6HandshakeIsNotTheLocalNetworksFault(t *testing.T) {
	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	p.LookupIPv6 = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	p.Dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		// Everything but the IPv6 address answers at once; that one holds the
		// connection open until the scan's budget is gone, which is the state
		// the guard exists for.
		if strings.HasPrefix(address, "[") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	p.TotalTimeout = 2 * time.Second
	p.RequestTimeout = 5 * time.Second

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	got := report.IPv6
	if !strings.Contains(got.Reason, "ran out of time") {
		t.Errorf("a handshake the scan ran out of time during reads %q", got.Reason)
	}
	if got.NoRouteFromHere {
		t.Error("a scan that ran out of time reported this machine as having no IPv6, which was never the question")
	}
	if got.Answered || got.Verified {
		t.Errorf("a handshake that never completed reads as an answer: %+v", got)
	}
}
