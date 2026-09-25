package webprobe

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The other form of a name is derived from it, and nothing else is looked up.
//
// Four characters added or removed. This is the line between reporting on a
// name somebody gave and enumerating an estate: a tool that also tried `mail`,
// `dev`, `staging` and `old` would be searching for hosts nobody named, which
// is what N7 refuses.
func TestTheOtherFormOfANameIsDerivedAndNotSearchedFor(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"example.com", "www.example.com"},
		{"www.example.com", "example.com"},
		{"WWW.Example.COM", "example.com"},
		{"example.com.", "www.example.com"},
		{"blog.example.com", "www.blog.example.com"},
		{"www.www.example.com", "www.example.com"},
		// Three labels where the middle is part of the registry's structure.
		// Nothing here claims to know that: telling example.co.uk from
		// blog.example.com needs the public suffix list, which this project
		// does not carry and will not write a copy of. The two forms every
		// visitor's fingers produce are what is compared, and the report names
		// which one it compared.
		{"example.co.uk", "www.example.co.uk"},
	} {
		if got := counterpartName(c.host); got != c.want {
			t.Errorf("the other form of %q read as %q, want %q", c.host, got, c.want)
		}
	}

	// And it is always exactly one name, never a list.
	if got := counterpartName("example.com"); strings.Count(got, " ") != 0 || got == "" {
		t.Errorf("one name was expected and this is %q", got)
	}
}

// The other form is asked once, for the root, and what it says is not followed.
//
// Following would buy another connection to somebody's server and no fact: a
// redirect names where it is sending a visitor in its own header. Where it
// answers with content, that is already the finding — two names, two sites,
// nothing joining them.
func TestTheOtherFormIsAskedOnceAndNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var seen []string

	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+r.URL.Path)
		mu.Unlock()

		if strings.HasPrefix(r.Host, "www.example.com") {
			// The www form sends a visitor to the bare name, and points at a
			// path so that a reader can see none of it is kept.
			http.Redirect(w, r, "https://example.com/landing?token=secret", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	got := report.Counterpart
	if !got.Asked || got.Name != "www.example.com" {
		t.Fatalf("the other form was measured as %+v", got)
	}
	if !got.Answered || got.Status != http.StatusMovedPermanently {
		t.Errorf("the www form answered 301 and this reads %+v", got)
	}
	if got.SendsTo != "example.com" {
		t.Errorf("where it sends visitors read as %q", got.SendsTo)
	}

	// A host and nothing else. The path and the query in that Location were
	// text chosen by whoever is being measured, and neither belongs in a report
	// somebody pastes into an issue tracker.
	if strings.Contains(got.SendsTo, "/") || strings.Contains(got.SendsTo, "token") {
		t.Errorf("more than a host was kept from the redirect: %q", got.SendsTo)
	}

	mu.Lock()
	asked := append([]string(nil), seen...)
	mu.Unlock()

	var times int
	for _, r := range asked {
		if strings.HasPrefix(r, "www.example.com") {
			times++
		}
	}
	if times != 1 {
		t.Errorf("the other form was asked %d times, want once: %v", times, asked)
	}

	// And the whole scan is exactly three requests of this listener: the root
	// of the scanned name, its security.txt, and the root of the other form. The
	// plaintext chain reaches a TLS listener and is refused below the handler,
	// and no IPv6 handshake is made because this package's tests resolve
	// nothing.
	//
	// Counted as a whole rather than per name, because the sabotage this catches
	// followed the redirect the other form returned — which adds a request to a
	// different name and leaves every per-name count as it was.
	if len(asked) != 3 {
		t.Errorf("the scan made %d requests, want three: %v", len(asked), asked)
	}
}

// A name this deployment may not reach is not reached, and the report says so
// rather than leaving silence to read as agreement.
//
// The other form of a name is not automatically inside a demonstration build's
// fixed list, nor inside an estate a service has been shown control of. Whatever
// decides that for every other address is asked about this one too (N6, N9).
func TestTheOtherFormGoesThroughWhateverDecidesWhatMayBeReached(t *testing.T) {
	var mu sync.Mutex
	var reached []string

	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	report, err := p.Probe(context.Background(), "example.com", func(_ context.Context, host string) string {
		if strings.HasPrefix(host, "www.") {
			return "this deployment scans only hosts it owns"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	if got := report.Counterpart; !got.Asked || !got.Refused || got.Answered {
		t.Errorf("a refused name was measured as %+v", got)
	}

	mu.Lock()
	hosts := append([]string(nil), reached...)
	mu.Unlock()
	for _, h := range hosts {
		if strings.HasPrefix(h, "www.") {
			t.Errorf("a name this deployment may not reach was connected to: %q", h)
		}
	}
}

// A name that answers nothing is still asked about its other form.
//
// This is the arrangement the row exists for and the one a scan would miss by
// giving up: the bare name is dead, the www form serves the site, and every
// visitor who types the short version gets nothing.
func TestTheOtherFormIsAskedEvenWhereTheNameItselfIsDead(t *testing.T) {
	p, _ := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "www.") {
			// The bare name accepts and hangs up without a response.
			panic(http.ErrAbortHandler)
		}
		w.WriteHeader(http.StatusOK)
	})
	p.RequestTimeout = 2 * time.Second

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	if got := report.Counterpart; !got.Asked || !got.Answered || got.Status != http.StatusOK {
		t.Errorf("the www form serves the site and the report says %+v", got)
	}
}

// A name that cannot be reached is not agreement.
//
// The sabotage that found this gap marked the other form as having answered
// when the connection failed, and nothing noticed — so a site whose www form
// does not exist would have been reported as a site whose two forms agree,
// which is the one wrong answer this row must never give.
func TestTheOtherFormBeingUnreachableIsNotAgreement(t *testing.T) {
	p, addr := twoNameServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Every name reaches the listener except the other form, which reaches
	// nothing at all — the commonest shape of this fault in the wild is a www
	// record nobody ever published.
	p.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "www.") {
			return nil, &net.DNSError{Err: "no such host", Name: address, IsNotFound: true}
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}

	report, err := p.Probe(context.Background(), "example.com", func(context.Context, string) string { return "" })
	if err != nil {
		t.Fatalf("probing: %v", err)
	}

	got := report.Counterpart
	if !got.Asked {
		t.Fatal("the other form was never asked about")
	}
	if got.Answered || got.Status != 0 || got.SendsTo != "" {
		t.Errorf("a name that does not resolve was reported as answering: %+v", got)
	}
	if got.Reason == "" {
		t.Error("a name that could not be reached gave no reason, so the row cannot say which kind of nothing it was")
	}
	// And the reason says the shape of it without the name or what the resolver
	// said (I6). The row adds the name itself, once, where it belongs.
	if strings.Contains(got.Reason, "www.example.com") || strings.Contains(got.Reason, "no such host") {
		t.Errorf("the reason echoes the input or the library: %q", got.Reason)
	}
}
