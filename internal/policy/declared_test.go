package policy

import (
	"strings"
	"testing"
	"time"
)

// Every header a report lists is listed whether or not it was there, and what
// is absent says "none" rather than not appearing.
//
// The whole point of the block: an operator reading a clean report could not
// tell a site that declares a content policy from one that declares nothing,
// because neither produced a row. "none" is a measurement — the response was
// read and carried no such header — and a missing row is not (R4).
func TestEveryDeclarationIsListedWhetherOrNotItWasThere(t *testing.T) {
	rows := Declarations(HeaderFacts{
		Answered: true,
		Present:  map[string]bool{"X-Frame-Options": true},
		Values:   map[string]string{"X-Frame-Options": "DENY"},
	}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)

	said := map[string]string{}
	for _, r := range rows {
		said[r.Label] = r.Says
	}

	for _, label := range []string{
		"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
		"Referrer-Policy", "Permissions-Policy",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy",
		"Access-Control-Allow-Origin", "Content-Security-Policy", "Cookies", "The page",
	} {
		if _, ok := said[label]; !ok {
			t.Errorf("%s has no row, so a reader cannot tell it was looked for", label)
		}
	}

	if said["Served over"] != "none" {
		t.Errorf("a response whose protocol was not recorded reads %q", said["Served over"])
	}
	if said["X-Frame-Options"] != "DENY" {
		t.Errorf("what the header said reads %q", said["X-Frame-Options"])
	}
	if said["Referrer-Policy"] != "none" {
		t.Errorf("a header that was not there reads %q, and it was measured", said["Referrer-Policy"])
	}
	if said["Cookies"] != "none set" {
		t.Errorf("a response that set no cookie reads %q", said["Cookies"])
	}

	// And each attribute is counted for itself, on a set where no two of them
	// come to the same number. One of each would agree with itself however the
	// counts were wired, which is a fixture that cannot fail.
	counted := Declarations(HeaderFacts{Answered: true}, ContentFacts{}, []CookieFacts{
		{Name: "a", Secure: true},
		{Name: "b", Secure: true, HTTPOnly: true},
		{Name: "c", SameSite: "Lax"},
	}, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	for _, r := range counted {
		if r.Label == "Cookies" && r.Says != "3 set; 2 Secure, 1 HttpOnly, 1 with SameSite" {
			t.Errorf("the cookies are counted as %q", r.Says)
		}
	}
	if said["The page"] != "not read" {
		t.Errorf("a page nobody read reads %q, which is not the same as one with nothing wrong", said["The page"])
	}

	// A response nobody reached declares nothing at all. An empty list says the
	// question was never put; a list of twelve "none" rows would say the site
	// answered and carried none of them.
	if got := Declarations(HeaderFacts{}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow); got != nil {
		t.Errorf("a response nobody reached declared %v", got)
	}
}

// Where a content policy is declared, and what a page pulls in, are said in
// words rather than by reproducing them.
//
// A content policy runs to thousands of characters, and the two places it can
// be declared are what somebody changing it needs. What a page pulls in is the
// half of a site's security nobody configures: a page served perfectly can
// still carry a script from somewhere else.
func TestTheContentPolicyAndThePageAreSaidInWords(t *testing.T) {
	says := func(f HeaderFacts, c ContentFacts) map[string]string {
		f.Answered = true
		out := map[string]string{}
		for _, r := range Declarations(f, c, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow) {
			out[r.Label] = r.Says
		}
		return out
	}

	both := says(HeaderFacts{
		Present: map[string]bool{"Content-Security-Policy": true},
		MetaCSP: true,
	}, ContentFacts{Read: true})
	if both["Content-Security-Policy"] != "declared in a header and in the page" {
		t.Errorf("a policy declared twice reads %q", both["Content-Security-Policy"])
	}

	// Report-only is declared and enforces nothing, which is a third state and
	// not either of the other two.
	only := says(HeaderFacts{
		Present:    map[string]bool{"Content-Security-Policy-Report-Only": true},
		MarkupRead: true,
	}, ContentFacts{Read: true})
	if !strings.Contains(only["Content-Security-Policy"], "report-only") {
		t.Errorf("a report-only policy reads %q", only["Content-Security-Policy"])
	}

	// No header and no page read is half an answer, and says so: a policy can
	// be declared in markup, and the markup was never looked at.
	unread := says(HeaderFacts{}, ContentFacts{})
	if !strings.Contains(unread["Content-Security-Policy"], "the page was not read") {
		t.Errorf("a policy nobody could have seen reads %q", unread["Content-Security-Policy"])
	}

	page := says(HeaderFacts{}, ContentFacts{
		Read: true, Blocking: []string{"a.example"}, Forms: []string{"b.example"},
		Unverified: []string{"cdn.example"},
	})
	for _, want := range []string{"2 things on it arrive in the clear", "1 origins it runs code from unchecked"} {
		if !strings.Contains(page["The page"], want) {
			t.Errorf("the page row reads %q, and does not say %q", page["The page"], want)
		}
	}

	// A value longer than a row is cut, and says it was: this is the one text
	// in the block chosen by whoever is being measured.
	long := says(HeaderFacts{
		Present: map[string]bool{"Permissions-Policy": true},
		Values:  map[string]string{"Permissions-Policy": strings.Repeat("x", 400)},
	}, ContentFacts{})
	if !strings.HasSuffix(long["Permissions-Policy"], "…") || len(long["Permissions-Policy"]) > maxDeclared+8 {
		t.Errorf("a long value was printed in full: %d characters", len(long["Permissions-Policy"]))
	}
}

// The version of HTTP that carried the response is a row, and is never graded.
//
// It costs no request — the transport settled it over ALPN during a handshake
// the scan already made — and no document requires a version. This project's
// own service answers HTTP/1.1 on purpose, which is the case that decides it:
// a rule here would grade a deliberate choice as a fault.
func TestTheProtocolIsAFactAndNotAFinding(t *testing.T) {
	rows := Declarations(HeaderFacts{Answered: true, Protocol: "HTTP/2.0"}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	if len(rows) == 0 || rows[0].Label != "Served over" {
		t.Fatalf("the first thing a report says about the response is %+v", rows)
	}
	if rows[0].Says != "HTTP/2.0" {
		t.Errorf("the protocol reads %q", rows[0].Says)
	}

	// And an older version is the same kind of row, carrying no verdict with
	// it: nothing in this package turns it into one.
	old := Declarations(HeaderFacts{Answered: true, Protocol: "HTTP/1.1"}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	if old[0].Says != "HTTP/1.1" {
		t.Errorf("an older protocol reads %q", old[0].Says)
	}
}

// testNow is the clock these rows are read against. A fixed date, because the
// one row that reads a clock is about whether a date has passed, and a test
// that used the real one would mean something different every day it ran.
var testNow = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// The security contact row says which kind of nothing it found, and says when
// a published contact has expired.
//
// Reported, never graded: RFC 9116 defines a format and requires it of nobody,
// so a verdict here would be a threshold this project invented (R21). What the
// row is for is the state that is neither present nor absent — a file that is
// there and expired two years ago, which tells whoever found a fault that they
// are expected at an address where nobody is waiting.
func TestTheSecurityContactRowSaysWhichNothingItFound(t *testing.T) {
	for _, c := range []struct {
		name  string
		facts SecurityTxtFacts
		want  string
	}{
		{"never looked for", SecurityTxtFacts{}, "not looked for"},
		{"the server says it has none", SecurityTxtFacts{Asked: true}, "none published"},
		{"nothing answered", SecurityTxtFacts{Asked: true, Reason: "the file could not be fetched over HTTPS"},
			"the file could not be fetched over HTTPS"},
		{"published and standing", SecurityTxtFacts{
			Asked: true, Served: true, Contacts: 2,
			Expires: testNow.Add(24 * time.Hour),
		}, "published, 2 contacts; expires 2026-09-25"},
		{"published and expired", SecurityTxtFacts{
			Asked: true, Served: true, Contacts: 1,
			Expires: testNow.Add(-24 * time.Hour),
		}, "published, 1 contact; expired 2026-09-23"},
		{"published with no expiry", SecurityTxtFacts{Asked: true, Served: true, Contacts: 1},
			"published, 1 contact; no expiry date, which RFC 9116 requires"},
		{"published naming nobody", SecurityTxtFacts{
			Asked: true, Served: true, Expires: testNow.Add(24 * time.Hour),
		}, "published, naming no contact; expires 2026-09-25"},
		{"signed", SecurityTxtFacts{
			Asked: true, Served: true, Contacts: 1, Signed: true,
			Expires: testNow.Add(24 * time.Hour),
		}, "published, 1 contact; expires 2026-09-25; signed"},
	} {
		if got := securityTxtLine(c.facts, testNow); got != c.want {
			t.Errorf("%s read as %q, not %q", c.name, got, c.want)
		}
	}

	// And the row is drawn on every answered scan, including the one where
	// nothing was found: a row that disappears when there is nothing to say
	// reads as a question nobody asked (R4).
	rows := Declarations(HeaderFacts{Answered: true}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	var seen bool
	for _, r := range rows {
		if r.Label == "Security contact" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no security contact row was drawn: %+v", rows)
	}
}

// The IPv6 row says which kind of "no" it found, and never blames a site for
// the scanner's own network.
//
// The distinction the row exists for is the one in the middle: a name that
// publishes an address and does not answer on it is a real fault, and a
// machine with no IPv6 address of its own learns nothing about that name. Said
// the same way, the second becomes a finding about somebody else's server
// arrived at from a fact about this one (R4).
func TestTheIPv6RowSaysWhichKindOfNoItFound(t *testing.T) {
	for _, c := range []struct {
		name  string
		facts IPv6Facts
		want  string
	}{
		{"never measured", IPv6Facts{}, "not measured"},
		{"the zone publishes none", IPv6Facts{Asked: true},
			"no address published (no AAAA record)"},
		{"published and answering", IPv6Facts{Asked: true, Published: 1, Answered: true, Verified: true},
			"1 address published, answers on 443, certificate valid for this name"},
		{"published and silent", IPv6Facts{Asked: true, Published: 2, Reason: "the address did not answer on 443"},
			"2 addresses published, the address did not answer on 443"},
		{"answering with the wrong certificate", IPv6Facts{
			Asked: true, Published: 1, Answered: true,
			Reason: "the certificate presented over IPv6 did not verify for this name",
		}, "1 address published, answers on 443, the certificate presented over IPv6 did not verify for this name"},
		{"nothing to measure from", IPv6Facts{
			Asked: true, Published: 1, NoRouteFromHere: true,
			Reason: "the address did not answer on 443",
		}, "1 address published, and this machine has no IPv6 address of its own, so nothing was measured"},
		{"published in a range nothing may dial", IPv6Facts{Asked: true, Published: 1},
			"1 address published, none of them could be tried"},
	} {
		if got := ipv6Line(c.facts); got != c.want {
			t.Errorf("%s read as %q, not %q", c.name, got, c.want)
		}
	}

	// A machine with no route of its own never produces a sentence that reads
	// as a fault in the site. This is the whole point of the field, so it is
	// asserted about the words rather than about the struct.
	blind := ipv6Line(IPv6Facts{Asked: true, Published: 1, NoRouteFromHere: true, Reason: "the address did not answer on 443"})
	if strings.Contains(blind, "did not answer") {
		t.Errorf("a scan from a machine with no IPv6 said the site did not answer: %q", blind)
	}

	// And the row is drawn on every answered scan, including the one where
	// there is nothing to say (R4).
	rows := Declarations(HeaderFacts{Answered: true}, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	var seen bool
	for _, r := range rows {
		if r.Label == "Over IPv6" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no IPv6 row was drawn: %+v", rows)
	}
}

// The other form of the name is compared, and the row says which way the two
// forms agree or that they do not.
//
// The question an operator cannot ask of their own site: their habit answers it
// for them. Whoever types the bare name daily never learns what a visitor
// typing www gets, and whoever bookmarked www never learns what happens at the
// bare name. Reported, never graded — no document requires a www form to exist
// or to redirect (R21) — and the commonest fault it surfaces is two names
// serving two sites, one of which stopped being updated years ago.
func TestTheOtherFormOfTheNameRowSaysHowTheTwoAgree(t *testing.T) {
	for _, c := range []struct {
		name  string
		facts CounterpartFacts
		want  string
	}{
		{"never measured", CounterpartFacts{}, "not measured"},
		{"out of this deployment's reach", CounterpartFacts{
			Asked: true, Name: "www.example.com", Refused: true,
		}, "www.example.com was not checked: this deployment may not reach it"},
		{"the other form does not exist", CounterpartFacts{
			Asked: true, Name: "www.example.com", Reason: "could not be reached",
		}, "www.example.com could not be reached"},
		{"the other form sends visitors here", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 301,
			SendsTo: "example.com", Scanned: "example.com",
		}, "www.example.com sends visitors to this name"},
		{"this name sends visitors there", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 200,
			Scanned: "example.com", LandsOn: "www.example.com",
		}, "this name sends visitors to www.example.com"},
		{"both end up somewhere else together", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 301,
			SendsTo: "shop.example.net", Scanned: "example.com", LandsOn: "shop.example.net",
		}, "www.example.com and this name both end up at shop.example.net"},
		{"the other form goes somewhere of its own", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 302,
			SendsTo: "old.example.net", Scanned: "example.com",
		}, "www.example.com sends visitors to old.example.net"},
		{"two names, two sites, nothing joining them", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 200,
			Scanned: "example.com",
		}, "www.example.com answers with its own site, and nothing sends visitors from one form to the other"},
		{"the other form refuses the request", CounterpartFacts{
			Asked: true, Name: "www.example.com", Answered: true, Status: 404,
			Scanned: "example.com",
		}, "www.example.com answers 404"},
	} {
		if got := counterpartLine(c.facts); got != c.want {
			t.Errorf("%s read as %q, not %q", c.name, got, c.want)
		}
	}

	// And the row is drawn on every answered scan, including where there is
	// nothing to say (R4).
	rows := Declarations(HeaderFacts{Answered: true}, ContentFacts{}, nil,
		SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
	var seen bool
	for _, r := range rows {
		if r.Label == "The other form" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no row for the other form of the name was drawn: %+v", rows)
	}
}
