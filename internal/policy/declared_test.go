package policy

import (
	"strings"
	"testing"
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
	}, ContentFacts{}, nil)

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
	})
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
	if got := Declarations(HeaderFacts{}, ContentFacts{}, nil); got != nil {
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
		for _, r := range Declarations(f, c, nil) {
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
