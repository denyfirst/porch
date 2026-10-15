package policy

import (
	"strings"
	"testing"
)

// What a response named is a row, every time, and a version is one sentence
// that says how to turn it off — and never a finding.
//
// R21: no document sets a rule a report could hold a server to, and a hidden
// version patches nothing. Reported is not hidden, though: the row is drawn
// on every report, including when nothing was named (R4).
func TestSoftwareNamedIsReportedAndNeverGraded(t *testing.T) {
	f := present("Content-Security-Policy", "X-Content-Type-Options")
	f.Software = []Software{
		{Name: "nginx", Where: "Server", Versioned: true},
		{Name: "PHP", Where: "X-Powered-By", Versioned: true},
		{Name: "Next.js", Where: "X-Powered-By"},
	}

	got := GradeHeaders(f)
	if len(got.Findings) != 0 {
		t.Errorf("a version was graded: %v", findingIDs(got))
	}
	var note string
	for _, n := range got.Notes {
		if strings.Contains(n.Text, "the version of") {
			note = n.Text
		}
	}
	for _, want := range []string{"nginx (Server), PHP (X-Powered-By)", "server_tokens off in nginx", "expose_php = Off"} {
		if !strings.Contains(note, want) {
			t.Errorf("the sentence about versions lacks %q: %q", want, note)
		}
	}
	if strings.Contains(note, "Next.js") {
		t.Errorf("a name sent without a version is in the sentence about versions: %q", note)
	}

	row := declared(t, f, "Software named")
	if row != "nginx in Server, with its version; PHP in X-Powered-By, with its version; Next.js in X-Powered-By" {
		t.Errorf("the row reads %q", row)
	}

	// Nothing named: the row says so, and no sentence about versions.
	bare := present("Content-Security-Policy", "X-Content-Type-Options")
	if row := declared(t, bare, "Software named"); row != "none named" {
		t.Errorf("a response naming nothing reads %q", row)
	}
	for _, n := range GradeHeaders(bare).Notes {
		if strings.Contains(n.Text, "the version of") {
			t.Errorf("a response naming nothing got %q", n.Text)
		}
	}
}

// An exchanger's row says what its greeting named, and nothing where no
// greeting was read; one sentence covers every exchanger that gave a version.
func TestWhatEachGreetingNamedIsOneRowAndOneSentence(t *testing.T) {
	for _, c := range []struct {
		x    ExchangerTLS
		want string
	}{
		{ExchangerTLS{Connected: true, Software: []Software{{Name: "Exim", Where: "greeting", Versioned: true}}},
			"names Exim, with its version"},
		{ExchangerTLS{Connected: true, Software: []Software{{Name: "Postfix", Where: "greeting"}}}, "names Postfix"},
		{ExchangerTLS{Connected: true}, "names no mail server this check knows"},
		{ExchangerTLS{}, ""},
	} {
		if got := MailSoftwareLine(c.x); got != c.want {
			t.Errorf("%+v reads %q, want %q", c.x, got, c.want)
		}
	}

	n, ok := mailVersionNote([]ExchangerTLS{
		{Host: "mx1.example.net", Software: []Software{{Name: "Exim", Where: "greeting", Versioned: true}}},
		{Host: "mx2.example.net", Software: []Software{{Name: "Postfix", Where: "greeting"}}},
		{Host: "mx3.example.net", Software: []Software{{Name: "Exim", Where: "greeting", Versioned: true}}},
	})
	if !ok || !strings.Contains(n.Text, "The mail greetings name the version of Exim (mx1.example.net), Exim (mx3.example.net).") {
		t.Errorf("the sentence reads %q", n.Text)
	}
	if strings.Count(n.Text, "smtp_banner") != 1 || strings.Contains(n.Text, "Postfix") {
		t.Errorf("the settings named are %q", n.Text)
	}
	if _, ok := mailVersionNote([]ExchangerTLS{{Host: "mx2.example.net",
		Software: []Software{{Name: "Postfix", Where: "greeting"}}}}); ok {
		t.Error("a greeting naming no version got a sentence about versions")
	}
}

// declared is what one row of the declarations said.
func declared(t *testing.T, f HeaderFacts, label string) string {
	t.Helper()
	for _, d := range Declarations(f, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow) {
		if d.Label == label {
			return d.Says
		}
	}
	t.Fatalf("no %q row", label)
	return ""
}
