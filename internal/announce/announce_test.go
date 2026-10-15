package announce

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// The names are kept and the versions are not, anywhere in what is returned.
//
// The version is the part an operator usually did not mean to publish, and a
// report is pasted into issue trackers. A field that carried it, or a name
// that swallowed it, would publish it a second time.
func TestTheNameIsKeptAndTheVersionIsNot(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f")
	h.Set("X-Powered-By", "PHP/7.4.3")
	h.Set("X-AspNet-Version", "4.0.30319")

	got := FromHeaders(h)
	want := []Software{
		{Name: "Apache", Where: "Server", Versioned: true},
		{Name: "OpenSSL", Where: "Server", Versioned: true},
		{Name: "PHP", Where: "X-Powered-By", Versioned: true},
		{Name: "ASP.NET", Where: "X-AspNet-Version", Versioned: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read as %+v, want %+v", got, want)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"2.4", "41", "1.1.1", "7.4", "30319", "Ubuntu"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("%q reached what is kept: %s", leaked, raw)
		}
	}
}

// A name is kept only in the shape of a name, and a header cannot add more
// than a few to a report.
//
// Everything here is text chosen by whoever is being measured. A field that
// is not a short token is not a product name, whatever the server meant by
// it, and is dropped rather than cleaned: a cleaned value is still the
// server's sentence.
func TestOnlyANameShapedTokenIsKept(t *testing.T) {
	for _, c := range []struct {
		server string
		want   []Software
	}{
		{"nginx", []Software{{Name: "nginx", Where: "Server"}}},
		{"nginx/", []Software{{Name: "nginx", Where: "Server"}}},
		{"Microsoft-IIS/10.0", []Software{{Name: "Microsoft-IIS", Where: "Server", Versioned: true}}},
		{"Apache 2.4.41", []Software{{Name: "Apache", Where: "Server", Versioned: true}}},
		{"<script>alert(1)</script>", nil},
		{"evil\u202eexe", nil},
		{strings.Repeat("a", 41), nil},
		{"(an unterminated comment nginx/1.25.3", nil},
		{"(Red Hat) nginx", []Software{{Name: "nginx", Where: "Server"}}},
		{"1.2.3", nil},
		{"a b c d e f g", []Software{
			{Name: "a", Where: "Server"}, {Name: "b", Where: "Server"},
			{Name: "c", Where: "Server"}, {Name: "d", Where: "Server"},
		}},
	} {
		h := http.Header{}
		h.Set("Server", c.server)
		if got := FromHeaders(h); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Server: %q read as %+v, want %+v", c.server, got, c.want)
		}
	}
}

// A mail server is named only from the list, only after the server's own
// name, and with a version only where one follows the name.
func TestAGreetingIsReadForTheListAndNothingElse(t *testing.T) {
	for _, c := range []struct {
		greeting string
		want     []Software
	}{
		{"mx.example.com ESMTP Exim 4.96 Wed, 15 Oct 2026 09:48:35 +0000",
			[]Software{{Name: "Exim", Where: Greeting, Versioned: true}}},
		{"mx.example.com ESMTP Postfix (Ubuntu)",
			[]Software{{Name: "Postfix", Where: Greeting}}},
		{"mx.example.com ESMTP Sendmail 8.17.1/8.17.1; Wed, 15 Oct 2026 09:48:35 +0000",
			[]Software{{Name: "Sendmail", Where: Greeting, Versioned: true}}},
		{"mx.example.com Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready",
			[]Software{{Name: "Microsoft Exchange", Where: Greeting, Versioned: true}}},
		{"x.mail.protection.outlook.com Microsoft ESMTP MAIL Service ready at Wed, 15 Oct 2026 09:48:35 +0000",
			[]Software{{Name: "Microsoft Exchange", Where: Greeting}}},
		// The server's own name says what it is called, not what it runs.
		{"exim.example.com ESMTP", nil},
		{"postfix ESMTP", nil},
		// Part of a word is not the word.
		{"mx.example.com ESMTP netqmail 1.06", nil},
		{"mx.google.com ESMTP a1b2c3d4e5 - gsmtp", nil},
		{"", nil},
	} {
		if got := FromGreeting([]string{c.greeting}); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q read as %+v, want %+v", c.greeting, got, c.want)
		}
	}

	// A greeting across lines is read as one, with only the first word of the
	// first line skipped.
	got := FromGreeting([]string{"mx.example.com ESMTP", "Exim 4.96 ready"})
	if len(got) != 1 || got[0].Name != "Exim" || !got[0].Versioned {
		t.Errorf("a two-line greeting read as %+v", got)
	}
}
