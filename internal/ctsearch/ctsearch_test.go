package ctsearch

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The answer comes from a service this project does not run, over a question
// that names the domain. Everything here is written from that direction.

// searching returns a monitor pointed at a server handing out one body to the
// first page and an empty page after it, and the requests it was sent.
func searching(t *testing.T, body string, status int) (*CertSpotter, *[]string) {
	t.Helper()

	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RequestURI())
		if r.URL.Query().Get("after") != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return spotter(t, srv), &asked
}

// answerOf writes issuances the way the monitor does.
func answerOf(t *testing.T, entries []certSpotterEntry) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The name is what gets asked about, folded, and only once.
func TestTheNameIsFoldedIntoTheQuery(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	c.Search(context.Background(), "Example.TEST.")

	if len(*asked) != 1 {
		t.Fatalf("the monitor was asked %d times, want once", len(*asked))
	}

	// Folded before it is sent: a name with a trailing dot and mixed case is
	// the same name, and asking twice about one name is one disclosure too
	// many.
	u, err := url.ParseRequestURI((*asked)[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("domain"); got != "example.test" {
		t.Errorf("asked about %q, want the folded name", got)
	}
}

// A name carrying & or = does not add parameters to somebody else's query.
func TestAwkwardNamesDoNotEscapeTheQuery(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	c.Search(context.Background(), "a&b=c example.test")

	if len(*asked) != 1 {
		t.Fatalf("asked %d times", len(*asked))
	}
	u, err := url.ParseRequestURI((*asked)[0])
	if err != nil {
		t.Fatalf("the request line does not parse: %v", err)
	}
	q := u.Query()

	// Exactly the parameters this asks for, and domain carrying the whole name
	// rather than the part before an ampersand.
	for name := range q {
		switch name {
		case "domain", "include_subdomains", "expand":
		default:
			t.Errorf("the name added a parameter of its own, %q: %s", name, (*asked)[0])
		}
	}
	if len(q["domain"]) != 1 || q.Get("domain") != "a&b=c example.test" {
		t.Errorf("domain is %q, want the whole name", q["domain"])
	}
}

// Anything that is not an answer is reported as not established, never as none.
//
// "No certificates were found" is the reassuring half of this check, so every
// way of failing has to be distinguishable from it (R4). A monitor that is
// down, rate limiting, or answering with a page instead of a document must not
// read as a clean estate.
func TestNothingThatIsNotAnAnswerReadsAsNoneFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
	}{
		{"the monitor refused", "", http.StatusTooManyRequests},
		{"the monitor broke", "", http.StatusBadGateway},
		{"an address that is not there", "not found", http.StatusNotFound},
		{"a page instead of a document", "<html>search results</html>", http.StatusOK},
		{"truncated json", `[{"id":"1"`, http.StatusOK},
	} {
		c, _ := searching(t, tc.body, tc.status)

		got := c.Search(context.Background(), "example.test")
		if got.Reason == "" {
			t.Errorf("%s: the search reported success with %d entries; a failure that reads "+
				"as an empty estate is the one wrong answer here", tc.name, len(got.Entries))
		}
		if len(got.Entries) != 0 || got.Distinct != 0 {
			t.Errorf("%s: entries came back from a failed search", tc.name)
		}

		estate := c.SearchEstate(context.Background(), "example.test")
		if estate.Reason == "" || estate.Distinct != 0 || !estate.Asked {
			t.Errorf("%s: the inventory read %+v", tc.name, estate)
		}
	}
}

// An empty answer is an answer.
func TestAnEmptyAnswerIsNotAFailure(t *testing.T) {
	c, _ := searching(t, `[]`, http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if got.Reason != "" {
		t.Errorf("an empty list was reported as a failure: %s", got.Reason)
	}
	if got.Distinct != 0 {
		t.Errorf("distinct is %d for an empty answer", got.Distinct)
	}
}

// What the monitor says is bounded and stripped before it is kept.
//
// These strings come from certificates anybody may obtain and log, so they are
// chosen by whoever obtained them rather than by the operator being scanned. A
// report is rendered in a browser and pasted into chat windows, and a control
// character in a subject is an old way of making one line look like another.
func TestWhatTheMonitorSaysIsBoundedAndStripped(t *testing.T) {
	long := strings.Repeat("A", maxField*3)
	var many []string
	for i := 0; i < maxNames+5; i++ {
		many = append(many, "n"+serialFor(i)+".example.test")
	}
	body := answerOf(t, []certSpotterEntry{{
		ID:       "1",
		SHA256:   "aa",
		DNSNames: append([]string{"one.test\x00", "two\r\n.test"}, many...),
		CertDER:  logged(t, 0xaaaa, time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC), false),
		Issuer:   &certSpotterIssuer{Name: "CN=" + long},
	}})

	c, _ := searching(t, body, http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if len(got.Entries) != 1 {
		t.Fatalf("listed %d entries: %s", len(got.Entries), got.Reason)
	}
	e := got.Entries[0]

	if len(e.Issuer) > maxField {
		t.Errorf("the issuer is %d characters, and the bound is %d", len(e.Issuer), maxField)
	}
	if len(e.Names) > maxNames {
		t.Errorf("%d names kept from one certificate, and the bound is %d", len(e.Names), maxNames)
	}
	for _, n := range e.Names {
		if strings.ContainsAny(n, "\x00\n\r") {
			t.Errorf("a name carries a control character: %q", n)
		}
	}
}

// The list a report shows is bounded, and says when it is not the whole list.
func TestALongHistoryIsBoundedAndSaysSo(t *testing.T) {
	from := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	var entries []certSpotterEntry
	for i := 0; i < maxEntries+10; i++ {
		entries = append(entries, certSpotterEntry{
			ID:       serialFor(i),
			SHA256:   serialFor(i),
			DNSNames: []string{"example.test"},
			CertDER:  logged(t, int64(0x1000+i), from, false),
		})
	}

	c, _ := searching(t, answerOf(t, entries), http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if got.Reason != "" {
		t.Fatal(got.Reason)
	}
	if len(got.Entries) > maxEntries {
		t.Errorf("listed %d entries, and the bound is %d", len(got.Entries), maxEntries)
	}
	if !got.Truncated {
		t.Error("the list was cut and the result does not say so, so a reader takes a partial " +
			"list for the whole history")
	}

	// The count is still the real one. A bounded list with an honest total is
	// usable; a bounded list with a bounded total understates what exists.
	if got.Distinct != maxEntries+10 {
		t.Errorf("counted %d distinct certificates, want %d", got.Distinct, maxEntries+10)
	}
}

func serialFor(i int) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[(i/16)%16], hex[i%16], 'a', 'a'})
}

// An answer larger than the cap is refused rather than cut and parsed.
func TestAnOversizedAnswerIsRefusedRatherThanTruncated(t *testing.T) {
	c, _ := searching(t, strings.Repeat("x", maxBody+16), http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if !strings.Contains(got.Reason, "larger than this reads") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// No reason names a resolver, an address, or a Go type.
func TestNoReasonDescribesTheMachine(t *testing.T) {
	// A monitor that cannot be reached at all.
	c := &CertSpotter{
		Endpoint: "http://127.0.0.1:1/v1/issuances",
		Timeout:  2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("no network in tests")
		},
	}

	got := c.Search(context.Background(), "example.test")
	if got.Reason == "" {
		t.Fatal("a failed search came back with no reason")
	}
	for _, leak := range []string{"127.0.0.1", "dial ", "tcp ", "*net.", "0x"} {
		if strings.Contains(got.Reason, leak) {
			t.Errorf("the reason contains %q: %s", leak, got.Reason)
		}
	}
}

// An empty name is not a search.
func TestAnEmptyNameIsNotSearchedFor(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	if got := c.Search(context.Background(), "   "); got.Reason == "" {
		t.Error("an empty name was searched for")
	}
	if got := c.SearchEstate(context.Background(), "   "); got.Reason == "" {
		t.Error("an empty domain was searched under")
	}
	if len(*asked) != 0 {
		t.Errorf("the monitor was asked about an empty name: %v", *asked)
	}
}

// A character that makes a display act, or makes a reader misread, is shown
// as a replacement mark rather than passed on or silently dropped.
//
// These strings reach a person: the certificates a TLS report counts are
// listed under it, and the inventory prints names. 0x9b is CSI to several
// terminals; U+202E reverses what follows it; a zero-width space makes one name
// read as another, and dropping it would turn the disguise into the name it
// imitates.
func TestAMonitorsAnswerCannotActOnTheDisplay(t *testing.T) {
	for in, want := range map[string]string{
		"ok.example":            "ok.example",
		"goo\u200bgle.example":  "goo\ufffdgle.example",
		"safe\u202emoc.example": "safe\ufffdmoc.example",
		"csi\u009b2Jhere":       "csi\ufffd2Jhere",
		"bell\u0007.example":    "bell.example",
		"CN=Issuer\u200d Inc":   "CN=Issuer\ufffd Inc",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
