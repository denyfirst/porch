package ctsearch

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A name belongs to the estate only on a label boundary.
//
// The trap is that "notexample.com" ends with "example.com" as text. A check
// written with a suffix test alone puts somebody else's host into an inventory
// a security team acts on — and the inventory is the whole product here, so a
// wrong name in it is worse than a missing one: a missing name is found by the
// next method, and a wrong one is investigated, escalated and reported.
func TestANameBelongsToTheEstateOnlyOnALabelBoundary(t *testing.T) {
	for _, c := range []struct {
		name, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"a.b.c.example.com", "example.com", true},
		{"*.example.com", "example.com", true},

		{"notexample.com", "example.com", false},
		{"example.com.evil.test", "example.com", false},
		{"example.co", "example.com", false},
		{"com", "example.com", false},
		{"", "example.com", false},
		{"xexample.com", "example.com", false},
	} {
		if got := under(c.name, c.domain); got != c.want {
			t.Errorf("under(%q, %q) = %v, want %v", c.name, c.domain, got, c.want)
		}
	}
}

// The inventory counts certificates once, keeps only this estate's names, and
// says how much it could not see.
//
// Each of those is a way the answer goes quietly wrong. A certificate is logged
// twice — as a precertificate and as itself — so counting entries doubles the
// figure. A shared certificate carries somebody else's names. And a wildcard
// covers hosts without naming them, which is the one number that says how
// incomplete the list is.
func TestWhatTheInventoryKeepsAndWhatItCounts(t *testing.T) {
	raw := []entry{
		{
			SerialNumber: "aa",
			NameValue:    "example.com\nwww.example.com",
			NotBefore:    "2023-01-01T00:00:00",
			NotAfter:     "2023-04-01T00:00:00",
		},
		// The same certificate again, as every log holds it.
		{
			SerialNumber: "AA",
			NameValue:    "example.com\nwww.example.com",
			NotBefore:    "2023-01-01T00:00:00",
			NotAfter:     "2023-04-01T00:00:00",
		},
		// A later certificate for one of them, and a name nobody had seen.
		{
			SerialNumber: "bb",
			NameValue:    "www.example.com\napi.example.com",
			NotBefore:    "2024-06-01T00:00:00",
			NotAfter:     "2024-09-01T00:00:00",
		},
		// Shared with another estate, and carrying a wildcard.
		{
			SerialNumber: "cc",
			NameValue:    "*.example.com\nsomebody-else.test\nwww.somebody-else.test",
			NotBefore:    "2025-01-01T00:00:00",
			NotAfter:     "2025-04-01T00:00:00",
		},
	}

	got := collect(raw, "example.com")

	if got.Certificates != 3 {
		t.Errorf("%d certificates counted, want 3: the precertificate and the certificate share a serial", got.Certificates)
	}
	if got.Distinct != 4 {
		t.Errorf("%d names, want 4: %+v", got.Distinct, got.Names)
	}
	if got.Foreign != 2 {
		t.Errorf("%d foreign names dropped, want 2", got.Foreign)
	}
	if got.Wildcards != 1 {
		t.Errorf("%d wildcards counted, want 1", got.Wildcards)
	}

	// Nothing from the other estate reached the inventory.
	for _, n := range got.Names {
		if !under(n.Name, "example.com") {
			t.Errorf("%q is in this estate's inventory and is not under it", n.Name)
		}
	}

	// Sorted, so two runs of one search read the same.
	for i := 1; i < len(got.Names); i++ {
		if got.Names[i-1].Name > got.Names[i].Name {
			t.Errorf("the inventory is not sorted: %q before %q", got.Names[i-1].Name, got.Names[i].Name)
		}
	}

	// The window spans every certificate naming it, which is what makes a name
	// whose newest certificate expired years ago visible as one.
	at := byName(t, got, "www.example.com")
	if want := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC); !at.FirstSeen.Equal(want) {
		t.Errorf("www was first seen %v, want %v", at.FirstSeen, want)
	}
	if want := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC); !at.LastSeen.Equal(want) {
		t.Errorf("www was last covered to %v, want %v", at.LastSeen, want)
	}

	if !byName(t, got, "*.example.com").Wildcard {
		t.Error("a wildcard name is not marked as one, so a reader cannot tell how much is hidden")
	}
}

// An answer with nothing in it is an answer, and says so.
func TestAnEmptyInventoryIsStillAnAnswer(t *testing.T) {
	got := collect(nil, "example.com")
	if !got.Asked {
		t.Error("a search that was made reads as one that was not")
	}
	if got.Distinct != 0 || len(got.Names) != 0 || got.Reason != "" {
		t.Errorf("an empty answer read as %+v", got)
	}
	if got.Domain != "example.com" {
		t.Errorf("the inventory does not say what it searched under: %q", got.Domain)
	}
}

// A control character in a logged name does not travel.
//
// These names come from certificates anybody may obtain and log, so the text is
// chosen by whoever obtained them. This inventory is pasted into tickets and
// read in terminals, and a carriage return in a subject is an old way of making
// one line look like another.
func TestANameFromALogIsCleanedBeforeItIsKept(t *testing.T) {
	got := collect([]entry{{
		SerialNumber: "aa",
		NameValue:    "we\u0007b.example.com",
		NotBefore:    "2024-01-01T00:00:00",
		NotAfter:     "2024-04-01T00:00:00",
	}}, "example.com")

	if got.Distinct != 1 {
		t.Fatalf("expected one name, got %+v", got.Names)
	}
	if n := got.Names[0].Name; n != "web.example.com" {
		t.Errorf("the name was kept as %q", n)
	}
}

func byName(t *testing.T, e Estate, want string) Name {
	t.Helper()
	for _, n := range e.Names {
		if n.Name == want {
			return n
		}
	}
	t.Fatalf("%q is not in the inventory: %+v", want, e.Names)
	return Name{}
}

// The whole path, from the request this makes to the inventory it returns.
//
// Against a local stand-in rather than the monitor. The monitor answered 502 to
// every request on the day this was written — which is the ordinary state of a
// free service indexing billions of certificates, and exactly why the search is
// an interface with a configurable address. A test that depended on it would
// pass on the days the feature was least needed.
func TestTheSearchAsksForEverythingUnderTheDomainAndKeepsOnlyThat(t *testing.T) {
	var asked string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Query().Get("Identity")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
		  {"serial_number":"01","issuer_name":"CA","name_value":"api.example.com\nexample.com",
		   "not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"},
		  {"serial_number":"01","issuer_name":"CA","name_value":"api.example.com\nexample.com",
		   "not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"},
		  {"serial_number":"02","issuer_name":"CA","name_value":"*.example.com\nnotexample.com",
		   "not_before":"2025-01-01T00:00:00","not_after":"2025-04-01T00:00:00"}
		]`)
	}))
	t.Cleanup(srv.Close)

	c := &CRTSh{
		Endpoint: srv.URL + "/?Identity=%s&output=json",
		Timeout:  5 * time.Second,
		// safedial refuses loopback, as it should everywhere but here.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	got := c.SearchEstate(context.Background(), "Example.COM.")

	// The question is for everything under the domain, not for the domain
	// alone: a certificate issued only for api.example.com is not returned by
	// a search for example.com, and missing it would make the inventory quietly
	// short.
	if asked != "%.example.com" {
		t.Errorf("the monitor was asked for %q, want %%.example.com", asked)
	}

	if got.Domain != "example.com" {
		t.Errorf("the domain was recorded as %q, so a trailing dot or a capital reaches the report", got.Domain)
	}
	if got.Certificates != 2 {
		t.Errorf("%d certificates, want 2", got.Certificates)
	}
	if got.Distinct != 3 || got.Wildcards != 1 || got.Foreign != 1 {
		t.Errorf("inventory reads %d names, %d wildcards, %d foreign: %+v",
			got.Distinct, got.Wildcards, got.Foreign, got.Names)
	}
	for _, n := range got.Names {
		if n.Name == "notexample.com" {
			t.Error("notexample.com is a different estate and is in this inventory")
		}
	}
}

// A monitor that will not answer is reported as one that did not answer.
//
// The reassuring half of this search is "none found", so a failure that read as
// an empty inventory would tell an operator their estate publishes nothing —
// the most comfortable wrong answer available (R4). The monitor really was
// answering 502 the day this was written.
func TestAMonitorThatWillNotAnswerIsNotAnEmptyEstate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	c := &CRTSh{
		Endpoint: srv.URL + "/?Identity=%s&output=json",
		Timeout:  5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	got := c.SearchEstate(context.Background(), "example.com")

	if got.Reason == "" {
		t.Error("a monitor that refused the search gave no reason, so the inventory reads as empty")
	}
	if got.Distinct != 0 || len(got.Names) != 0 {
		t.Errorf("a failed search produced names: %+v", got)
	}
	if !got.Asked {
		t.Error("a search that was attempted reads as one that was not")
	}
}

// An answer too large to read is refused, not cut.
//
// A cut answer here is an inventory with names missing from it, and it would
// look exactly like a complete one: sorted, dated, plausible, short. Every
// other failure in this package announces itself; this is the one that would
// not, which is why the body is refused whole rather than truncated and parsed.
func TestAnOversizedAnswerLeavesNoShortInventory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"serial_number":"01","name_value":"a.example.com","not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"},`)
		// Past the bound, in one certificate repeated, so that a reader cutting
		// the body would still find valid records at the front.
		filler := strings.Repeat(
			`{"serial_number":"02","name_value":"b.example.com","not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"},`, 40000)
		_, _ = io.WriteString(w, filler)
		_, _ = io.WriteString(w, `{"serial_number":"03","name_value":"c.example.com","not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"}]`)
	}))
	t.Cleanup(srv.Close)

	c := &CRTSh{
		Endpoint: srv.URL + "/?Identity=%s&output=json",
		Timeout:  20 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	got := c.SearchEstate(context.Background(), "example.com")

	if got.Reason == "" {
		t.Error("an answer past the bound gave no reason, so a short inventory reads as a complete one")
	}

	// And the reason is the size rather than the shape. Cutting the body and
	// parsing what is left also refuses — a truncated array is not valid JSON —
	// so the bound is not what stops a short inventory being produced. What it
	// buys is the sentence: "larger than this reads" sends an operator to a
	// narrower search, and "not in the form this reads" sends them to report a
	// broken monitor that is working correctly.
	if !strings.Contains(got.Reason, "larger than this reads") {
		t.Errorf("an answer past the bound reads as %q, which describes the wrong fault", got.Reason)
	}
	if got.Distinct != 0 || len(got.Names) != 0 {
		t.Errorf("an answer past the bound produced %d names: %+v", got.Distinct, got.Names)
	}
}
