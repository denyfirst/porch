package passivedns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialTo sends every connection to the stub, whatever address was asked for.
//
// The register client refuses loopback of its own accord — safedial is what it
// uses when nothing else is given, and that refusal is the guard these tests
// must not remove from the product to exercise it. So the dialler is replaced
// here and nowhere else.
func dialTo(srv *httptest.Server) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
}

func trails(srv *httptest.Server, token string) *SecurityTrails {
	return &SecurityTrails{
		Endpoint: srv.URL + "/v1",
		Token:    token,
		Timeout:  20 * time.Second,
		Dial:     dialTo(srv),
	}
}

func total(srv *httptest.Server, token string) *VirusTotal {
	return &VirusTotal{
		Endpoint: srv.URL + "/api/v3",
		Token:    token,
		Timeout:  20 * time.Second,
		Dial:     dialTo(srv),
	}
}

// A register answers with labels, and the inventory needs names.
//
// This is the source that sees what a wildcard certificate hides, so what it
// returns has to arrive as something a resolver can be asked about: `www` is
// not a name, and a report full of labels would be a report nobody can act on.
func TestWhatARegisterHasSeenUnderADomain(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path + "?" + r.URL.RawQuery
		if r.Header.Get("APIKEY") != "a-key" {
			t.Errorf("the key was sent as %q", r.Header.Get("APIKEY"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subdomains":["www","bitrix","dev.old","www",""],"subdomain_count":4}`))
	}))
	t.Cleanup(srv.Close)

	got := trails(srv, "a-key").Under(context.Background(), "Example.TEST.")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	want := []string{"bitrix.example.test", "dev.old.example.test", "www.example.test"}
	if len(got.Names) != len(want) {
		t.Fatalf("the register named %v", got.Names)
	}
	for i, name := range want {
		if got.Names[i] != name {
			t.Errorf("name %d is %q, want %q", i, got.Names[i], name)
		}
	}
	if got.Register != "securitytrails" {
		t.Errorf("the answer is credited to %q", got.Register)
	}

	// Everything it holds, including what it has stopped seeing: a name that
	// went quiet last year is the kind an operator is looking for.
	if !strings.Contains(asked, "include_inactive=true") || !strings.Contains(asked, "children_only=false") {
		t.Errorf("the register was asked %q", asked)
	}
	if !strings.Contains(asked, "/domain/example.test/subdomains") {
		t.Errorf("the register was asked for %q", asked)
	}
}

// A name that is not under the domain is dropped and counted.
//
// A register returns what it observed, and what it observed includes names
// that have nothing to do with this estate. A wrong name in an inventory is
// worse than a missing one: the missing one is found by the next method, and
// the wrong one is investigated, escalated and reported.
func TestANameFromARegisterBelongsToTheEstateOnlyOnALabelBoundary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"id":"good.example.test"},
			{"id":"notexample.test"},
			{"id":"example.test.evil.test"},
			{"id":"example.test"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	got := total(srv, "a-key").Under(context.Background(), "example.test")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	if len(got.Names) != 2 {
		t.Fatalf("the register named %v", got.Names)
	}
	if got.Names[0] != "example.test" || got.Names[1] != "good.example.test" {
		t.Errorf("the names kept are %v", got.Names)
	}
	if got.Foreign != 2 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 2", got.Foreign)
	}
}

// Every page of a paged answer is read.
//
// A reader that took the first page and stopped would return a list that is
// sorted, plausible and missing most of a large estate, with nothing about it
// looking wrong.
func TestEveryPageOfARegistersAnswerIsRead(t *testing.T) {
	const pages, perPage = 3, 40

	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		cursors = append(cursors, cursor)

		page := 0
		if cursor != "" {
			if _, err := fmt.Sscanf(cursor, "page%d", &page); err != nil {
				t.Errorf("the cursor was sent as %q", cursor)
			}
		}

		var out struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}
		for i := 0; i < perPage; i++ {
			out.Data = append(out.Data, struct {
				ID string `json:"id"`
			}{ID: fmt.Sprintf("host%03d.example.test", page*perPage+i)})
		}
		if page+1 < pages {
			out.Meta.Cursor = fmt.Sprintf("page%d", page+1)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)

	got := total(srv, "a-key").Under(context.Background(), "example.test")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	if len(got.Names) != pages*perPage {
		t.Errorf("%d names, want %d: a page was not followed", len(got.Names), pages*perPage)
	}
	if got.Truncated {
		t.Error("an answer read to its end says it was cut")
	}
	if len(cursors) != pages {
		t.Errorf("%d requests were made, want %d", len(cursors), pages)
	}
	if cursors[0] != "" {
		t.Errorf("the first request carried a cursor: %q", cursors[0])
	}
}

// A register that keeps handing back the same cursor is left rather than
// followed forever.
//
// The bound has to exist, and a walk that never advances would reach it by
// making twenty-five identical requests to somebody else's service before
// giving up. Neither is anything to do to a register an operator is paying for.
func TestACursorThatDoesNotMoveEndsTheWalk(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"one.example.test"}],"meta":{"cursor":"stuck"}}`))
	}))
	t.Cleanup(srv.Close)

	got := total(srv, "a-key").Under(context.Background(), "example.test")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	if requests != 2 {
		t.Errorf("%d requests were made, want 2: one page, and one that proved the cursor had not moved", requests)
	}
	if len(got.Names) != 1 {
		t.Errorf("the names are %v", got.Names)
	}
}

// An estate past the page bound is reported as cut rather than as complete.
func TestAnEstatePastTheRegistersPageBoundSaysItWasCut(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		cursor := r.URL.Query().Get("cursor")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":[{"id":"h%d.example.test"}],"meta":{"cursor":"%sx"}}`, len(cursor), cursor)
	}))
	t.Cleanup(srv.Close)

	got := total(srv, "a-key").Under(context.Background(), "example.test")

	if !got.Truncated {
		t.Error("an answer that was cut at the page bound does not say so")
	}
	if requests != maxPages {
		t.Errorf("%d requests were made, want the bound of %d", requests, maxPages)
	}
	if len(got.Names) == 0 {
		t.Error("the names read before the bound were thrown away")
	}
}

// A register with no key is not asked at all.
//
// The disclosure is the question, not the answer: naming somebody's domain to
// a company that will refuse to answer buys nothing and discloses the same
// thing a successful search would. Refused here rather than sent and rejected.
func TestARegisterWithNoKeyIsNotAsked(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	for _, register := range []Register{trails(srv, ""), total(srv, "")} {
		got := register.Under(context.Background(), "example.test")
		if got.Reason == "" {
			t.Errorf("%T with no key reported a search: %+v", register, got)
		}
		if len(got.Names) != 0 {
			t.Errorf("%T with no key named %v", register, got.Names)
		}
	}
	if reached {
		t.Error("a domain was named to a register this installation has no key for")
	}
}

// Each answer an operator can act on gets its own sentence.
//
// "Did not answer the search" for a refused key sends somebody looking for a
// fault in their network when what they need is to look at their account, and
// the same for a rate limit, where what they need is to wait.
func TestWhatARegisterRefusedIsSaidPlainly(t *testing.T) {
	for _, tc := range []struct {
		status int
		says   string
	}{
		{http.StatusUnauthorized, "refused the key"},
		{http.StatusForbidden, "refused the key"},
		{http.StatusTooManyRequests, "rate limiting"},
		{http.StatusInternalServerError, "did not answer the search"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))

		got := trails(srv, "a-key").Under(context.Background(), "example.test")
		if !strings.Contains(got.Reason, tc.says) {
			t.Errorf("%d was reported as %q, want something saying %q", tc.status, got.Reason, tc.says)
		}
		if len(got.Names) != 0 {
			t.Errorf("%d came back with names: %v", tc.status, got.Names)
		}
		srv.Close()
	}
}

// A register that holds nothing under a name is not a failure, and a register
// that failed is not an empty estate.
//
// The reassuring answer here is "none found", so the two must never render the
// same (R4).
func TestNothingHeldIsNotTheSameAsNothingEstablished(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subdomains":[]}`))
	}))
	t.Cleanup(empty.Close)

	got := trails(empty, "a-key").Under(context.Background(), "example.test")
	if got.Reason != "" || !got.Asked {
		t.Errorf("a register holding nothing reported %+v", got)
	}
	if len(got.Names) != 0 {
		t.Errorf("a register holding nothing named %v", got.Names)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>we are down</html>`))
	}))
	t.Cleanup(broken.Close)

	got = trails(broken, "a-key").Under(context.Background(), "example.test")
	if got.Reason == "" {
		t.Errorf("an answer that was not in the form this reads was taken as an empty estate: %+v", got)
	}
}

// What a register says is untrusted, and is cleaned before it is kept.
//
// The names in a register are whatever somebody's resolver was asked for, so
// they were chosen by whoever made the query — including, once, by somebody
// hoping they would be printed into a terminal.
func TestWhatARegisterSaysIsCleanedBeforeItIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"data\":[" +
			`{"id":"esc\u001b[31mape.example.test"},` +
			`{"id":"  spaced.example.test  "},` +
			`{"id":"two words.example.test"},` +
			`{"id":"https://scheme.example.test"},` +
			`{"id":"UPPER.Example.Test."}` +
			"]}"))
	}))
	t.Cleanup(srv.Close)

	got := total(srv, "a-key").Under(context.Background(), "example.test")

	for _, name := range got.Names {
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%q carries a control character", name)
			}
		}
		if strings.ContainsAny(name, " /:[") {
			t.Errorf("%q is not a name and was kept", name)
		}
		if name != strings.ToLower(name) {
			t.Errorf("%q was kept unfolded, so one host could be listed twice", name)
		}
	}
	if len(got.Names) != 2 {
		// Two of the five are names: the one with an escape sequence in it, the
		// one with a space and the one with a scheme are not, and a register
		// returns all three because somebody once looked them up.
		t.Errorf("the names kept are %v", got.Names)
	}
	for _, name := range got.Names {
		if strings.Contains(name, "esc") {
			t.Errorf("%q was kept with its odd parts removed rather than dropped", name)
		}
	}
}

// An answer larger than this reads is refused rather than cut.
//
// A partial answer here is an inventory with names missing from it, and an
// inventory that is quietly short is the one thing this must never produce.
func TestAnOversizedRegisterAnswerIsRefusedRatherThanTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subdomains":["` + strings.Repeat("a", maxBody) + `"]}`))
	}))
	t.Cleanup(srv.Close)

	got := trails(srv, "a-key").Under(context.Background(), "example.test")
	if !strings.Contains(got.Reason, "larger than this reads") {
		t.Errorf("an oversized answer was reported as %q", got.Reason)
	}
	if len(got.Names) != 0 {
		t.Errorf("an oversized answer produced names: %v", got.Names)
	}
}

// A register is not followed to an address it chose.
//
// A redirect is the register naming somewhere else for this installation to
// send the question to, and the question carries the operator's domain and
// their key. It is reported as not established instead.
func TestARegisterIsNotFollowedToAnotherAddress(t *testing.T) {
	var elsewhere bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subdomains":["www"]}`))
	}))
	t.Cleanup(other.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/domain/example.test/subdomains", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	got := trails(srv, "a-key").Under(context.Background(), "example.test")

	if elsewhere {
		t.Error("the register sent this installation somewhere else and it went")
	}
	if got.Reason == "" {
		t.Errorf("a redirect was taken as an answer: %+v", got)
	}
}
