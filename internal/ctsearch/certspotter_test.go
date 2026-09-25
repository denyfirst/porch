package ctsearch

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

// Every page is followed, and a monitor that answers in pages does not produce
// a short inventory.
//
// This is the failure the whole mode cannot survive. One request to this
// monitor returns at most a hundred issuances; a reader that took the first
// page and stopped would return a list that is sorted, dated, plausible and
// missing most of a large estate — and nothing about it would look wrong.
func TestEveryPageOfAPagedAnswerIsRead(t *testing.T) {
	const pages, perPage = 4, 100

	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		requested = append(requested, after)

		start := 0
		if after != "" {
			if _, err := fmt.Sscanf(after, "%d", &start); err != nil {
				t.Errorf("the cursor was sent as %q", after)
			}
			start++
		}

		var out []certSpotterEntry
		for i := start; i < start+perPage && i < pages*perPage; i++ {
			out = append(out, certSpotterEntry{
				ID:        fmt.Sprint(i),
				SHA256:    fmt.Sprintf("%064x", i),
				DNSNames:  []string{fmt.Sprintf("host%03d.example.com", i)},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2026-01-01T00:00:00Z",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).SearchEstate(context.Background(), "example.com")

	if got.Reason != "" {
		t.Fatalf("the search failed: %s", got.Reason)
	}
	if want := pages * perPage; got.Distinct != want {
		t.Errorf("%d names, want %d: a page was not followed", got.Distinct, want)
	}
	if got.Certificates != pages*perPage {
		t.Errorf("%d certificates, want %d", got.Certificates, pages*perPage)
	}
	if got.Truncated {
		t.Error("an answer that was read to its end says it was cut")
	}
	if len(requested) != pages+1 {
		t.Errorf("%d requests were made, want %d: every page and one that comes back empty", len(requested), pages+1)
	}
	// The first asks for no cursor and each one after carries the last
	// identifier of the page before it.
	if requested[0] != "" {
		t.Errorf("the first request carried a cursor: %q", requested[0])
	}
	if requested[1] != "99" {
		t.Errorf("the second request asked after %q, want 99", requested[1])
	}
}

// An estate past the page bound is reported as cut rather than as complete.
//
// The bound has to exist — a monitor that answered forever would be followed
// forever — and the only dishonest way to have one is to stop quietly.
func TestAnEstatePastTheBoundSaysItWasCut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always one more page, whatever the cursor.
		after := r.URL.Query().Get("after")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]certSpotterEntry{{
			ID:        after + "x",
			SHA256:    fmt.Sprintf("%064x", len(after)),
			DNSNames:  []string{fmt.Sprintf("h%d.example.com", len(after))},
			NotBefore: "2024-01-01T00:00:00Z",
			NotAfter:  "2026-01-01T00:00:00Z",
		}})
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).SearchEstate(context.Background(), "example.com")

	if !got.Truncated {
		t.Error("an answer that never ended is reported as complete")
	}
	if got.Distinct == 0 {
		t.Error("nothing was kept from the pages that were read")
	}
}

// Rate limiting says so, in its own words.
//
// The monitor answers anonymous callers at a low rate. "Did not answer the
// search" would send an operator looking for a fault in their network or in the
// domain, when what they need is to wait or to set a key.
func TestRateLimitingIsSaidPlainly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).SearchEstate(context.Background(), "example.com")

	if !strings.Contains(got.Reason, "rate limiting") {
		t.Errorf("a rate-limited search reads as %q", got.Reason)
	}
	if got.Distinct != 0 {
		t.Error("a rate-limited search produced names")
	}
}

// The key, where there is one, travels as a credential and nowhere else.
func TestTheKeyIsSentAsACredentialAndNotWrittenDown(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	c := spotter(t, srv)
	c.Token = "secret-token"
	got := c.SearchEstate(context.Background(), "example.com")

	if auth != "Bearer secret-token" {
		t.Errorf("the key was sent as %q", auth)
	}
	// And nothing carrying it comes back. A token in a report is a token in
	// whatever the report is pasted into (I6).
	if strings.Contains(got.Reason, "secret-token") || strings.Contains(got.Domain, "secret-token") {
		t.Errorf("the key reached the answer: %+v", got)
	}
}

// And this monitor's names go through the same estate boundary as the other's.
func TestTheSecondMonitorKeepsOnlyThisEstate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]certSpotterEntry{{
			ID:        "1",
			SHA256:    "aa",
			DNSNames:  []string{"www.example.com", "notexample.com", "*.example.com"},
			NotBefore: "2024-01-01T00:00:00Z",
			NotAfter:  "2026-01-01T00:00:00Z",
		}})
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).SearchEstate(context.Background(), "example.com")

	if got.Distinct != 2 || got.Foreign != 1 || got.Wildcards != 1 {
		t.Errorf("read %d names, %d foreign, %d wildcards: %+v",
			got.Distinct, got.Foreign, got.Wildcards, got.Names)
	}
	for _, n := range got.Names {
		if n.Name == "notexample.com" {
			t.Error("a different estate's name is in this inventory")
		}
	}
}

// spotter points the monitor at a local stand-in, which safedial would
// otherwise refuse.
func spotter(t *testing.T, srv *httptest.Server) *CertSpotter {
	t.Helper()
	return &CertSpotter{
		Endpoint: srv.URL + "/v1/issuances",
		Timeout:  20 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
}

// One certificate returned twice is one certificate.
//
// A monitor may report the same certificate under two identifiers — once per
// log it was submitted to, or across a page boundary — and the identifier is
// not what a certificate is. The hash is. Counting issuances instead would tell
// an operator they have twice the certificates they have, and the count is one
// of the two numbers this report puts in front of them.
func TestOneCertificateUnderTwoIdentifiersIsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]certSpotterEntry{
			{ID: "1", SHA256: "abc", DNSNames: []string{"www.example.com"},
				NotBefore: "2024-01-01T00:00:00Z", NotAfter: "2026-01-01T00:00:00Z"},
			{ID: "2", SHA256: "abc", DNSNames: []string{"www.example.com"},
				NotBefore: "2024-01-01T00:00:00Z", NotAfter: "2026-01-01T00:00:00Z"},
		})
	}))
	t.Cleanup(srv.Close)

	got := spotter(t, srv).SearchEstate(context.Background(), "example.com")

	if got.Certificates != 1 {
		t.Errorf("%d certificates counted for one certificate reported twice", got.Certificates)
	}
	if got.Distinct != 1 {
		t.Errorf("%d names, want 1: %+v", got.Distinct, got.Names)
	}
}
