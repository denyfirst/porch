package rpki

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ripestat stands in for RIPEstat: a prefix and origins per address, and a
// validation state per origin and prefix.
type ripestat struct {
	info     map[string]string // address -> JSON data
	valid    map[string]string // "origin prefix" -> status
	asked    []string
	validate int
}

func (s *ripestat) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("sourceapp") != "porch" {
		http.Error(w, "no sourceapp", http.StatusBadRequest)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/network-info/data.json"):
		s.asked = append(s.asked, q.Get("resource"))
		data, ok := s.info[q.Get("resource")]
		if !ok {
			data = `{"asns":[],"prefix":""}`
		}
		fmt.Fprintf(w, `{"status":"ok","data":%s}`, data)
	case strings.HasSuffix(r.URL.Path, "/rpki-validation/data.json"):
		s.validate++
		fmt.Fprintf(w, `{"status":"ok","data":{"status":%q}}`, s.valid[q.Get("resource")+" "+q.Get("prefix")])
	default:
		http.NotFound(w, r)
	}
}

func stat(t *testing.T, s *ripestat) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return &Client{
		Endpoint: srv.URL + "/data/",
		Roots:    pool,
		Timeout:  5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}

// Each address gets the state its route validates to, and two addresses in
// one block cost one validation.
func TestEachAddressGetsItsRoutesState(t *testing.T) {
	s := &ripestat{
		info: map[string]string{
			"192.0.2.10":  `{"asns":["64500"],"prefix":"192.0.2.0/24"}`,
			"192.0.2.11":  `{"asns":["64500"],"prefix":"192.0.2.0/24"}`,
			"2001:db8::1": `{"asns":["64501"],"prefix":"2001:db8::/32"}`,
			"198.51.100.": `{}`,
		},
		valid: map[string]string{
			"64500 192.0.2.0/24":  "valid",
			"64501 2001:db8::/32": "unknown",
		},
	}
	got := stat(t, s).Check(context.Background(), []string{"192.0.2.10", "192.0.2.11", "2001:db8::1", "203.0.113.5", "not an address"})

	want := map[string]string{"192.0.2.10": Valid, "192.0.2.11": Valid, "2001:db8::1": NotFound, "203.0.113.5": NoRoute}
	if len(got) != len(want) {
		t.Fatalf("%d routes: %+v", len(got), got)
	}
	for _, r := range got {
		if r.State != want[r.Address] || r.Reason != "" {
			t.Errorf("%s: %+v", r.Address, r)
		}
	}
	if s.validate != 2 {
		t.Errorf("%d validations, want one per block and origin", s.validate)
	}
}

// One origin announcing a block in contradiction of its signature makes the
// route invalid, whatever the others do.
func TestTheWorstOriginDecides(t *testing.T) {
	s := &ripestat{
		info:  map[string]string{"192.0.2.10": `{"asns":["64500","AS64502"],"prefix":"192.0.2.0/24"}`},
		valid: map[string]string{"64500 192.0.2.0/24": "valid", "64502 192.0.2.0/24": "invalid_asn"},
	}
	got := stat(t, s).Check(context.Background(), []string{"192.0.2.10"})
	if len(got) != 1 || got[0].State != Invalid || strings.Join(got[0].Origins, ",") != "64500,64502" {
		t.Errorf("read %+v", got)
	}
}

// What RIPEstat says is parsed rather than repeated: a prefix that does not
// hold the address, or an origin that is not a number, is no answer.
func TestAnAnswerThatDoesNotParseIsNoAnswer(t *testing.T) {
	for name, info := range map[string]string{
		"a prefix elsewhere":     `{"asns":["64500"],"prefix":"198.51.100.0/24"}`,
		"an origin not a number": `{"asns":["<script>"],"prefix":"192.0.2.0/24"}`,
		"a prefix not a prefix":  `{"asns":["64500"],"prefix":"192.0.2.0/33"}`,
	} {
		s := &ripestat{info: map[string]string{"192.0.2.10": info}}
		got := stat(t, s).Check(context.Background(), []string{"192.0.2.10"})
		if len(got) != 1 || got[0].Reason == "" || got[0].State != "" {
			t.Errorf("%s: read %+v", name, got)
		}
	}
	s := &ripestat{
		info:  map[string]string{"192.0.2.10": `{"asns":["64500"],"prefix":"192.0.2.0/24"}`},
		valid: map[string]string{"64500 192.0.2.0/24": "probably"},
	}
	if got := stat(t, s).Check(context.Background(), []string{"192.0.2.10"}); got[0].Reason == "" {
		t.Errorf("a state RIPEstat does not define read %+v", got)
	}
}

// At most eight addresses are asked about, however many a zone names.
func TestTheAddressesAreBounded(t *testing.T) {
	var many []string
	for i := range 20 {
		many = append(many, fmt.Sprintf("192.0.2.%d", i+1))
	}
	s := &ripestat{}
	got := stat(t, s).Check(context.Background(), many)
	if len(got) != maxAddresses || len(s.asked) != maxAddresses {
		t.Errorf("%d routes from %d questions", len(got), len(s.asked))
	}
}

// A service that cannot be reached says so, in a sentence that describes no
// machine.
func TestAServiceThatCannotBeReachedSaysSo(t *testing.T) {
	c := &Client{Endpoint: "https://127.0.0.1:1/data/", Timeout: 2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("no network in tests")
		}}
	got := c.Check(context.Background(), []string{"192.0.2.10"})
	if len(got) != 1 || got[0].Reason != "RIPEstat could not be reached" {
		t.Errorf("read %+v", got)
	}
}
