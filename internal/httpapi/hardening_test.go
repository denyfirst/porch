package httpapi

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
)

// Every code this package can refuse with is one the counter keeps.
//
// refuse drops a code outside refusalCodes rather than counting it, which is
// right — an open-ended map is how something identifying reaches a published
// file — and it means a code added to a handler and not to the list is
// answered and never counted. Six were: every refusal the inventory makes and
// the bound on DKIM selectors. TestEveryRefusalCodeCanBeProduced could not see
// it, because it drives the codes the list holds and a code the list does not
// hold is not in its loop.
//
// So the codes are read out of the source, from every place one is written:
// a call to refuse and a refusal literal. A new code is either added to the
// list or this fails.
func TestEveryCodeThisPackageRefusesWithIsCounted(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`refuse\(w,\s*[^,]+,\s*"([a-z_]+)"`),
		regexp.MustCompile(`&refusal\{[^,]+,\s*"([a-z_]+)"`),
		regexp.MustCompile(`code:\s*"([a-z_]+)"`),
	}
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range patterns {
			for _, m := range p.FindAllStringSubmatch(string(body), -1) {
				found++
				if !slices.Contains(refusalCodes, m[1]) {
					t.Errorf("%s refuses with %q, which refusalCodes does not hold, so it is answered "+
						"and never counted", name, m[1])
				}
			}
		}
	}
	// A pattern that stopped matching would pass this test by finding nothing.
	if found < len(refusalCodes) {
		t.Errorf("only %d refusals were found in the source; the patterns above no longer "+
			"match how this package refuses", found)
	}
}

// A plain-HTTP request naming this machine by a name it was never told is its
// own is refused, and an address or localhost is answered.
//
// The name is what a rebinding page sends: its own, pointed at 127.0.0.1 once
// it has loaded, so that its script can call this service as same-origin and
// read the answer. On loopback with no password that caller is the one this
// service trusts as its operator.
func TestARebindingPageIsNotAnswered(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	var reached atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	guarded := s.GuardHost(next)

	ask := func(host string, overTLS bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		r.RemoteAddr = "127.0.0.1:5000"
		if overTLS {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		return w
	}

	for _, host := range []string{
		"127.0.0.1:8080", "127.0.0.1", "[::1]:8080", "::1", "localhost:8080", "LOCALHOST.:8080",
		"192.0.2.10:8080", "[2001:db8::1]:8443", "",
	} {
		before := reached.Load()
		if w := ask(host, false); w.Code != http.StatusNoContent || reached.Load() != before+1 {
			t.Errorf("Host %q over plain HTTP was not answered: %d", host, w.Code)
		}
	}

	for _, host := range []string{
		"rebound.example:8080", "rebound.example", "127.0.0.1.rebound.example",
		"localhost.rebound.example:8080", "0x7f000001:8080", "scanner.corp:8080",
	} {
		before := reached.Load()
		w := ask(host, false)
		if w.Code != http.StatusMisdirectedRequest || reached.Load() != before {
			t.Errorf("Host %q over plain HTTP reached the service: %d", host, w.Code)
			continue
		}
		if got := errorCode(t, w); got != "host_not_served" {
			t.Errorf("Host %q was refused as %q", host, got)
		}
		if strings.Contains(w.Body.String(), "rebound") || strings.Contains(w.Body.String(), "corp") {
			t.Errorf("the refusal repeats the name that was sent: %s", w.Body.String())
		}
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("the refusal for %q carries no security headers", host)
		}
	}

	// Over TLS the certificate settles it: a browser rebinding a name to this
	// machine expects the certificate for that name and never gets as far as a
	// request.
	before := reached.Load()
	if w := ask("scan.example.com", true); w.Code != http.StatusNoContent || reached.Load() != before+1 {
		t.Errorf("a name over TLS was refused: %d", w.Code)
	}

	if got := s.Stats().Refused["host_not_served"]; got == 0 {
		t.Error("a refused name was not counted")
	}
}

// A DKIM selector from a request is a DNS name, and a list of them is bounded
// by what it holds rather than by how many strings carried it.
//
// One entry reading "a,b,c,…" passed the bound as one selector and was split
// into as many as it named, then cut to sixteen without a word — the list the
// bound says is refused rather than cut short.
func TestASelectorIsADNSNameAndCountsAsOne(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for _, bad := range []string{
		`"a,b"`, `"s1 google"`, `"."`, `"-lead"`, `"trail-"`, `"a..b"`, `""`,
		`"` + strings.Repeat("a", 64) + `"`, `"line\nbreak"`, `"über"`,
	} {
		w := postTo(t, s, "/api/v1/mail/scan",
			`{"target":"example.test","selectors":[`+bad+`]}`, "203.0.113.200:5000")
		if got := errorCode(t, w); got != "invalid_selector" {
			t.Errorf("selector %s was answered %q", bad, got)
		}
		if strings.Contains(w.Body.String(), "google") || strings.Contains(w.Body.String(), "lead") {
			t.Errorf("the refusal repeats the selector: %s", w.Body.String())
		}
	}

	for _, good := range []string{`"s1"`, `"Google"`, `"key1.migadu"`, `"sel_2026-09"`} {
		w := postTo(t, s, "/api/v1/mail/scan",
			`{"target":"example.test","selectors":[`+good+`]}`, "203.0.113.201:5000")
		if w.Code != http.StatusOK {
			t.Errorf("selector %s was refused: %d %s", good, w.Code, w.Body.String())
		}
	}
}

// An inventory is of a domain, and an address is refused in the words every
// other endpoint uses — before anything is asked about it.
func TestAnInventoryIsNotOfAnAddress(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.ReachableByOthers(false)
	monitor := &stubMonitor{estate: ctsearch.Estate{Asked: true}}
	s.SearchNames(monitor)

	for _, address := range []string{"192.0.2.10", "[2001:db8::1]"} {
		w := postTo(t, s, "/api/v1/names/scan", `{"target":"`+address+`"}`, "203.0.113.210:5000")
		if got := errorCode(t, w); got != "hostname_required" {
			t.Errorf("%s was answered %q", address, got)
		}
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about an address: %q", was)
	}
}
