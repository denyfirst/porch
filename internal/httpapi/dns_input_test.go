package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
)

func postDNS(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/scan", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.41:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// The DNS endpoint takes a domain, and an address as the domain it names, the
// way the mail endpoint does: somebody reading a report about their mail and
// asking about their DNS types the same thing into both. What it refuses is
// what is not a domain, and it says so without repeating what was typed (I3).
func TestTheDNSEndpointTakesADomain(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for _, target := range []string{"example.test", "someone@example.test", "EXAMPLE.test."} {
		w := postDNS(t, s, `{"target":"`+target+`"}`)
		if w.Code != http.StatusOK {
			t.Errorf("%q: %d %s", target, w.Code, w.Body.String())
			continue
		}
		var got struct {
			Domain string `json:"domain"`
			Policy string `json:"policy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%q: %v", target, err)
		}
		if got.Domain != "example.test" {
			t.Errorf("%q was read as %q", target, got.Domain)
		}
		if got.Policy != policy.DNSVersion {
			t.Errorf("%q: the report names %q", target, got.Policy)
		}
		if strings.Contains(w.Body.String(), "someone") {
			t.Errorf("%q: the local part reached the report", target)
		}
	}

	// An address gets the refusal that names the rule about addresses; the rest
	// are not names at all.
	if w := postDNS(t, s, `{"target":"192.0.2.1"}`); errorCode(t, w) != "hostname_required" {
		t.Errorf("an address: %d %s", w.Code, w.Body.String())
	}

	for _, target := range []string{"", "localhost", "example.test:53", "example.test/path", "bad name.test"} {
		w := postDNS(t, s, `{"target":"`+target+`"}`)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_target" {
			// The code as well as the status, because the scanner refuses a
			// malformed name too: a parser that let one through would still
			// be caught, one layer down and with the wrong sentence.
			t.Errorf("%q: %d %s", target, w.Code, w.Body.String())
		}
		if target != "" && strings.Contains(w.Body.String(), target) {
			t.Errorf("%q: the refusal repeats what was typed: %s", target, w.Body.String())
		}
	}
}

// The delegation is asked about directly only where control of the domain has
// been proven.
//
// Every other question the DNS check asks goes to a resolver; this one opens a
// connection to an address the measured zone chose, which is the condition the
// mail check's two connections carry and for the same reason. A service that
// requires no proof is scanning names nobody proved anything about, and it
// does not also connect to their servers.
func TestTheDelegationIsAskedOnlyWhereProofWasRequired(t *testing.T) {
	open := New(offlineScanner(), Limits{}, nil)
	if open.dns.AskServers {
		t.Error("a service that requires no proof asks the zone's own servers")
	}

	scope := &verify.Scope{Secret: []byte("a deployment secret"), Resolver: nothingPublished{}}
	guarded := New(&scan.Scanner{Verify: scope}, Limits{}, nil)
	if !guarded.dns.AskServers {
		t.Error("a service with proof of control does not ask the zone's own servers")
	}
}

type nothingPublished struct{}

func (nothingPublished) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, true, nil
}
