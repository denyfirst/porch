package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
)

// stubMonitor answers without asking anybody, and records what it was asked.
type stubMonitor struct {
	asked  atomic.Value
	estate ctsearch.Estate
}

func (m *stubMonitor) SearchEstate(_ context.Context, domain string) ctsearch.Estate {
	m.asked.Store(domain)
	out := m.estate
	out.Domain = domain
	return out
}

func (m *stubMonitor) was() string {
	if v, ok := m.asked.Load().(string); ok {
		return v
	}
	return ""
}

// An inventory is produced only for a domain this installation has been shown
// control of.
//
// Stricter than the checks, and deliberately. A check measures how a host
// answers, which is what any visitor learns and which the scanned party can see
// happening. This produces the shape of an estate, and the scanned party cannot
// see it at all, because nothing is asked of them. A service answering that for
// anybody would be an anonymous reconnaissance endpoint with this project's
// name on it, and the data being public does not change what the service would
// be doing: assembling it, on request, for people who will not say who they
// are.
func TestAnInventoryIsOnlyProducedForAProvenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	monitor := &stubMonitor{estate: ctsearch.Estate{
		Asked: true, Distinct: 1, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}},
	}}
	s.SearchNames(monitor)

	// The domain nobody proved.
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.10:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about %q for an unproven domain", was)
	}

	// And the one somebody did.
	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.11:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}
	var got ctsearch.Estate
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Distinct != 1 || len(got.Names) != 1 {
		t.Errorf("the inventory came back as %+v", got)
	}
	if monitor.was() != "proven.example" {
		t.Errorf("the monitor was asked about %q", monitor.was())
	}
}

// An installation with no verification configured refuses, rather than
// producing inventories for anybody.
//
// This is where it parts company with the checks, which run for anything when
// no scope is set. "Nobody has proven anything" must not mean "everybody may
// ask" — not for the one endpoint that hands out the shape of an estate.
func TestAnInstallationWithNoVerificationProducesNoInventory(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	monitor := &stubMonitor{estate: ctsearch.Estate{Asked: true}}
	s.SearchNames(monitor)

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"example.test"}`, "203.0.113.20:5000")); got != "proof_required" {
		t.Errorf("an installation with no verification answered %q", got)
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about %q by an installation with no verification", was)
	}
}

// Whether this installation has a monitor is told to nobody who has not proven
// anything.
//
// The refusals are ordered for that reason: proof first, configuration second.
// A stranger learning which monitors an installation is wired to has learned
// something about the installation in exchange for nothing.
func TestTheMonitorIsNotDescribedToSomebodyWhoProvedNothing(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	// No monitor configured at all.

	body := postTo(t, s, "/api/v1/names/scan", `{"target":"unproven.example"}`, "203.0.113.30:5000").Body.String()
	if !strings.Contains(body, "proof_required") {
		t.Errorf("an unproven domain was answered %s", body)
	}
	if strings.Contains(body, "monitor") {
		t.Errorf("an unproven caller was told about this installation's monitor: %s", body)
	}

	// The proven one is told plainly, because it is their answer to act on.
	body = postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.31:5000").Body.String()
	if !strings.Contains(body, "not_offered") {
		t.Errorf("a proven domain with no monitor configured was answered %s", body)
	}
}

// An inventory is of a domain, not of a port or an address.
func TestTheInventoryEndpointTakesADomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true}})

	for _, bad := range []string{"proven.example:8443", "not a domain"} {
		got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
			`{"target":"`+bad+`"}`, "203.0.113.40:5000"))
		if got != "invalid_target" {
			t.Errorf("%q was answered %q", bad, got)
		}
	}
}

// An installation nobody else can reach produces an inventory without proof.
//
// It is the command line with a browser in front of it. Asking the operator to
// publish a DNS record proving to themselves that they own their own domain,
// on a copy of the service that only they can reach, is friction bought with no
// safety — and friction bought with no safety is how a rule comes to be turned
// off altogether.
//
// What the rule is for is the other case, and that case is still refused: a
// service somebody else can reach, answering for anybody, would be an anonymous
// reconnaissance endpoint with this project's name on it.
func TestAnInstallationNobodyElseCanReachNeedsNoProof(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	monitor := &stubMonitor{estate: ctsearch.Estate{
		Asked: true, Distinct: 1, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.example.test"}},
	}}
	s.SearchNames(monitor)

	// Reachable by others, which is what a server that was never told assumes.
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"example.test"}`, "203.0.113.50:5000")); got != "proof_required" {
		t.Errorf("a reachable installation with no verification answered %q", got)
	}

	// And the same server, told that nobody else can reach it.
	s.ReachableByOthers(false)
	w := postTo(t, s, "/api/v1/names/scan", `{"target":"example.test"}`, "203.0.113.51:5000")
	if w.Code != 200 {
		t.Fatalf("an installation nobody else can reach answered %d: %s", w.Code, w.Body.String())
	}
	if monitor.was() != "example.test" {
		t.Errorf("the monitor was asked about %q", monitor.was())
	}
}

// Configuring verification is opting into it, and it is then enforced wherever
// the service listens.
//
// The loopback exception is about an installation that was never given a scope.
// An operator who set one has said what they want, and a copy that quietly
// stopped enforcing it because of the address it bound to would be answering a
// question they had already answered.
func TestVerificationConfiguredIsEnforcedEvenOnLoopback(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.ReachableByOthers(false)

	monitor := &stubMonitor{estate: ctsearch.Estate{Asked: true}}
	s.SearchNames(monitor)

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.60:5000")); got != "proof_required" {
		t.Errorf("an unproven domain on a loopback installation answered %q", got)
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about %q for an unproven domain", was)
	}
}
