package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/certnames"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/knownnames"
	"github.com/denyfirst/porch/internal/liveness"
	"github.com/denyfirst/porch/internal/passivedns"
	"github.com/denyfirst/porch/internal/ptrnames"
	"github.com/denyfirst/porch/internal/zonenames"
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

// stubRecords answers for the domain's own records without asking anybody, and
// records what it was asked.
type stubRecords struct {
	asked atomic.Value
	found dnsnames.Found
}

func (r *stubRecords) Under(_ context.Context, domain string) dnsnames.Found {
	r.asked.Store(domain)
	return r.found
}

func (r *stubRecords) was() string {
	if v, ok := r.asked.Load().(string); ok {
		return v
	}
	return ""
}

// The service reads both sources, and every name says which of them named it.
//
// The page is the face most operators see, and until this it showed half an
// estate: a certificate log cannot see a host on plain HTTP, one behind a
// private authority, or anything hidden by a wildcard, and the domain's own
// mail, sender policy and delegation name some of exactly those.
func TestTheServiceReadsBothSourcesForAProvenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 2,
		Names: []ctsearch.Name{
			{Name: "www.proven.example"},
			{Name: "mail.proven.example"},
		},
	}})
	s.records = &stubRecords{found: dnsnames.Found{
		Asked: true,
		Names: []dnsnames.Name{
			{Name: "mail.proven.example", Sources: []dnsnames.Source{dnsnames.FromMX}},
			{Name: "ns1.proven.example", Sources: []dnsnames.Source{dnsnames.FromNS}},
		},
	}}

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.70:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Distinct != 3 {
		t.Errorf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}

	want := map[string]int{"www.proven.example": 1, "mail.proven.example": 2, "ns1.proven.example": 1}
	for _, n := range got.Names {
		sources, known := want[n.Name]
		if !known {
			t.Errorf("%s is in the inventory and should not be", n.Name)
			continue
		}
		if len(n.Sources) != sources {
			t.Errorf("%s was named by %v", n.Name, n.Sources)
		}
	}

	// And each source says how much of the list it is answerable for, so that
	// a report missing half of itself cannot read like a whole one (R4).
	if !got.Logs.Established() || got.Logs.Named != 2 {
		t.Errorf("the log reading came back as %+v", got.Logs)
	}
	if !got.Records.Established() || got.Records.Named != 2 {
		t.Errorf("the record reading came back as %+v", got.Records)
	}
}

// Neither source is read for a domain nobody proved control of.
//
// The proof gate is the whole of what makes this endpoint something other than
// an anonymous reconnaissance service, and a source added after the gate was
// written must be behind it too. Three lookups of a stranger's domain, made by
// this installation on request, are three lookups this installation made.
func TestNeitherSourceIsReadForAnUnprovenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	monitor := &stubMonitor{estate: ctsearch.Estate{Asked: true}}
	s.SearchNames(monitor)
	records := &stubRecords{found: dnsnames.Found{Asked: true}}
	s.records = records

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.71:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := records.was(); was != "" {
		t.Errorf("the domain's own records were read for %q, which nobody proved", was)
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about %q, which nobody proved", was)
	}
}

// An installation with no resolver says the records were not read.
//
// Not that the domain publishes none. The two are the same empty list and only
// one of them is true, so the reading carries which it is (R4) — and the half
// that was established is still answered with, rather than thrown away to
// report the half that was not.
func TestAnInstallationWithNoResolverSaysTheRecordsWereNotRead(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}},
	}})
	if s.records != nil {
		t.Fatal("this fixture was built with a resolver, which is not what it is for")
	}

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.72:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Records.Asked {
		t.Errorf("an installation with no resolver reports that it read the records: %+v", got.Records)
	}
	if got.Distinct != 1 || !got.Logs.Established() {
		t.Errorf("the half that was established was lost: %+v", got)
	}
}

// An installation with a resolver reads the records without being told to.
//
// The other half of the rule above. A reader that had to be wired up by hand
// would be wired up in porchd and not in a fixture, and the endpoint would
// answer with half an inventory everywhere it was not — which is the failure
// this whole pair exists to make impossible to ship quietly.
func TestAnInstallationWithAResolverReadsTheRecords(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	if s.records == nil {
		t.Error("an installation with a resolver has nothing to read the domain's own records with")
	}
}

// stubLiveness answers what the names are doing without dialling anything, and
// records which names it was given.
type stubLiveness struct {
	asked  atomic.Value
	answer []liveness.Name
}

func (l *stubLiveness) Check(_ context.Context, names []string) []liveness.Name {
	l.asked.Store(strings.Join(names, " "))
	return l.answer
}

func (l *stubLiveness) was() string {
	if v, ok := l.asked.Load().(string); ok {
		return v
	}
	return ""
}

// The service says what each name is doing now, as the command line does.
//
// A list of names is a record of the past whichever register it came from, and
// an operator reading their own estate is asking about the present. Until this
// the page handed them names with dates and left the question unanswered, so
// the work of finding out which of forty names still exist was theirs.
func TestTheServiceSaysWhatEachNameIsDoing(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 2,
		Names: []ctsearch.Name{
			{Name: "www.proven.example"},
			{Name: "old.proven.example"},
			{Name: "*.proven.example", Wildcard: true},
		},
	}})
	probe := &stubLiveness{answer: []liveness.Name{
		{Name: "www.proven.example", Status: liveness.Live, Answered: []string{"443"}},
		{Name: "old.proven.example", Status: liveness.Gone},
	}}
	s.live = probe

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.80:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Probed {
		t.Error("the names were asked what they are doing and the answer does not say so")
	}

	states := map[string]liveness.Status{}
	for _, n := range got.Names {
		if n.Now != nil {
			states[n.Name] = n.Now.Status
		}
	}
	if states["www.proven.example"] != liveness.Live || states["old.proven.example"] != liveness.Gone {
		t.Errorf("the states came back as %+v", states)
	}

	// A wildcard is never put through a resolver: nothing resolves
	// `*.proven.example`, and the failure would read as a dead host that never
	// existed.
	if strings.Contains(probe.was(), "*") {
		t.Errorf("a wildcard was asked about as a name: %q", probe.was())
	}
}

// No name is probed for a domain nobody proved control of.
//
// This is the part of the inventory that touches the estate — one resolution
// per name and at most one connection per address — so it sits behind the same
// gate as the registers. A service that opened connections to a stranger's
// hosts on request would be a scanner anybody could point anywhere, which is
// the thing this endpoint exists not to be.
func TestNoNameIsProbedForAnUnprovenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true}})
	probe := &stubLiveness{}
	s.live = probe

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.81:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := probe.was(); was != "" {
		t.Errorf("names were probed for a domain nobody proved: %q", was)
	}
}

// The probe this installation builds dials through safedial.
//
// Nothing here sets a dialler, and that is the guard rather than an omission:
// internal/liveness reads a nil dialler as safedial, which refuses private,
// loopback, link-local and reserved destinations. A proven domain whose name
// points at 127.0.0.1, or at a cloud metadata address, must not turn this
// service into a way of reaching it (N6).
func TestTheProbeTheServiceBuildsRefusesPrivateDestinations(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	checker, ok := s.live.(*liveness.Checker)
	if !ok {
		t.Fatalf("the installation's probe is a %T", s.live)
	}
	if checker.Dial != nil {
		t.Error("the probe was given a dialler of its own, so safedial no longer decides what it may reach")
	}
	if checker.Resolver == nil {
		t.Error("the probe has no resolver, so every name would come back unchecked")
	}
}

// stubRegister answers as a passive register would, and records what it was
// asked about.
type stubRegister struct {
	asked atomic.Value
	found passivedns.Found
}

func (r *stubRegister) Under(_ context.Context, domain string) passivedns.Found {
	r.asked.Store(domain)
	return r.found
}

func (r *stubRegister) was() string {
	if v, ok := r.asked.Load().(string); ok {
		return v
	}
	return ""
}

// The service reads a register where one was configured, and never for a
// domain nobody proved.
//
// This source is the one that sees behind a wildcard, and it is also the one
// that spends the operator's own account: two reasons for it to be asked only
// about estates somebody has been shown to control.
func TestTheServiceReadsTheRegisterOnlyForAProvenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}},
	}})
	register := &stubRegister{found: passivedns.Found{
		Asked: true, Register: "securitytrails",
		Names: []string{"bitrix.proven.example", "www.proven.example"},
	}}
	s.AskPassiveRegister(register)

	// The domain nobody proved: not one question is put to the register.
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.90:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := register.was(); was != "" {
		t.Errorf("the register was asked about %q, which nobody proved", was)
	}

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.91:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}
	if register.was() != "proven.example" {
		t.Errorf("the register was asked about %q", register.was())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Passive.Established() || got.Passive.Named != 2 {
		t.Errorf("the register's reading came back as %+v", got.Passive)
	}
	if got.Distinct != 2 {
		t.Errorf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}

	// The name only the register has says so, and the name both have says
	// both.
	sources := map[string]int{}
	for _, n := range got.Names {
		sources[n.Name] = len(n.Sources)
	}
	if sources["bitrix.proven.example"] != 1 || sources["www.proven.example"] != 2 {
		t.Errorf("the provenance came back as %+v", sources)
	}
}

// An installation with no register configured says so, rather than reporting
// an estate with nothing behind its wildcards.
func TestAnInstallationWithNoRegisterSaysItAskedNone(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}},
	}})

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.92:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Passive.Asked || got.Passive.Reason != "" {
		t.Errorf("an installation with no register reports %+v", got.Passive)
	}
}

// stubCertificates answers as the hosts' own certificates would, and records
// which hosts it was given.
type stubCertificates struct {
	asked atomic.Value
	found certnames.Found
}

func (c *stubCertificates) Under(_ context.Context, _ string, hosts []string) certnames.Found {
	c.asked.Store(strings.Join(hosts, " "))
	return c.found
}

func (c *stubCertificates) was() string {
	if v, ok := c.asked.Load().(string); ok {
		return v
	}
	return ""
}

// The service reads the certificates the hosts present, asks only the ones
// that answer, and asks what the new names are doing.
//
// The order is the whole of it: the hosts worth knocking on are the ones the
// probe has just established are answering, and a name that arrives off a
// certificate has to be asked what it is doing like any other — otherwise the
// newest half of the inventory is the half with nothing beside it (R4).
func TestTheServiceReadsTheCertificatesTheHostsPresent(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 1,
		Names: []ctsearch.Name{
			{Name: "www.proven.example"},
			{Name: "gone.proven.example"},
		},
	}})

	probe := &stubLiveness{answer: []liveness.Name{
		{Name: "www.proven.example", Status: liveness.Live, Answered: []string{"443"}},
		{Name: "gone.proven.example", Status: liveness.Gone},
	}}
	s.live = probe

	certificates := &stubCertificates{found: certnames.Found{
		Asked: true, Hosts: 1, Answered: 1,
		Names: []string{"www.proven.example", "internal.proven.example"},
	}}
	s.ReadHostCertificates(certificates)

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.93:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}

	// Only the host that answers is knocked on again. Asking one that does not
	// resolve spends a timeout to learn what the report already says.
	if certificates.was() != "www.proven.example" {
		t.Errorf("the certificates were asked of %q", certificates.was())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Presented.Established() || got.Presented.Named != 2 {
		t.Errorf("the hosts' reading came back as %+v", got.Presented)
	}
	if got.Distinct != 3 {
		t.Errorf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}

	// And the name that arrived off a certificate was asked what it is doing,
	// rather than being the one line in the report with nothing beside it.
	if !strings.Contains(probe.was(), "internal.proven.example") {
		t.Errorf("the name a certificate produced was never asked about: %q", probe.was())
	}
}

// No certificate is asked for on a domain nobody proved.
func TestNoCertificateIsReadForAnUnprovenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true}})
	s.live = &stubLiveness{}
	certificates := &stubCertificates{}
	s.ReadHostCertificates(certificates)

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.94:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := certificates.was(); was != "" {
		t.Errorf("a host was asked for its certificate on a domain nobody proved: %q", was)
	}
}

// stubReverse answers as a reverse walk would, and records what it walked.
type stubReverse struct {
	asked atomic.Value
	found ptrnames.Found
}

func (r *stubReverse) Under(_ context.Context, _ string, ranges []netip.Prefix) ptrnames.Found {
	var seen []string
	for _, p := range ranges {
		seen = append(seen, p.String())
	}
	r.asked.Store(strings.Join(seen, " "))
	return r.found
}

func (r *stubReverse) was() string {
	if v, ok := r.asked.Load().(string); ok {
		return v
	}
	return ""
}

// An address range is walked for the operator, and for nobody else.
//
// This is the one capability proof of control cannot grant. A domain is proven
// with a record in its zone; an address range is not provable by anything this
// project can check. So a service that walked one for whoever proved a domain
// would be a reverse-scanner for whoever proved a domain — while refusing the
// person who runs the installation would be friction bought with no safety,
// which is the reasoning that decided proof for the inventory itself.
func TestAnAddressRangeIsWalkedForTheOperatorAndNobodyElse(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}}}})

	walk := &stubReverse{found: ptrnames.Found{Asked: true, Addresses: 16, Answered: 1,
		Names: []string{"build.proven.example"}}}
	s.reverse = walk

	body := `{"target":"proven.example","ranges":["203.0.113.0/28"]}`

	// Reachable by anybody, with proof configured: the domain is proven and
	// the range still is not, so the range is refused and nothing is walked.
	s.ReachableByOthers(true)
	s.BehindPassword(false)
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan", body, "203.0.113.120:5000")); got != "not_your_range" {
		t.Errorf("a range on a reachable installation was answered %q", got)
	}
	if was := walk.was(); was != "" {
		t.Errorf("a range was walked for somebody who only proved a domain: %q", was)
	}

	// Nobody else can reach it: the caller is the operator.
	s.ReachableByOthers(false)
	w := postTo(t, s, "/api/v1/names/scan", body, "203.0.113.121:5000")
	if w.Code != 200 {
		t.Fatalf("a range on a loopback installation answered %d: %s", w.Code, w.Body.String())
	}
	if walk.was() != "203.0.113.0/28" {
		t.Errorf("the walk covered %q", walk.was())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Reverse.Established() || got.Reverse.Named != 1 {
		t.Errorf("the walk's reading came back as %+v", got.Reverse)
	}

	// Or a password the operator set stands in front of it, which is the same
	// answer to the same question: the callers are people they let in.
	s.ReachableByOthers(true)
	s.BehindPassword(true)
	if w := postTo(t, s, "/api/v1/names/scan", body, "203.0.113.122:5000"); w.Code != 200 {
		t.Errorf("a range behind a password answered %d: %s", w.Code, w.Body.String())
	}
}

// A range too wide to read is refused before anything is asked, and the
// refusal never repeats what was typed.
func TestARangeTooWideIsRefusedByTheService(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.ReachableByOthers(false)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true}})
	walk := &stubReverse{}
	s.reverse = walk

	for _, tc := range []struct{ body, says string }{
		{`{"target":"example.test","ranges":["203.0.0.0/16"]}`, "narrower"},
		{`{"target":"example.test","ranges":["not-a-range"]}`, "203.0.113.0/24"},
	} {
		w := postTo(t, s, "/api/v1/names/scan", tc.body, "203.0.113.123:5000")
		if got := errorCode(t, w); got != "invalid_range" {
			t.Errorf("%s was answered %q", tc.body, got)
		}
		if !strings.Contains(w.Body.String(), tc.says) {
			t.Errorf("the refusal for %s does not say %q: %s", tc.body, tc.says, w.Body.String())
		}
	}
	if was := walk.was(); was != "" {
		t.Errorf("a refused range was walked anyway: %q", was)
	}

	// And the refusal for a malformed range does not echo it back (I6).
	w := postTo(t, s, "/api/v1/names/scan",
		`{"target":"example.test","ranges":["203.0.113.999/24"]}`, "203.0.113.124:5000")
	if strings.Contains(w.Body.String(), "999") {
		t.Errorf("the refusal repeats what was typed: %s", w.Body.String())
	}
}

// A check takes no address ranges, and says so rather than dropping them.
func TestACheckRefusesAddressRanges(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	w := postTo(t, s, "/api/v1/tls/scan",
		`{"target":"example.test","ranges":["203.0.113.0/28"]}`, "203.0.113.125:5000")
	if got := errorCode(t, w); got != "bad_request" {
		t.Errorf("a check sent ranges answered %q", got)
	}
	if !strings.Contains(w.Body.String(), "name inventory reads them") {
		t.Errorf("the refusal does not say where ranges belong: %s", w.Body.String())
	}
}

// stubZone hands a zone over without asking any server anything.
type stubZone struct {
	asked atomic.Value
	found zonenames.Found
}

func (z *stubZone) Under(_ context.Context, domain string) zonenames.Found {
	z.asked.Store(domain)
	return z.found
}

func (z *stubZone) was() string {
	if v, ok := z.asked.Load().(string); ok {
		return v
	}
	return ""
}

// The zone is read for a proven domain, and for no other.
//
// The DNS check asks whether a zone transfers to anybody and reads none of it,
// because that zone belongs to whoever runs it. Reading one is for an estate
// the asker owns, and on a service that means a domain this installation has
// been shown control of — the same gate every other source is behind.
func TestTheZoneIsReadOnlyForAProvenDomain(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}}}})
	zone := &stubZone{found: zonenames.Found{
		Asked: true, Servers: 2, Refused: 1, From: "ns2.proven.example",
		Names: []string{"www.proven.example", "staging.proven.example"},
	}}
	s.ReadZoneTransfers(zone)

	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"unproven.example"}`, "203.0.113.130:5000")); got != "proof_required" {
		t.Errorf("an unproven domain was answered %q", got)
	}
	if was := zone.was(); was != "" {
		t.Errorf("the zone of %q was read, and nobody proved it", was)
	}

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.131:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain answered %d: %s", w.Code, w.Body.String())
	}
	if zone.was() != "proven.example" {
		t.Errorf("the zone read was %q", zone.was())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Zone.Established() || got.Zone.Named != 2 {
		t.Errorf("the zone's reading came back as %+v", got.Zone)
	}
	if got.Distinct != 2 {
		t.Errorf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}
}

// An installation that was not told to ask for a zone does not ask.
func TestAnInstallationNotToldToReadAZoneDoesNot(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}}}})

	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.132:5000")
	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Zone.Asked || got.Zone.Reason != "" {
		t.Errorf("an installation that asks for no zone reports %+v", got.Zone)
	}
}

// The list a caller already has is read for a domain they proved, and for no
// other.
//
// A range cannot be proven and is refused to anybody but the operator (A30).
// A list of names can: every name in it is held to the domain the caller has
// already been shown to control, so the worst a list can cause is this
// installation resolving hosts under an estate that is theirs. That makes the
// gate the ordinary one — but it is still a gate, and a list sent for a domain
// nobody proved must reach nothing.
func TestAListOfNamesIsReadForAProvenDomainAndNoOther(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}}}})

	body := `{"target":"unproven.example","names":["bitrix.unproven.example"]}`
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan", body, "203.0.113.150:5000")); got != "proof_required" {
		t.Errorf("an unproven domain with a list was answered %q", got)
	}

	w := postTo(t, s, "/api/v1/names/scan",
		`{"target":"proven.example","names":["bitrix.proven.example","www.proven.example","x.other.example"]}`,
		"203.0.113.151:5000")
	if w.Code != 200 {
		t.Fatalf("a proven domain with a list answered %d: %s", w.Code, w.Body.String())
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if !got.Known.Established() || got.Known.Named != 2 {
		t.Errorf("the list's reading came back as %+v", got.Known)
	}
	if got.Known.Foreign != 1 {
		t.Errorf("a name under another domain was not counted as one: %+v", got.Known)
	}
	if got.Distinct != 2 {
		t.Errorf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}

	// And the name nothing published is in the report, labelled as the
	// caller's own. That row is the whole reason to send a list.
	var alone bool
	for _, n := range got.Names {
		if n.Name == "bitrix.proven.example" {
			alone = len(n.Sources) == 1 && n.Sources[0] == inventory.FromOperator
		}
	}
	if !alone {
		t.Errorf("a name only the caller had is not labelled as theirs: %+v", got.Names)
	}
}

// A list longer than an estate is refused, and the message says the rule.
//
// The bound is the line between a list somebody has and a dictionary being
// tried against a resolver, so it is where this mode could quietly become the
// thing it refuses to be (N7). It is refused whole rather than cut to size,
// because a list silently shortened is an inventory that is quietly
// incomplete (R4), and the message names no host that was sent (I6).
func TestAListLongerThanAnEstateIsRefusedByTheService(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true}})

	names := make([]string, knownnames.MaxNames+1)
	for i := range names {
		names[i] = fmt.Sprintf("host%d.proven.example", i)
	}
	body, err := json.Marshal(map[string]any{"target": "proven.example", "names": names})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	w := postTo(t, s, "/api/v1/names/scan", string(body), "203.0.113.152:5000")
	if got := errorCode(t, w); got != "list_too_long" {
		t.Fatalf("a wordlist was answered %q: %s", got, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "host0.proven.example") {
		t.Errorf("the refusal echoes what was sent: %s", w.Body.String())
	}
}

// A check refuses a list rather than dropping it.
//
// The same rule as an address range: a field accepted and ignored is a caller
// believing something happened. A check measures one host and has nothing to
// do with a list of them.
func TestACheckRefusesAListOfNames(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for _, path := range []string{"/api/v1/tls/scan", "/api/v1/web/scan", "/api/v1/mail/scan", "/api/v1/dns/scan"} {
		body := `{"target":"example.test","names":["www.example.test"]}`
		if got := errorCode(t, postTo(t, s, path, body, "203.0.113.153:5000")); got != "bad_request" {
			t.Errorf("%s answered a list of names with %q", path, got)
		}
	}
}

// A list nobody gave is not an empty list, and a list one caller gave is never
// kept for the next one.
//
// Two halves of the same property. The first is the difference every source
// here is held to: a report where no list was handed over and a report where
// one was handed over and added nothing are different reports, and only Asked
// says which happened (R4).
//
// The second is what the first would cost if it were wrong. A kept copy exists
// so that the same question asked twice is answered once, and a list makes it a
// different question — the caller's own names are in the answer. Filing that
// under the domain would hand one caller's list to the next caller who asked
// about the same domain, which is somebody else's estate arriving in a report
// they did not ask for.
func TestAListIsNeverKeptForTheNextCaller(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	s.SearchNames(&stubMonitor{estate: ctsearch.Estate{Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "www.proven.example"}}}})
	s.KeepInventoryFor(time.Hour)

	read := func(body, from string) inventory.Inventory {
		t.Helper()
		w := postTo(t, s, "/api/v1/names/scan", body, from)
		if w.Code != 200 {
			t.Fatalf("the inventory answered %d: %s", w.Code, w.Body.String())
		}
		var got inventory.Inventory
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("the inventory did not decode: %v", err)
		}
		return got
	}

	// One caller hands over a list.
	with := read(`{"target":"proven.example","names":["bitrix.proven.example"]}`, "203.0.113.160:5000")
	if !with.Known.Asked || with.Known.Named != 1 {
		t.Fatalf("the list came back as %+v", with.Known)
	}

	// The next asks the same domain and hands over nothing.
	without := read(`{"target":"proven.example"}`, "203.0.113.161:5000")
	if without.Known.Asked {
		t.Errorf("a caller who gave no list is told one was given: %+v", without.Known)
	}
	for _, n := range without.Names {
		if n.Name == "bitrix.proven.example" {
			t.Errorf("one caller's own list reached another caller: %+v", without.Names)
		}
	}
}
