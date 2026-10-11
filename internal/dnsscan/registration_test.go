package dnsscan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rdap"
	"github.com/denyfirst/porch/internal/rpki"
)

// stubRegistry answers every lookup with one registration and records what it
// was asked.
type stubRegistry struct {
	asked []string
	reg   rdap.Registration
}

func (s *stubRegistry) Lookup(_ context.Context, name string) rdap.Registration {
	s.asked = append(s.asked, name)
	return s.reg
}

// The registry is asked once per scan, and what it holds reaches the facts,
// the line both faces print, and the notes.
func TestTheRegistrationReachesTheReport(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r := &stubRegistry{reg: rdap.Registration{
		Asked: true, Domain: "example.com", Registrar: "Example Registrar",
		Expires: now.Add(10 * 24 * time.Hour), Statuses: []string{"active"},
	}}

	got, err := (&Scanner{Resolver: served(t), Registry: r, Now: func() time.Time { return now }}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 1 || r.asked[0] != "example.com" {
		t.Errorf("the registry was asked %v", r.asked)
	}
	f := got.Observed.Registration
	if f == nil || f.Registrar != "Example Registrar" || f.TransferLocked {
		t.Fatalf("the facts read %+v", f)
	}
	if !strings.Contains(got.Observed.RegistrationLine, "runs out 2026-10-20, in 10 days; not locked against transfer") {
		t.Errorf("the line reads %q", got.Observed.RegistrationLine)
	}
	notes := strings.Join(policy.Texts(got.Notes), " ")
	if !strings.Contains(notes, "within a month") || !strings.Contains(notes, "not locked against transfer") {
		t.Errorf("the notes do not say what to act on: %s", notes)
	}
	// Reported, never graded (R21).
	if got.Verdict != policy.Strong {
		t.Errorf("the registration moved the verdict to %q", got.Verdict)
	}
}

// Without a registry nothing is asked and nothing is said.
func TestNoRegistryAsksNothing(t *testing.T) {
	got := read(t, served(t))
	if got.Observed.Registration != nil || got.Observed.RegistrationLine != "" {
		t.Errorf("a scan with no registry reports %+v", got.Observed.Registration)
	}
}

// stubRoutes answers every address with one state and records what it was
// asked.
type stubRoutes struct {
	asked []string
	state string
}

func (s *stubRoutes) Check(_ context.Context, addresses []string) []rpki.Route {
	s.asked = addresses
	var out []rpki.Route
	for _, a := range addresses {
		out = append(out, rpki.Route{Address: a, State: s.state})
	}
	return out
}

// The routes to the name's addresses and its name servers' are asked about,
// the name's first, and reach the line both faces print and the notes.
func TestTheRoutesReachTheReport(t *testing.T) {
	r := &stubRoutes{state: rpki.NotFound}
	got, err := (&Scanner{Resolver: served(t), Routes: r}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.asked) < 2 || r.asked[0] != got.Observed.IPv4[0] {
		t.Errorf("the addresses asked about were %v", r.asked)
	}
	if !strings.Contains(got.Observed.RoutesLine, "not signed") {
		t.Errorf("the line reads %q", got.Observed.RoutesLine)
	}
	if notes := strings.Join(policy.Texts(got.Notes), " "); !strings.Contains(notes, "Nobody has signed the route") {
		t.Errorf("the notes do not say the route is unsigned: %s", notes)
	}
	if got.Verdict != policy.Strong {
		t.Errorf("the routes moved the verdict to %q", got.Verdict)
	}
	if plain := read(t, served(t)); plain.Observed.Routes != nil || plain.Observed.RoutesLine != "" {
		t.Error("a scan with no route checker reported routes")
	}
}
