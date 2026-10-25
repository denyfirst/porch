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
	// A registration about to run out is reported, not graded: automatic
	// renewal does not show from outside.
	if got.Verdict != policy.Strong {
		t.Errorf("the registration moved the verdict to %q", got.Verdict)
	}
}

// A registry that publishes no RDAP service is said as that and leaves the
// verdict alone; one asked and not answered leaves the zone not strong
// (dns-v5). Both reach the scan from the client's own flag, not from words.
func TestARegistryWithNoServiceIsNotAnUnansweredOne(t *testing.T) {
	for _, c := range []struct {
		name string
		reg  rdap.Registration
		want policy.Verdict
	}{
		{"no service", rdap.Registration{Asked: true, NoService: true,
			Reason: "the registry for .com publishes no RDAP service"}, policy.Strong},
		{"no answer", rdap.Registration{Asked: true,
			Reason: "the registry did not answer the lookup"}, policy.Ungraded},
	} {
		got, err := (&Scanner{Resolver: served(t), Registry: &stubRegistry{reg: c.reg}}).
			Scan(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if got.Verdict != c.want {
			t.Errorf("%s: verdict %q, want %q", c.name, got.Verdict, c.want)
		}
		if got.Observed.Registration == nil || got.Observed.Registration.NoService != c.reg.NoService {
			t.Errorf("%s: the facts read %+v", c.name, got.Observed.Registration)
		}
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

// boundedRoutes answers the first two addresses, as the real client answers
// the first eight, and fails them with a reason.
type boundedRoutes struct{}

func (boundedRoutes) Check(_ context.Context, addresses []string) []rpki.Route {
	var out []rpki.Route
	for _, a := range addresses[:2] {
		out = append(out, rpki.Route{Address: a, Reason: "RIPEstat could not be reached"})
	}
	return out
}

// A route not established says why, and addresses past the bound are counted
// as not asked. Found in a report on 2026-10-25: "8 not established of 8
// addresses" for a name whose servers had twelve, and no reason anywhere.
func TestTheRoutesNotAskedAndNotEstablishedAreSaid(t *testing.T) {
	got, err := (&Scanner{Resolver: served(t), Routes: boundedRoutes{}}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// served has two addresses of its own and one for each of two servers.
	if got.Observed.RoutesSkipped != 2 {
		t.Errorf("%d addresses counted as not asked, want 2", got.Observed.RoutesSkipped)
	}
	if want := "2 not established of 2 addresses, and 2 more not asked"; got.Observed.RoutesLine != want {
		t.Errorf("the line reads %q, want %q", got.Observed.RoutesLine, want)
	}
	notes := strings.Join(policy.Texts(got.Notes), " ")
	for _, want := range []string{"was not established: RIPEstat could not be reached", "the other 2 were not asked about"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q: %s", want, notes)
		}
	}
}

// hangingRegistry and hangingRoutes answer only once they are given up on.
type hangingRegistry struct{}

func (hangingRegistry) Lookup(ctx context.Context, _ string) rdap.Registration {
	<-ctx.Done()
	return rdap.Registration{Asked: true, Reason: "the registry did not answer in the time the scan allows"}
}

type hangingRoutes struct{}

func (hangingRoutes) Check(ctx context.Context, addresses []string) []rpki.Route {
	<-ctx.Done()
	var out []rpki.Route
	for _, a := range addresses {
		out = append(out, rpki.Route{Address: a, Reason: "RIPEstat did not answer in the time the scan allows"})
	}
	return out
}

// A registry and a route service that never answer cost the report two lines,
// not the report. The scan comes back before its caller's deadline, so the
// handler does not throw away the zone's own answers, and both lines say what
// was not established (live test, 2026-10-20).
func TestSlowOutsideServicesDoNotSpendTheScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), outsideReserve+time.Second)
	defer cancel()

	got, err := (&Scanner{Resolver: served(t), Registry: hangingRegistry{}, Routes: hangingRoutes{}}).
		Scan(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("the scan ran into its caller's deadline, so the handler would discard the report")
	}
	if line := got.Observed.RegistrationLine; !strings.HasPrefix(line, "not established: ") {
		t.Errorf("the registration line reads %q", line)
	}
	if line := got.Observed.RoutesLine; !strings.Contains(line, "not established") {
		t.Errorf("the routes line reads %q", line)
	}
	// Since dns-v5 a registration asked about and not read withholds strong,
	// because a registration that has run out is graded. Nothing worse: a
	// question that went unanswered is not a finding.
	if got.Verdict != policy.Ungraded || len(got.Findings) != 0 {
		t.Errorf("a registry that did not answer graded the zone %q %v, want ungraded and nothing more",
			got.Verdict, ruleIDs(got))
	}

	// The routes are described and never graded, so a route service that
	// never answers moves nothing.
	fresh, stop := context.WithTimeout(context.Background(), outsideReserve+time.Second)
	defer stop()
	routesOnly, err := (&Scanner{Resolver: served(t), Routes: hangingRoutes{}}).Scan(fresh, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if routesOnly.Verdict != policy.Strong {
		t.Errorf("a route service that did not answer moved the verdict to %q", routesOnly.Verdict)
	}
}
