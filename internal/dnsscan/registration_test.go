package dnsscan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rdap"
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
