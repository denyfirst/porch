package webscan

import (
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/securitytxt"
	"github.com/denyfirst/porch/internal/webprobe"
)

// What the probe read about a site's security contact reaches the report, and
// the clock that decides whether it has expired is the one the caller gave.
//
// Both halves escaped a sabotage before this existed. The facts could be
// dropped on the way from the probe to the rules and every report would say
// "none published" about sites that publish one; and the grade could read the
// wall clock instead of the scanner's, which is the difference between a test
// that says what a date means and a test that means something different every
// day it runs.
func TestTheSecurityContactReachesTheReportAndTheGivenClockDecides(t *testing.T) {
	at := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	report := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, nil)),
		SecurityTxt: securitytxt.Facts{
			Asked: true, Served: true, Contacts: 3,
			Expires: at.Add(48 * time.Hour),
		},
	}

	standing := says(t, GradeAt(report, at), "Security contact")
	if !strings.Contains(standing, "3 contacts") {
		t.Errorf("the count did not reach the report: %q", standing)
	}
	if !strings.Contains(standing, "expires 2026-09-26") {
		t.Errorf("a contact two days from expiry read as %q", standing)
	}

	// The same report, read from after the date the site itself put on the
	// file. Nothing about the measurement changed; only the clock did.
	later := says(t, GradeAt(report, at.Add(96*time.Hour)), "Security contact")
	if !strings.Contains(later, "expired 2026-09-26") {
		t.Errorf("read from after the expiry, the row says %q", later)
	}
}

// says returns what one row of a result said, and fails where there is no such
// row — a row that quietly disappears is the failure R4 is about.
func says(t *testing.T, r *Result, label string) string {
	t.Helper()

	for _, d := range r.Declared {
		if d.Label == label {
			return d.Says
		}
	}
	t.Fatalf("no %q row was drawn: %+v", label, r.Declared)
	return ""
}

// Where this name's own chain ended is half the answer about whether the two
// forms agree, and it comes from the chain this check already followed.
//
// The probe can only say what the other form did. Whether that amounts to
// agreement depends on where the scanned name sends a visitor, which nothing
// but this translation knows — and a chain that stayed put has not sent anybody
// anywhere, so reporting its own name as somewhere it sends visitors would make
// every site on earth look as though it redirected to itself.
func TestWhereThisNameLandsReachesTheRowAboutTheOtherForm(t *testing.T) {
	at := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	// The scanned name serves its own site, and the www form sends visitors to
	// it. The two agree, in that direction.
	toHere := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, nil)),
		Counterpart: webprobe.CounterpartFacts{
			Asked: true, Name: "www.example.test", Answered: true, Status: 301,
			SendsTo: "example.test",
		},
	}
	if got := says(t, GradeAt(toHere, at), "The other form"); got != "www.example.test sends visitors to this name" {
		t.Errorf("the row reads %q", got)
	}

	// A chain that stayed on the scanned name must not be reported as sending
	// visitors to itself.
	if got := counterpartFacts(toHere); got.LandsOn != "" {
		t.Errorf("a chain that never moved says it lands on %q", got.LandsOn)
	}
	if got := counterpartFacts(toHere); got.Scanned != "example.test" {
		t.Errorf("the scanned name reached the rules as %q", got.Scanned)
	}
}
