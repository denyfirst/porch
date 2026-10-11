package policy

import (
	"strings"
	"testing"
	"time"
)

// The line says who, when and whether it is locked, and the notes say what to
// act on, never more.
func TestTheRegistrationLineSaysWhenAndWhetherItIsLocked(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f := RegistrationFacts{Asked: true, Domain: "example.test", Registrar: "Namecheap, Inc.",
		Expires: now.Add(291 * 24 * time.Hour), TransferLocked: true}

	if got := RegistrationLine(f, now); got != "example.test, registered through Namecheap, Inc.; runs out 2027-07-28, in 291 days; locked against transfer" {
		t.Errorf("the line reads %q", got)
	}
	if notes := DescribeRegistration(f, now); len(notes) != 0 {
		t.Errorf("a locked domain a year from expiry carries notes: %v", Texts(notes))
	}

	f.TransferLocked = false
	f.Expires = now.Add(10 * 24 * time.Hour)
	line := RegistrationLine(f, now)
	notes := strings.Join(Texts(DescribeRegistration(f, now)), " ")
	if !strings.Contains(line, "in 10 days") || !strings.Contains(line, "not locked against transfer") {
		t.Errorf("the line reads %q", line)
	}
	if !strings.Contains(notes, "within a month") || !strings.Contains(notes, "clientTransferProhibited") {
		t.Errorf("the notes read %q", notes)
	}

	f.Expires = now.Add(-3 * 24 * time.Hour)
	if line := RegistrationLine(f, now); !strings.Contains(line, "ran out") || !strings.Contains(line, "3 days ago") {
		t.Errorf("an expired registration reads %q", line)
	}
	if notes := strings.Join(Texts(DescribeRegistration(f, now)), " "); !strings.Contains(notes, "has run out") {
		t.Errorf("an expired registration's notes read %q", notes)
	}

	f.RegistryLocked, f.TransferLocked = true, true
	if line := RegistrationLine(f, now); !strings.Contains(line, "locked at the registry") {
		t.Errorf("a registry lock reads %q", line)
	}
}

// A registry that did not answer is said to be one, and nothing is claimed
// about the registration; a registry nobody asked says nothing at all.
func TestARegistrationNotEstablishedClaimsNothing(t *testing.T) {
	now := time.Now()
	f := RegistrationFacts{Asked: true, Reason: "the registry did not answer the lookup"}
	if got := RegistrationLine(f, now); got != "not established: the registry did not answer the lookup" {
		t.Errorf("the line reads %q", got)
	}
	if notes := DescribeRegistration(f, now); notes != nil {
		t.Errorf("a failed lookup carries notes: %v", Texts(notes))
	}
	if RegistrationLine(RegistrationFacts{}, now) != "" || DescribeRegistration(RegistrationFacts{}, now) != nil {
		t.Error("a registry nobody asked is described")
	}
}
