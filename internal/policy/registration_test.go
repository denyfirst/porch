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
	// Graded since porch-dns-v4 (dns.registration-expired), and said by the
	// finding rather than twice.
	if notes := strings.Join(Texts(DescribeRegistration(f, now)), " "); strings.Contains(notes, "run out") {
		t.Errorf("an expired registration is described as well as graded: %q", notes)
	}
	graded := GradeDNS(DNSFacts{Apex: true, NameServers: []NameServer{{Name: "a.ns.example", Addresses: []string{"192.0.2.1"}}, {Name: "b.ns.example", Addresses: []string{"198.51.100.1"}}}, Networks: 2, Registration: &f}, now)
	if graded.Verdict != Insecure || !hasRule(graded.Findings, "dns.registration-expired", Insecure) {
		t.Errorf("an expired registration graded %q", graded.Verdict)
	}

	f.RegistryLocked, f.TransferLocked = true, true
	if line := RegistrationLine(f, now); !strings.Contains(line, "locked at the registry") {
		t.Errorf("a registry lock reads %q", line)
	}
}

// A registry that did not answer is said to be one, and nothing is claimed
// about the registration; a registry nobody asked says nothing at all.
//
// Since dns-v5 what a failed lookup costs is said too: a registration that
// has run out is graded, so the zone is not strong while it is unknown. A
// registry with no RDAP service is said as that, and costs nothing, because
// no scan can ask it.
func TestARegistrationNotEstablishedClaimsNothing(t *testing.T) {
	now := time.Now()
	f := RegistrationFacts{Asked: true, Reason: "the registry did not answer the lookup"}
	if got := RegistrationLine(f, now); got != "not established: the registry did not answer the lookup" {
		t.Errorf("the line reads %q", got)
	}
	notes := DescribeRegistration(f, now)
	if len(notes) != 1 || notes[0].Kind != KindUnsettled ||
		!strings.HasPrefix(notes[0].Text, "Whether the registration has run out was not established") {
		t.Errorf("a failed lookup is described as %v", notes)
	}

	none := RegistrationFacts{Asked: true, Reason: "the registry for .az publishes no RDAP service", NoService: true}
	notes = DescribeRegistration(none, now)
	if len(notes) != 1 || notes[0].Kind != KindUnsettled || !strings.Contains(notes[0].Text, "no scan can ask it") {
		t.Errorf("a registry with no service is described as %v", notes)
	}

	if RegistrationLine(RegistrationFacts{}, now) != "" || DescribeRegistration(RegistrationFacts{}, now) != nil {
		t.Error("a registry nobody asked is described")
	}
}
