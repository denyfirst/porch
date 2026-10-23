package policy

import (
	"strings"
	"testing"
)

// The line names what answered once per service, and each gets a note saying
// what it is and what to do; nothing answering says how many were checked.
func TestTheExposureLineNamesWhatAnswered(t *testing.T) {
	if got := ExposureLine(true, 16, nil, ""); got != "none of the 16 services checked answers" {
		t.Errorf("nothing open reads %q", got)
	}
	open := []ExposedService{
		{Address: "192.0.2.10", Port: 3389, Name: "Remote Desktop", Why: "it is the most common way in"},
		{Address: "2001:db8::1", Port: 3389, Name: "Remote Desktop", Why: "it is the most common way in"},
		{Address: "192.0.2.10", Port: 6379, Name: "Redis", Why: "it often has no password"},
	}
	if got := ExposureLine(true, 16, open, ""); got != "Remote Desktop (3389) and Redis (6379) answer to anybody on the internet" {
		t.Errorf("two services read %q", got)
	}
	notes := Texts(DescribeExposure(open, 16))
	if len(notes) != 2 || !strings.Contains(notes[0], "192.0.2.10 and 2001:db8::1") || !strings.Contains(notes[1], "VPN") {
		t.Errorf("the notes read %v", notes)
	}
	if got := ExposureLine(true, 16, nil, "no address of the host was reached to ask"); !strings.HasPrefix(got, "not established") {
		t.Errorf("a failure reads %q", got)
	}
	if ExposureLine(false, 0, nil, "") != "" {
		t.Error("nothing asked was described")
	}
}

// Open services are one weak finding naming each; an address where every port
// answered is set apart and graded for nothing, with a note saying why.
func TestOpenServicesAreGradedAndAnAddressAcceptingEverythingIsNot(t *testing.T) {
	open := []ExposedService{
		{Address: "192.0.2.10", Port: 3389, Name: "Remote Desktop", Why: "w"},
		{Address: "192.0.2.10", Port: 6379, Name: "Redis", Why: "w"},
	}
	got := GradeExposure(open, 16)
	if len(got) != 1 || got[0].RuleID != "exposure.service-open" || got[0].Verdict != Weak || got[0].Policy != TLSVersion {
		t.Fatalf("graded %+v, want one weak exposure.service-open", got)
	}
	if !strings.Contains(got[0].Title, "Remote Desktop (3389)") || !strings.Contains(got[0].Title, "Redis (6379)") {
		t.Errorf("the finding does not name both: %q", got[0].Title)
	}
	if GradeExposure(nil, 16) != nil {
		t.Error("nothing open was graded")
	}

	// Every one of three ports at one address, one port at another.
	all := []ExposedService{
		{Address: "192.0.2.20", Port: 21, Name: "FTP", Why: "w"},
		{Address: "192.0.2.20", Port: 23, Name: "Telnet", Why: "w"},
		{Address: "192.0.2.20", Port: 3389, Name: "Remote Desktop", Why: "w"},
		{Address: "2001:db8::2", Port: 3389, Name: "Remote Desktop", Why: "w"},
	}
	got = GradeExposure(all, 3)
	if len(got) != 1 || !strings.HasPrefix(got[0].Title, "Remote Desktop (3389) answers") {
		t.Errorf("graded %+v, want Remote Desktop alone, from the address that did not accept everything", got)
	}
	line := ExposureLine(true, 3, all, "")
	if !strings.Contains(line, "Remote Desktop (3389) answers") || !strings.Contains(line, "accepts a connection at 192.0.2.20") ||
		strings.Contains(line, "FTP") {
		t.Errorf("the line reads %q", line)
	}
	notes := DescribeExposure(all, 3)
	var unsettled, observed int
	for _, n := range notes {
		switch n.Kind {
		case KindUnsettled:
			unsettled++
		case KindObserved:
			observed++
			if !strings.Contains(n.Text, "2001:db8::2") || strings.Contains(n.Text, "192.0.2.20") {
				t.Errorf("a service note names the address that accepts everything: %q", n.Text)
			}
		}
	}
	if unsettled != 1 || observed != 1 {
		t.Errorf("%d unsettled and %d observed notes, want one of each: %v", unsettled, observed, Texts(notes))
	}

	// A list of one port is not "everything".
	if got := GradeExposure([]ExposedService{{Address: "192.0.2.30", Port: 3389, Name: "Remote Desktop"}}, 1); len(got) != 1 {
		t.Errorf("with one port asked, an open one was not graded: %+v", got)
	}
}
