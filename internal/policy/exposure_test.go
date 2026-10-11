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
	notes := Texts(DescribeExposure(open))
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
