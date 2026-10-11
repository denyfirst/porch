package policy

import (
	"strings"
	"testing"
)

// The line counts each state, and the notes say what an invalid or unsigned
// route means and who can change it.
func TestTheRoutesLineCountsEachState(t *testing.T) {
	all := []RouteFacts{{Address: "192.0.2.1", State: "valid"}, {Address: "2001:db8::1", State: "valid"}}
	if got := RoutesLine(all); got != "signed and valid for all 2 addresses" {
		t.Errorf("all valid reads %q", got)
	}
	if notes := DescribeRoutes(all); len(notes) != 0 {
		t.Errorf("valid routes carry notes: %v", Texts(notes))
	}

	mixed := []RouteFacts{
		{Address: "192.0.2.1", State: "invalid"},
		{Address: "192.0.2.2", State: "not-found"},
		{Address: "192.0.2.3", State: "valid"},
		{Address: "192.0.2.4", Reason: "RIPEstat could not be reached"},
	}
	if got := RoutesLine(mixed); got != "1 invalid, 1 not signed, 1 valid, 1 not established of 4 addresses" {
		t.Errorf("mixed reads %q", got)
	}
	notes := strings.Join(Texts(DescribeRoutes(mixed)), " ")
	for _, want := range []string{"192.0.2.1 contradicts its RPKI signature", "drop it", "Nobody has signed the route to 192.0.2.2", "ROA"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q: %s", want, notes)
		}
	}
	if RoutesLine(nil) != "" || DescribeRoutes(nil) != nil {
		t.Error("no routes were described")
	}
}
