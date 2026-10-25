package policy

import (
	"strings"
	"testing"
)

// The line counts each state, and the notes say what an invalid or unsigned
// route means and who can change it.
func TestTheRoutesLineCountsEachState(t *testing.T) {
	all := []RouteFacts{{Address: "192.0.2.1", State: "valid"}, {Address: "2001:db8::1", State: "valid"}}
	if got := RoutesLine(all, 0); got != "signed and valid for all 2 addresses" {
		t.Errorf("all valid reads %q", got)
	}
	if notes := DescribeRoutes(all, 0); len(notes) != 0 {
		t.Errorf("valid routes carry notes: %v", Texts(notes))
	}

	mixed := []RouteFacts{
		{Address: "192.0.2.1", State: "invalid"},
		{Address: "192.0.2.2", State: "not-found"},
		{Address: "192.0.2.3", State: "valid"},
		{Address: "192.0.2.4", Reason: "RIPEstat could not be reached"},
	}
	if got := RoutesLine(mixed, 0); got != "1 invalid, 1 not signed, 1 valid, 1 not established of 4 addresses" {
		t.Errorf("mixed reads %q", got)
	}
	notes := strings.Join(Texts(DescribeRoutes(mixed, 0)), " ")
	for _, want := range []string{"192.0.2.1 contradicts its RPKI signature", "drop it", "Nobody has signed the route to 192.0.2.2", "ROA"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q: %s", want, notes)
		}
	}
	if RoutesLine(nil, 0) != "" || DescribeRoutes(nil, 0) != nil {
		t.Error("no routes were described")
	}
}

// A route that was not established says why, and an address the bound left out
// is counted as not asked rather than folded into the ones that were.
//
// Found in a report on 2026-10-25: "8 not established of 8 addresses", of a
// name whose servers had twelve, and nothing anywhere said why the eight were
// not established.
func TestARouteNotEstablishedSaysWhyAndTheBoundIsSaid(t *testing.T) {
	rs := []RouteFacts{
		{Address: "192.0.2.1", Reason: "RIPEstat could not be reached"},
		{Address: "192.0.2.2", Reason: "RIPEstat could not be reached"},
		{Address: "192.0.2.3", State: "valid"},
	}
	if got, want := RoutesLine(rs, 4), "1 valid, 2 not established of 3 addresses, and 4 more not asked"; got != want {
		t.Errorf("the line reads %q, want %q", got, want)
	}
	notes := DescribeRoutes(rs, 4)
	want := map[string]bool{
		"Whether the routes to 192.0.2.1 and 192.0.2.2 are signed was not established: RIPEstat could not be reached.":                    false,
		"Routes were asked about for 3 addresses, the name's own first and then its name servers', and the other 4 were not asked about.": false,
	}
	for _, n := range notes {
		if _, ok := want[n.Text]; ok {
			want[n.Text] = n.Kind == KindUnsettled
		}
	}
	for text, said := range want {
		if !said {
			t.Errorf("the notes do not say, as not established, %q: %v", text, Texts(notes))
		}
	}
}
