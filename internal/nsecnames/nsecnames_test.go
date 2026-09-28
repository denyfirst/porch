package nsecnames

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// chain answers NSEC queries from a table, and records what it was asked.
type chain struct {
	next  map[string]string
	fails map[string]bool
	asked []string
}

func (c *chain) LookupNSEC(_ context.Context, name string) (dnsclient.ZoneAnswer, error) {
	c.asked = append(c.asked, name)
	if c.fails[name] {
		return dnsclient.ZoneAnswer{}, errors.New("the resolver did not answer")
	}
	to, ok := c.next[name]
	if !ok {
		return dnsclient.ZoneAnswer{}, nil
	}
	return dnsclient.ZoneAnswer{NSEC: []dnsclient.NSEC{{Next: to}}}, nil
}

// A zone signed the plain way lists itself, and the walk stops when it comes
// round to the apex.
//
// Nothing here is guessed. Every name is read out of a record the zone
// publishes and serves to anybody who asks, which is the property RFC 5155
// exists to remove and the one the DNS check already reports.
func TestASignedZoneListsItself(t *testing.T) {
	z := &chain{next: map[string]string{
		"example.test":     "api.example.test",
		"api.example.test": "mail.example.test",
		// A wildcard is in the ordering like any other name, and nothing
		// resolves one.
		"mail.example.test": "*.example.test",
		"*.example.test":    "vpn.example.test",
		"vpn.example.test":  "example.test",
	}}

	got := (&Reader{Resolver: z}).Under(context.Background(), "example.test")

	if !got.Asked || got.Reason != "" {
		t.Fatalf("a zone that answered came back as %+v", got)
	}
	if got.Truncated {
		t.Error("a walk that came round to the apex says it was cut")
	}

	want := []string{"api.example.test", "mail.example.test", "vpn.example.test"}
	if len(got.Names) != len(want) {
		t.Fatalf("the walk came back as %v", got.Names)
	}
	for i := range want {
		if got.Names[i] != want[i] {
			t.Errorf("name %d is %q, want %q", i, got.Names[i], want[i])
		}
	}
	if got.Wildcards != 1 {
		t.Errorf("%d wildcards were counted, want 1", got.Wildcards)
	}

	// The apex is where the walk starts, and it is not one of the names it
	// found: it is the domain that was asked about.
	for _, n := range got.Names {
		if n == "example.test" {
			t.Error("the apex is listed as something the walk discovered")
		}
	}
}

// A zone with no plain absence proofs says so, and says it as a reason rather
// than as an empty list.
//
// The commonest answer this source gives. An unsigned zone publishes none and
// a zone using NSEC3 publishes the hashed kind, and neither is a failure — but
// neither is an estate with no names in it either, and a caller must be able
// to tell all three apart (R4).
func TestAZoneWithNoPlainProofsSaysSo(t *testing.T) {
	got := (&Reader{Resolver: &chain{}}).Under(context.Background(), "example.test")

	if !got.Asked {
		t.Error("a walk that was tried reads as one that was not")
	}
	if got.Reason == "" {
		t.Fatalf("a zone with nothing to follow came back as %+v", got)
	}
	if len(got.Names) != 0 {
		t.Errorf("a zone with nothing to follow produced %v", got.Names)
	}

	// And a resolver that would not answer is a different nothing again.
	z := &chain{fails: map[string]bool{"example.test": true}}
	unread := (&Reader{Resolver: z}).Under(context.Background(), "example.test")
	if unread.Reason == "" || unread.Reason == got.Reason {
		t.Errorf("a resolver that failed reads the same as a zone with nothing: %+v", unread)
	}
}

// A chain that does not come round is stopped, and says it was cut.
//
// Three shapes and all of them are somebody else's zone deciding how long this
// runs: a chain that points back at a name already passed, one that never
// reaches the apex, and one that stops answering part way. Each produces the
// names that were read and none of them reads as a whole zone (R4).
func TestAChainThatDoesNotComeRoundIsCut(t *testing.T) {
	// A loop: two names pointing at each other.
	loop := (&Reader{Resolver: &chain{next: map[string]string{
		"example.test":   "a.example.test",
		"a.example.test": "b.example.test",
		"b.example.test": "a.example.test",
	}}}).Under(context.Background(), "example.test")

	if !loop.Truncated {
		t.Error("a chain that loops reads as a whole zone")
	}
	if len(loop.Names) != 2 {
		t.Errorf("a chain that loops produced %v", loop.Names)
	}

	// A chain that stops answering. What arrived is kept, and it is cut.
	stops := (&Reader{Resolver: &chain{
		next:  map[string]string{"example.test": "a.example.test"},
		fails: map[string]bool{"a.example.test": true},
	}}).Under(context.Background(), "example.test")

	if !stops.Truncated {
		t.Error("a chain that stopped answering reads as a whole zone")
	}
	if len(stops.Names) != 1 {
		t.Errorf("a chain that stopped produced %v", stops.Names)
	}
}

// A chain that leaves the domain stops there, and the name it left for is
// counted rather than listed.
//
// Following it would put another estate's names in a report about this one.
func TestAChainThatLeavesTheDomainStops(t *testing.T) {
	got := (&Reader{Resolver: &chain{next: map[string]string{
		"example.test":   "a.example.test",
		"a.example.test": "somewhere.else.test",
	}}}).Under(context.Background(), "example.test")

	if got.Foreign != 1 {
		t.Errorf("%d names were counted as another estate's, want 1", got.Foreign)
	}
	for _, n := range got.Names {
		if n == "somewhere.else.test" {
			t.Error("a name outside the domain was listed")
		}
	}
}

// A zone that never comes round is stopped, and the one bound stops both the
// names and the questions.
//
// Two bounds were written here first — one on names, one on questions —
// against a zone answering every query with a name already seen. The second
// was unreachable: every turn either adds a name nobody has seen, which counts
// against the first, or meets one that has and returns. A sabotage removing it
// changed nothing any test could see, which is what a bound that cannot fire
// looks like, so it is gone. This holds the property it was supposed to: the
// questions asked cannot exceed the names allowed.
func TestAZoneThatNeverComesRoundIsStopped(t *testing.T) {
	// Every name points at one nobody has seen: a zone with no end.
	z := &endless{}
	got := (&Reader{Resolver: z}).Under(context.Background(), "example.test")

	if !got.Truncated {
		t.Error("a zone that never comes round reads as a whole one")
	}
	if len(got.Names) > maxNames {
		t.Errorf("the walk kept %d names and the bound is %d", len(got.Names), maxNames)
	}
	if len(z.asked) > maxNames+1 {
		t.Errorf("the walk asked %d questions, which is past what %d names can cost",
			len(z.asked), maxNames)
	}
}

// endless answers every query with a name nobody has seen before.
type endless struct{ asked []string }

func (e *endless) LookupNSEC(_ context.Context, name string) (dnsclient.ZoneAnswer, error) {
	e.asked = append(e.asked, name)
	return dnsclient.ZoneAnswer{NSEC: []dnsclient.NSEC{
		{Next: fmt.Sprintf("h%d.example.test", len(e.asked))},
	}}, nil
}
