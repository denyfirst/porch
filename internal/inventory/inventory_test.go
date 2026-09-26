package inventory

import (
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// One host named by two sources is one name carrying both.
//
// The merge is the point of this package and the deduplication is the half of
// it that is easy to get wrong in the direction nobody notices: a report that
// listed mail.example.test twice, once from a log and once from an MX record,
// would tell an operator they have two hosts where they have one, and every
// count in the report above it would be wrong by the same amount.
func TestOneHostNamedTwiceIsOneName(t *testing.T) {
	got := Merge("Example.TEST.", ctsearch.Estate{
		Asked: true, Domain: "example.test", Certificates: 3,
		Names: []ctsearch.Name{
			{Name: "mail.example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
			{Name: "www.example.test", FirstSeen: day(2023, 5, 1), LastSeen: day(2025, 5, 1)},
		},
	}, dnsnames.Found{
		Asked: true,
		Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX, dnsnames.FromSPF}},
			{Name: "ns1.example.test", Sources: []dnsnames.Source{dnsnames.FromNS}},
		},
	})

	if got.Domain != "example.test" {
		t.Errorf("the inventory is under %q", got.Domain)
	}
	if got.Distinct != 3 || len(got.Names) != 3 {
		t.Fatalf("merged to %d names: %+v", got.Distinct, got.Names)
	}

	want := map[string][]Source{
		"mail.example.test": {FromCertificate, FromMX, FromSPF},
		"www.example.test":  {FromCertificate},
		"ns1.example.test":  {FromNS},
	}
	for _, n := range got.Names {
		sources, known := want[n.Name]
		if !known {
			t.Errorf("%s is in the inventory and should not be", n.Name)
			continue
		}
		if len(n.Sources) != len(sources) {
			t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
			continue
		}
		for i, s := range sources {
			// The order is fixed rather than the order they were read, so that
			// two runs of the same inventory read the same.
			if n.Sources[i] != s {
				t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}

	// And each source says how much of the list it is answerable for. The one
	// named by an MX and a sender policy is one name the records named, not
	// two.
	if got.Logs.Named != 2 {
		t.Errorf("the logs are credited with %d names, want 2", got.Logs.Named)
	}
	if got.Records.Named != 2 {
		t.Errorf("the records are credited with %d names, want 2", got.Records.Named)
	}
}

// A merge does not narrow what one source established.
//
// The dates come from the logs and nothing else has them, so a name the
// records also carried must keep them. A merge that dropped them would take
// the finding that matters most in an old estate — still answering, last
// covered years ago — and quietly remove half of it.
func TestTheWindowSurvivesTheMerge(t *testing.T) {
	got := Merge("example.test", ctsearch.Estate{
		Asked: true, Domain: "example.test",
		Names: []ctsearch.Name{
			{Name: "mail.example.test", FirstSeen: day(2019, 3, 1), LastSeen: day(2021, 6, 1)},
		},
	}, dnsnames.Found{
		Asked: true,
		Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
			{Name: "ns1.example.test", Sources: []dnsnames.Source{dnsnames.FromNS}},
		},
	})

	for _, n := range got.Names {
		switch n.Name {
		case "mail.example.test":
			if !n.FirstSeen.Equal(day(2019, 3, 1)) || !n.LastSeen.Equal(day(2021, 6, 1)) {
				t.Errorf("the window was lost in the merge: %+v", n)
			}
		case "ns1.example.test":
			// And nothing is invented for a name no log ever covered.
			if !n.FirstSeen.IsZero() || !n.LastSeen.IsZero() {
				t.Errorf("a name only the records carried was given log dates: %+v", n)
			}
		}
	}
}

// A source that failed is not a source that found nothing.
//
// Nothing found is the reassuring answer here, so the two must never render
// the same (R4). An inventory where both sources failed establishes nothing at
// all; one where a source answered is an inventory, and the reading says which
// half of it is missing.
func TestASourceThatFailedIsNotAnEmptyEstate(t *testing.T) {
	both := Merge("example.test",
		ctsearch.Estate{Asked: true, Reason: "the certificate transparency monitor could not be reached"},
		dnsnames.Found{Asked: true, Reason: "the domain's own records could not be read"})
	if both.Established() {
		t.Error("an inventory neither source answered reports that something was established")
	}

	half := Merge("example.test",
		ctsearch.Estate{Asked: true, Reason: "the certificate transparency monitor could not be reached"},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
		}})
	if !half.Established() {
		t.Error("an inventory one source answered reports that nothing was established")
	}
	if half.Logs.Established() {
		t.Error("a monitor that could not be reached is reported as having answered")
	}
	if !half.Records.Established() {
		t.Error("the records answered and are reported as not having done")
	}
	if len(half.Names) != 1 {
		t.Errorf("the half that was established was lost: %+v", half.Names)
	}

	// A source nobody read is not a source that failed either, and saying so
	// is what stops a report claiming coverage it never had.
	unasked := Merge("example.test",
		ctsearch.Estate{Asked: true, Names: []ctsearch.Name{{Name: "www.example.test"}}},
		dnsnames.Found{})
	if unasked.Records.Asked || unasked.Records.Reason != "" {
		t.Errorf("a source that was never read is reported as %+v", unasked.Records)
	}
}

// A wildcard is never a name to resolve.
//
// Nothing resolves `*.example.test`, so asking would produce a failure that
// reads as a fault in the estate — and the estate would then be reported as
// having a dead host that never existed.
func TestAWildcardIsNeverAHostToResolve(t *testing.T) {
	got := Merge("example.test", ctsearch.Estate{
		Asked: true,
		Names: []ctsearch.Name{
			{Name: "*.example.test", Wildcard: true},
			{Name: "api.example.test"},
			{Name: "*.staging.example.test", Wildcard: true},
		},
	}, dnsnames.Found{Asked: true, Names: []dnsnames.Name{
		{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
	}})

	hosts := got.Hosts()
	if len(hosts) != 2 || hosts[0] != "api.example.test" || hosts[1] != "mail.example.test" {
		t.Errorf("the names to ask about are %v", hosts)
	}
	if got.Wildcards != 2 {
		t.Errorf("%d wildcards were counted, want 2", got.Wildcards)
	}
}

// A record source this does not know is carried, not dropped.
//
// The short labels here are a second spelling of the ones in the reader, and a
// record type added there and not here would otherwise take its names out of
// the inventory silently — a name missing from a list somebody acts on, with
// nothing anywhere saying it was ever found.
func TestARecordSourceWithNoShortLabelIsStillCarried(t *testing.T) {
	got := Merge("example.test", ctsearch.Estate{Asked: true}, dnsnames.Found{
		Asked: true,
		Names: []dnsnames.Name{
			{Name: "new.example.test", Sources: []dnsnames.Source{dnsnames.Source("SRV record")}},
		},
	})

	if len(got.Names) != 1 {
		t.Fatalf("a name from an unknown source was dropped: %+v", got.Names)
	}
	if len(got.Names[0].Sources) != 1 || got.Names[0].Sources[0] != Source("SRV record") {
		t.Errorf("the unknown source came through as %v", got.Names[0].Sources)
	}
	if got.Records.Named != 1 {
		t.Errorf("the records are credited with %d names, want 1", got.Records.Named)
	}

	// And the three the reader has are known here, so the fallback above stays
	// the exception rather than the way this works.
	for _, s := range []dnsnames.Source{dnsnames.FromMX, dnsnames.FromSPF, dnsnames.FromNS} {
		if short := sourceOf(s); short != FromMX && short != FromSPF && short != FromNS {
			t.Errorf("%q has no short label here and came through as %q", s, short)
		}
	}
}

// What each source dropped is kept, per source, and not added together into
// one number nobody can read.
func TestWhatEachSourceDroppedIsKeptApart(t *testing.T) {
	got := Merge("example.test",
		ctsearch.Estate{Asked: true, Foreign: 4, Certificates: 2},
		dnsnames.Found{Asked: true, Foreign: 1})

	if got.Logs.Foreign != 4 || got.Records.Foreign != 1 {
		t.Errorf("the dropped names are %d from the logs and %d from the records",
			got.Logs.Foreign, got.Records.Foreign)
	}
	if got.Certificates != 2 {
		t.Errorf("%d certificates were reported read, want 2", got.Certificates)
	}
}

// Two spellings of one host are one host.
//
// A monitor writes a trailing dot or a capital where a resolver does not, and
// a merge comparing the two as text would list the same host twice with one
// source each — which reads as two hosts, each with less evidence behind it
// than the one that is really there.
func TestTwoSpellingsOfOneHostAreOneHost(t *testing.T) {
	got := Merge("example.test", ctsearch.Estate{
		Asked: true,
		Names: []ctsearch.Name{{Name: "Mail.Example.Test."}},
	}, dnsnames.Found{
		Asked: true,
		Names: []dnsnames.Name{{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}}},
	})

	if len(got.Names) != 1 {
		t.Fatalf("one host was listed %d times: %+v", len(got.Names), got.Names)
	}
	if got.Names[0].Name != "mail.example.test" {
		t.Errorf("the host is listed as %q", got.Names[0].Name)
	}
	if len(got.Names[0].Sources) != 2 {
		t.Errorf("the merged host was named by %v, want both sources", got.Names[0].Sources)
	}
}
