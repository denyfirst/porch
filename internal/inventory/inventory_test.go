package inventory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/certnames"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/knownnames"
	"github.com/denyfirst/porch/internal/liveness"
	"github.com/denyfirst/porch/internal/passivedns"
	"github.com/denyfirst/porch/internal/ptrnames"
	"github.com/denyfirst/porch/internal/zonenames"
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
	got := merge("Example.TEST.", ctsearch.Estate{
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
	got := merge("example.test", ctsearch.Estate{
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
	both := merge("example.test",
		ctsearch.Estate{Asked: true, Reason: "the certificate transparency monitor could not be reached"},
		dnsnames.Found{Asked: true, Reason: "the domain's own records could not be read"})
	if both.Established() {
		t.Error("an inventory neither source answered reports that something was established")
	}

	half := merge("example.test",
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
	unasked := merge("example.test",
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
	got := merge("example.test", ctsearch.Estate{
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
	got := merge("example.test", ctsearch.Estate{Asked: true}, dnsnames.Found{
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
	got := merge("example.test",
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
	got := merge("example.test", ctsearch.Estate{
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

// What each name is doing goes beside the name, and a name nothing answered
// for keeps its row.
//
// The alternative — a list of names and a parallel list of answers — is how a
// name leaves a report without being mentioned. The probe bounds how many
// names it will reach and gives up on the rest when the time runs out, so a
// renderer walking the answers prints a shorter estate than the one that was
// found, with nothing saying so (R4).
func TestWhatEachNameIsDoingGoesBesideTheName(t *testing.T) {
	got := merge("example.test", ctsearch.Estate{
		Asked: true,
		Names: []ctsearch.Name{
			{Name: "answered.example.test"},
			{Name: "unreached.example.test"},
		},
	}, dnsnames.Found{}).WithLiveness([]liveness.Name{
		{Name: "answered.example.test", Status: liveness.Live, Answered: []string{"443"}},
	})

	if !got.Probed {
		t.Error("the names were asked and the inventory does not say so")
	}
	if len(got.Names) != 2 {
		t.Fatalf("the inventory holds %d names: %+v", len(got.Names), got.Names)
	}

	for _, n := range got.Names {
		switch n.Name {
		case "answered.example.test":
			if n.Now == nil || n.Now.Status != liveness.Live {
				t.Errorf("the name that answered came back as %+v", n.Now)
			}
		case "unreached.example.test":
			if n.Now != nil {
				t.Errorf("a name nothing reached was given a state: %+v", n.Now)
			}
		}
	}
}

// An answer is matched to its name however either was spelled.
//
// The probe is given the folded names this package produced, so this is belt
// and braces — but a state attached to the wrong name is worse than no state,
// and the cost of being sure is one call.
func TestAnAnswerIsMatchedToItsNameWhateverTheSpelling(t *testing.T) {
	got := merge("example.test", ctsearch.Estate{
		Asked: true,
		Names: []ctsearch.Name{{Name: "mail.example.test"}},
	}, dnsnames.Found{}).WithLiveness([]liveness.Name{
		{Name: "Mail.Example.Test.", Status: liveness.Gone},
	})

	if got.Names[0].Now == nil || got.Names[0].Now.Status != liveness.Gone {
		t.Errorf("the answer was not matched to the name: %+v", got.Names[0])
	}
}

// Asking is what makes a report a probed one, not getting answers back.
//
// An estate where every name is gone answers nothing, and a report that read
// that as "nobody asked" would leave the operator with the one thing they came
// for unsaid.
func TestAnEstateWhereNothingAnswersWasStillAsked(t *testing.T) {
	got := merge("example.test", ctsearch.Estate{
		Asked: true,
		Names: []ctsearch.Name{{Name: "gone.example.test"}},
	}, dnsnames.Found{}).WithLiveness(nil)

	if !got.Probed {
		t.Error("an estate that answered nothing is reported as never having been asked")
	}
}

// merge is Merge with the two sources most fixtures here use.
//
// A helper so that adding a source does not rewrite every fixture in the file:
// what each test is about is the merging, and a test that has to name three
// sources to say nothing about two of them reads as though it did.
func merge(domain string, e ctsearch.Estate, d dnsnames.Found) Inventory {
	return Merge(domain, Sources{Logs: e, Records: d})
}

// A register's names join the list, and say that a register named them.
//
// This is the source that sees behind a wildcard, so most of what it
// contributes is names no other source has. Reporting them without saying
// where they came from would put an observation and a publication on the same
// line with nothing to tell them apart — and they are not worth the same: a
// name a register saw may never have existed.
func TestWhatARegisterObservedIsItsOwnSource(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Certificates: 1, Names: []ctsearch.Name{
			{Name: "www.example.test"},
			{Name: "*.example.test", Wildcard: true},
		}},
		Records: dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
		}},
		Passive: passivedns.Found{Asked: true, Register: "securitytrails", Names: []string{
			"bitrix.example.test",
			"www.example.test",
		}},
	})

	if got.Distinct != 4 {
		t.Fatalf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}

	want := map[string][]Source{
		"*.example.test":      {FromCertificate},
		"bitrix.example.test": {FromPassive},
		"mail.example.test":   {FromMX},
		"www.example.test":    {FromCertificate, FromPassive},
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
		for i := range sources {
			if n.Sources[i] != sources[i] {
				t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}

	// Each source is credited with what it named, and a name two of them
	// named is credited to both.
	if got.Logs.Named != 2 || got.Records.Named != 1 || got.Passive.Named != 2 {
		t.Errorf("the sources are credited with logs=%d records=%d passive=%d",
			got.Logs.Named, got.Records.Named, got.Passive.Named)
	}
	if !got.Passive.Established() {
		t.Error("a register that answered is not reported as having answered")
	}
}

// A register nobody configured is not a register that found nothing.
//
// The zero value is "not read", and it has to render as that: an estate behind
// a wildcard with no register asked has hosts nothing here looked for, and a
// report that let that read as "none found" would be the comfortable wrong
// answer (R4).
func TestARegisterThatWasNeverAskedIsNotAnEmptyRegister(t *testing.T) {
	unasked := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{{Name: "www.example.test"}}},
	})
	if unasked.Passive.Asked || unasked.Passive.Reason != "" {
		t.Errorf("a register nobody asked is reported as %+v", unasked.Passive)
	}
	if !unasked.Established() {
		t.Error("an inventory with one source answering established nothing")
	}

	failed := Merge("example.test", Sources{
		Passive: passivedns.Found{Asked: true, Reason: "the passive register is rate limiting this search"},
	})
	if failed.Established() {
		t.Error("an inventory whose only source failed reports that something was established")
	}

	// And a register alone is an inventory: an installation with no monitor
	// and a register still has names to show.
	alone := Merge("example.test", Sources{
		Passive: passivedns.Found{Asked: true, Names: []string{"bitrix.example.test"}},
	})
	if !alone.Established() || len(alone.Names) != 1 {
		t.Errorf("a register on its own established %+v", alone)
	}
}

// What a register could not finish is carried into the inventory.
func TestARegisterThatWasCutSaysSoInTheInventory(t *testing.T) {
	got := Merge("example.test", Sources{
		Passive: passivedns.Found{Asked: true, Truncated: true, Foreign: 3,
			Names: []string{"one.example.test"}},
	})
	if !got.Truncated {
		t.Error("a register that was cut produced an inventory that says it is whole")
	}
	if got.Passive.Foreign != 3 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 3", got.Passive.Foreign)
	}
}

// What a host presented is its own source, and a wildcard on a certificate is
// still a wildcard.
//
// This is the only source that is the estate rather than a record of it, and
// the only one that finds what a private authority issued. A wildcard it hands
// over must not become a name to resolve: nothing resolves `*.example.test`,
// and the failure would read as a dead host that never existed.
func TestWhatAHostPresentedIsItsOwnSource(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Certificates: 1, Names: []ctsearch.Name{
			{Name: "www.example.test"},
		}},
		Presented: certnames.Found{Asked: true, Hosts: 1, Answered: 1,
			Names:     []string{"www.example.test", "internal-billing.example.test"},
			Wildcards: []string{"*.internal.example.test"},
		},
	})

	want := map[string][]Source{
		"www.example.test":              {FromCertificate, FromHost},
		"internal-billing.example.test": {FromHost},
		"*.internal.example.test":       {FromHost},
	}
	if len(got.Names) != len(want) {
		t.Fatalf("the merged inventory holds %+v", got.Names)
	}
	for _, n := range got.Names {
		sources, known := want[n.Name]
		if !known || len(n.Sources) != len(sources) {
			t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
			continue
		}
		for i := range sources {
			if n.Sources[i] != sources[i] {
				t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}

	if got.Wildcards != 1 {
		t.Errorf("%d wildcards were counted, want 1", got.Wildcards)
	}
	for _, name := range got.Hosts() {
		if strings.HasPrefix(name, "*") {
			t.Errorf("a wildcard is in the names to resolve: %v", got.Hosts())
		}
	}
	if got.Presented.Named != 3 {
		t.Errorf("the hosts are credited with %d names, want 3", got.Presented.Named)
	}
}

// The names nothing has asked about yet are the ones a late source brought in.
//
// A report where the newest names are the ones with nothing beside them would
// be answering the easy half (R4).
func TestUnaskedAreTheNamesNothingHasAskedAboutYet(t *testing.T) {
	inv := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{
			{Name: "old.example.test"},
			{Name: "*.example.test", Wildcard: true},
		}},
		Presented: certnames.Found{Asked: true, Names: []string{"new.example.test"}},
	})

	got := inv.Unasked([]liveness.Name{{Name: "old.example.test", Status: liveness.Live}})
	if len(got) != 1 || got[0] != "new.example.test" {
		t.Errorf("the names still to ask about are %v", got)
	}
}

// What an address answers to is its own source.
//
// The only one that starts from an address rather than from a name, so it
// finds a machine that is in no certificate, in no record the domain
// publishes, and in no register — and a reader has to be able to see that
// that is where the name came from.
func TestWhatAnAddressAnsweredToIsItsOwnSource(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Certificates: 1, Names: []ctsearch.Name{
			{Name: "www.example.test"},
		}},
		Reverse: ptrnames.Found{Asked: true, Addresses: 256, Answered: 2,
			Names: []string{"build.example.test", "www.example.test"}},
	})

	want := map[string][]Source{
		"www.example.test":   {FromCertificate, FromPTR},
		"build.example.test": {FromPTR},
	}
	if len(got.Names) != len(want) {
		t.Fatalf("the merged inventory holds %+v", got.Names)
	}
	for _, n := range got.Names {
		sources, known := want[n.Name]
		if !known || len(n.Sources) != len(sources) {
			t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
			continue
		}
		for i := range sources {
			if n.Sources[i] != sources[i] {
				t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}
	if got.Reverse.Named != 2 {
		t.Errorf("the reverse walk is credited with %d names, want 2", got.Reverse.Named)
	}
	if !got.Reverse.Established() {
		t.Error("a walk that answered is not reported as having answered")
	}

	// A walk nobody asked for is not a walk that found nothing.
	none := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{{Name: "www.example.test"}}},
	})
	if none.Reverse.Asked || none.Reverse.Reason != "" {
		t.Errorf("a walk nobody asked for is reported as %+v", none.Reverse)
	}
}

// A name no certificate covered carries no date, in the JSON as well as in
// the report.
//
// `omitempty` does nothing for a time.Time, so both fields went out as
// "0001-01-01T00:00:00Z" and every reader had to know that one date means no
// date. The page did not: it printed "certificates to 0001-01-01" beside a
// host found by a reverse record, which is a date invented for a fact nobody
// has (R17).
func TestANameWithNoDateCarriesNoneInTheJSON(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{
			{Name: "dated.example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
		}},
		Reverse: ptrnames.Found{Asked: true, Names: []string{"undated.example.test"}},
	})

	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling the inventory: %v", err)
	}
	out := string(body)

	if strings.Contains(out, "0001-01-01") {
		t.Errorf("a name with no date carries the zero time:\n%s", out)
	}
	for _, want := range []string{
		`"name":"undated.example.test"`,
		`"firstSeen":"2024-01-01T00:00:00Z"`,
		`"lastSeen":"2026-01-01T00:00:00Z"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the JSON does not carry %s:\n%s", want, out)
		}
	}

	// And it decodes back to the same thing, so a kept report reads as it was
	// written.
	var back Inventory
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	if len(back.Names) != 2 {
		t.Fatalf("the inventory came back as %+v", back.Names)
	}
	for _, n := range back.Names {
		if n.Name == "undated.example.test" && !n.LastSeen.IsZero() {
			t.Errorf("the undated name came back dated %s", n.LastSeen)
		}
		if n.Name == "dated.example.test" && n.LastSeen.IsZero() {
			t.Errorf("the dated name came back without its date")
		}
	}
}

// What a zone handed over is its own source, and it is the one that is
// complete.
//
// Every other source is a sample. This one is the zone, so a name in it needs
// no corroboration — and a name only it has is the ordinary case rather than
// the surprising one, because most names in a zone were never certified,
// never resolved from outside, and never had to appear in a record anybody
// else reads.
func TestWhatAZoneHandedOverIsItsOwnSource(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Certificates: 1, Names: []ctsearch.Name{
			{Name: "www.example.test"},
		}},
		Zone: zonenames.Found{Asked: true, Servers: 2, Refused: 1, From: "ns2.example.test",
			Names: []string{"www.example.test", "bitrix.example.test", "staging.example.test"}},
	})

	want := map[string][]Source{
		"www.example.test":     {FromZone, FromCertificate},
		"bitrix.example.test":  {FromZone},
		"staging.example.test": {FromZone},
	}
	if len(got.Names) != len(want) {
		t.Fatalf("the merged inventory holds %+v", got.Names)
	}
	for _, n := range got.Names {
		sources, known := want[n.Name]
		if !known || len(n.Sources) != len(sources) {
			t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
			continue
		}
		for i := range sources {
			if n.Sources[i] != sources[i] {
				t.Errorf("%s was named by %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}
	if got.Zone.Named != 3 {
		t.Errorf("the zone is credited with %d names, want 3", got.Zone.Named)
	}

	// The zone comes first in the column, because it is the source that needed
	// no inference: a reader running an eye down it should meet the strongest
	// evidence first.
	if order[0] != FromZone {
		t.Errorf("the sources are listed %v", order)
	}

	// A zone nobody asked for is not a zone that refused.
	none := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{{Name: "www.example.test"}}},
	})
	if none.Zone.Asked || none.Zone.Reason != "" {
		t.Errorf("a zone nobody asked for is reported as %+v", none.Zone)
	}

	// And a zone that refused established something: it was asked, and the
	// answer was no.
	refused := Merge("example.test", Sources{
		Zone: zonenames.Found{Asked: true, Servers: 2, Refused: 2},
	})
	if !refused.Zone.Established() || refused.Zone.Named != 0 {
		t.Errorf("a zone that refused came back as %+v", refused.Zone)
	}
}

// Every source on the report is a Reading, and every Reading is on the list.
//
// Taken from the struct, because three separate places had each decided for
// themselves how many sources there are and all three were wrong by the time
// the sixth arrived: the exit status looked at two, the page's failure
// paragraph printed three, and only Established named all six. A seventh
// source is a seventh field, and it fails here until the list has it — which
// is one failing test rather than three silent shortenings (R4).
func TestEverySourceIsAReadingAndEveryReadingIsListed(t *testing.T) {
	report := reflect.TypeOf(Inventory{})
	reading := reflect.TypeOf(Reading{})

	var fields []string
	for i := range report.NumField() {
		if report.Field(i).Type == reading {
			fields = append(fields, report.Field(i).Name)
		}
	}
	if len(fields) < 6 {
		t.Fatalf("the inventory carries %d sources: %v", len(fields), fields)
	}

	if got := len(Inventory{}.Readings()); got != len(fields) {
		t.Fatalf("Readings returns %d of the %d sources on the report: %v", got, len(fields), fields)
	}

	// And each one is the field it claims to be, rather than one field listed
	// twice. Set one source at a time and check exactly one reading changes.
	for _, name := range fields {
		var inv Inventory
		reflect.ValueOf(&inv).Elem().FieldByName(name).
			Set(reflect.ValueOf(Reading{Asked: true, Reason: name}))

		var seen int
		for _, r := range inv.Readings() {
			if r.Reason == name {
				seen++
			}
		}
		if seen != 1 {
			t.Errorf("%s appears %d times in Readings, so a source is listed twice or not at all",
				name, seen)
		}
		if failures := inv.Failures(); len(failures) != 1 || failures[0] != name {
			t.Errorf("a failed %s reads as %v", name, failures)
		}
	}
}

// A name whoever asked already had is a source of its own, and says so.
//
// The point of the source is the row a reader goes looking for: a host they
// listed that nothing public named. So it is labelled like every other source
// rather than folded into the list, and it is labelled last, because the
// column leads with evidence and this is a claim — the operator saying the
// host is theirs is not the same kind of statement as a certificate log
// holding a certificate for it.
func TestAListSomebodyGaveIsItsOwnSource(t *testing.T) {
	got := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{
			{Name: "www.example.test"},
			// One the list does not carry, so that a source crediting itself
			// with every name in the inventory rather than with its own is a
			// failure here. Without it every count in this test is the same
			// number and any of them could be wrong unseen.
			{Name: "shop.example.test"},
		}},
		Known: knownnames.Found{Asked: true, Names: []string{
			"www.example.test",    // one the logs had too
			"bitrix.example.test", // and one nothing public holds
		}},
	})

	if got.Distinct != 3 {
		t.Fatalf("the merged inventory holds %d names: %+v", got.Distinct, got.Names)
	}
	if got.Known.Named != 2 {
		t.Errorf("the list is credited with %d names, want 2", got.Known.Named)
	}
	if got.Logs.Named != 2 {
		t.Errorf("the logs are credited with %d names, want 2", got.Logs.Named)
	}

	by := map[string][]Source{}
	for _, n := range got.Names {
		by[n.Name] = n.Sources
	}
	if want := []Source{FromCertificate, FromOperator}; !sameSources(by["www.example.test"], want) {
		t.Errorf("a name both had is named by %v, want %v", by["www.example.test"], want)
	}
	if want := []Source{FromOperator}; !sameSources(by["bitrix.example.test"], want) {
		t.Errorf("a name only the operator had is named by %v, want %v", by["bitrix.example.test"], want)
	}

	// The claim is last in the column. A reader running an eye down it meets
	// the evidence first, and "operator" alone is the row worth stopping at.
	if order[len(order)-1] != FromOperator {
		t.Errorf("the sources are listed %v", order)
	}

	// And a list nobody gave is not an empty list.
	none := Merge("example.test", Sources{
		Logs: ctsearch.Estate{Asked: true, Names: []ctsearch.Name{{Name: "www.example.test"}}},
	})
	if none.Known.Asked || none.Known.Reason != "" {
		t.Errorf("a list nobody gave is reported as %+v", none.Known)
	}
}

func sameSources(got, want []Source) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
