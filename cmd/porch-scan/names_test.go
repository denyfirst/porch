package main

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/liveness"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// fromLogs is an inventory where only the certificate monitor was read.
//
// The older shape of this report, kept as a fixture because it is still a
// shape the report takes: a resolver that answers nothing leaves the logs as
// the only source there is.
func fromLogs(e ctsearch.Estate) inventory.Inventory {
	return inventory.Merge(e.Domain, e, dnsnames.Found{})
}

// The inventory prints what was found and, every time, what it cannot show.
//
// The second half is not decoration. A list of names read without it says "this
// is your estate", which is not what either source establishes for anybody: a
// host with no publicly trusted certificate never appears in a log, a wildcard
// covers hosts without naming them, and a domain's own records name only the
// hosts they have to. Somebody who hands this to a security team as an estate
// inventory, and is then shown more hosts by a port scan, loses the argument —
// and the difference between the methods was knowable in advance and is
// printed here.
func TestTheInventoryAlwaysSaysWhatItCannotShow(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test",
		Distinct: 4, Certificates: 4, Wildcards: 1, Foreign: 1,
		Names: []ctsearch.Name{
			{Name: "*.staging.example.test", Wildcard: true, FirstSeen: day(2025, 6, 1), LastSeen: day(2026, 9, 1)},
			{Name: "api.example.test", FirstSeen: day(2024, 5, 2), LastSeen: day(2026, 1, 20)},
			{Name: "old-portal.example.test", FirstSeen: day(2021, 3, 1), LastSeen: day(2022, 6, 1)},
			{Name: "www.example.test", FirstSeen: day(2023, 2, 14), LastSeen: day(2025, 11, 1)},
		},
	}), nil)
	out := buf.String()

	for _, want := range []string{
		"4 distinct names",
		"named 4 of them, across 4 certificates",
		"1, each covering hosts it does not name",
		"and 1 of the names\n    above is a wildcard.",
		"1 on the same certificates, under other domains, not listed",
		"old-portal.example.test",
		"from 2021-03-01, certificates to 2022-06-01",
		"What this does not show",
		"no name was invented",
		"no publicly trusted certificate never appears",
		"nothing above is graded",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the inventory does not say %q:\n%s", want, out)
		}
	}

	// Every name found is printed. A list that silently stopped short is the
	// one failure this mode cannot survive.
	for _, name := range []string{"*.staging.example.test", "api.example.test", "www.example.test"} {
		if !strings.Contains(out, name) {
			t.Errorf("%s was found and is not in the printed inventory:\n%s", name, out)
		}
	}

	// And it does not claim to have read a source nobody read. The records
	// were not asked here, and a report that quietly spoke for them would be
	// claiming coverage it never had (R4).
	if !strings.Contains(out, "Records      not read") {
		t.Errorf("a source that was never read is not reported as unread:\n%s", out)
	}
	if strings.Contains(out, "sender policy and its delegation have to name") {
		t.Errorf("the report describes the limits of a source it never read:\n%s", out)
	}
}

// A search that failed says so, and prints no inventory at all.
//
// The reassuring answer here is "none found", so a failure that printed an
// empty list under the usual heading would be the most comfortable wrong answer
// available (R4). The monitor answered 502 to every request on the day this was
// written, so this is the ordinary case rather than the rare one.
func TestAFailedSearchPrintsNoInventory(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test",
		Reason: "the certificate transparency monitor could not be reached",
	}), nil)
	out := buf.String()

	if !strings.Contains(out, "Not established: the certificate transparency monitor could not be reached") {
		t.Errorf("a failed search does not say so:\n%s", out)
	}
	if strings.Contains(out, "distinct name") {
		t.Errorf("a failed search printed a count:\n%s", out)
	}
}

// One source down is a short inventory, and it says which half is missing.
//
// This is the case the second source was added for: the monitor was unreachable
// for a whole day while this mode was being written, and the domain's own
// records answered throughout. The report that comes out of that day must be
// usable, and it must not read like a complete one — a list of three names with
// nothing saying the logs went unread is a list somebody presents as the
// estate.
func TestAnInventoryMissingASourceSaysWhichOne(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, inventory.Merge("example.test",
		ctsearch.Estate{Asked: true, Domain: "example.test",
			Reason: "the certificate transparency monitor could not be reached"},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
			{Name: "ns1.example.test", Sources: []dnsnames.Source{dnsnames.FromNS}},
		}}), nil)
	out := buf.String()

	if !strings.Contains(out, "Certificates Not established: the certificate transparency monitor could not be reached") {
		t.Errorf("the failed source is not named:\n%s", out)
	}
	if !strings.Contains(out, "named 2 of them, from MX and NS") {
		t.Errorf("the source that answered is not credited:\n%s", out)
	}
	for _, name := range []string{"mail.example.test", "ns1.example.test"} {
		if !strings.Contains(out, name) {
			t.Errorf("%s was established and is not printed:\n%s", name, out)
		}
	}

	// And the paragraph about what a certificate log misses is not printed
	// under a report where no log was read: it would be describing the limits
	// of something that did not happen.
	if strings.Contains(out, "no publicly trusted certificate never appears") {
		t.Errorf("the report describes a source it could not read:\n%s", out)
	}
	if !strings.Contains(out, "sender policy and its delegation have to name") {
		t.Errorf("the source that did answer has no limits printed:\n%s", out)
	}
}

// A source that failed is a non-zero exit, even where the other answered.
//
// The report says which half is missing, and a script does not read the
// report. A run that exited zero with the certificate half missing would hand
// a caller a list from two sources on the days both answered and from one on
// the days they did not, with nothing in the status to tell those apart (R4).
func TestASourceThatFailedIsANonZeroExit(t *testing.T) {
	answered := inventory.Merge("example.test",
		ctsearch.Estate{Asked: true, Domain: "example.test", Certificates: 1,
			Names: []ctsearch.Name{{Name: "www.example.test"}}},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
		}})
	if shortInventory(answered) {
		t.Error("an inventory both sources answered is reported as short")
	}

	for _, short := range []inventory.Inventory{
		inventory.Merge("example.test",
			ctsearch.Estate{Asked: true, Reason: "the certificate transparency monitor could not be reached"},
			dnsnames.Found{Asked: true, Names: []dnsnames.Name{
				{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
			}}),
		inventory.Merge("example.test",
			ctsearch.Estate{Asked: true, Certificates: 1,
				Names: []ctsearch.Name{{Name: "www.example.test"}}},
			dnsnames.Found{Asked: true, Reason: "the domain's own records could not be read"}),
	} {
		if !shortInventory(short) {
			t.Errorf("an inventory missing a source is reported as whole: %+v", short)
		}
	}
}

// One name is not "1 names".
func TestTheInventoryCountsInWords(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 1, Certificates: 1,
		Names: []ctsearch.Name{{Name: "example.test", LastSeen: day(2026, 1, 1)}},
	}), nil)
	out := buf.String()

	if !strings.Contains(out, "1 distinct name\n") {
		t.Errorf("the count reads wrongly:\n%s", out)
	}
	if !strings.Contains(out, "named 1 of them, across 1 certificate\n") {
		t.Errorf("the source line reads wrongly:\n%s", out)
	}
}

// A bare domain, and nothing else.
func TestTheInventoryTakesADomainAndNotAnAddress(t *testing.T) {
	for _, bad := range []string{"https://example.test", "example.test:443", "example.test/path"} {
		if err := namesTargets([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a domain to inventory", bad)
		}
	}
	if err := namesTargets([]string{"example.test", "sub.example.test"}); err != nil {
		t.Errorf("a bare domain was refused: %v", err)
	}
}

// The limits are printed under every inventory, including the tidy ones.
//
// A sabotage printed them only where a wildcard had hidden something, which
// every fixture here happened to have — so the paragraph vanished exactly from
// the reports most likely to be believed: the short, clean ones with no
// wildcard and nothing foreign, where a reader is most inclined to take the
// list for the estate.
func TestTheLimitsArePrintedEvenWhenNothingWasHidden(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 2, Certificates: 2,
		Names: []ctsearch.Name{
			{Name: "example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
			{Name: "www.example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
		},
	}), nil)
	out := buf.String()

	if !strings.Contains(out, "What this does not show") {
		t.Errorf("an inventory with nothing hidden printed no limits:\n%s", out)
	}
	if !strings.Contains(out, "nothing above is graded") {
		t.Errorf("an inventory with nothing hidden did not say it was ungraded:\n%s", out)
	}
	// And it does not claim a wildcard hid something when none did.
	if strings.Contains(out, "covers hosts without naming them") {
		t.Errorf("an inventory with no wildcards mentions one:\n%s", out)
	}
}

// The page says what the command line says, in the same words.
//
// Two renderers composing one claim from the same facts is how the two faces of
// a report drift apart, and this project has caught that happening before
// (R16). It matters more here than anywhere: the paragraph these share is the
// one that stops a list of names being read as an estate, so a page that
// quietly said something weaker would be the page somebody presents from.
//
// Only the claims about the certificate logs are compared. The page reads that
// one source; the command line reads two and asks each name what it is doing,
// so each says more than the other about what it did — and neither may say less
// about what they both did.
func TestBothFacesSayTheSameThingAboutWhatTheInventoryMisses(t *testing.T) {
	script, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page's script: %v", err)
	}
	page := string(script)

	// Both sources answered, so every sentence either face can carry is in
	// this one report. A fixture with one source would compare the shared
	// paragraph against a report that never printed half of it.
	var buf bytes.Buffer
	printNames(&buf, inventory.Merge("example.test",
		ctsearch.Estate{Asked: true, Domain: "example.test", Certificates: 1, Wildcards: 1,
			Names: []ctsearch.Name{{Name: "*.example.test", Wildcard: true, LastSeen: day(2026, 1, 1)}}},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
		}}), nil)
	printed := buf.String()

	// Each is a sentence both faces have to carry. Compared against what the
	// command line actually printed, so that a change to one and not the other
	// fails here rather than in front of a reader.
	for _, claim := range []string{
		"Nothing here was guessed: no name was invented and no list of names was tried.",
		"these names were published by whoever obtained a certificate for them",
		"no publicly trusted certificate never appears",
		"From the domain's own records, these are the hosts its mail, its sender policy and its delegation have to name.",
		"A host that takes no mail, sends none and answers for no zone is in none of them.",
		"nothing above is graded, because no",
		"document says which names an estate ought to have",
		"of the names above is a wildcard",
	} {
		if !strings.Contains(page, claim) {
			t.Errorf("the page does not say %q", claim)
		}
		// The command line wraps its lines, so its copy is compared with the
		// wrapping removed rather than by looking for the same run of bytes.
		if !strings.Contains(flatten(printed), claim) {
			t.Errorf("the command line does not say %q:\n%s", claim, printed)
		}
	}
}

// flatten folds the wrapped lines of a printed report into one, so a sentence
// broken across two lines can be compared with the same sentence in the page.
func flatten(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// The status is the first thing on the line, and each state says what it is.
//
// An operator reads the left edge and stops at what is not "live". That only
// works if the five states are distinguishable at a glance and each carries the
// evidence for itself: where the name points, or why nothing was established.
func TestWhatEachNameIsDoingIsTheFirstThingOnTheLine(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 5, Certificates: 5, Wildcards: 1,
		Names: []ctsearch.Name{
			{Name: "*.example.test", Wildcard: true, FirstSeen: day(2025, 6, 1), LastSeen: day(2026, 9, 1)},
			{Name: "api.example.test", LastSeen: day(2026, 9, 1)},
			{Name: "old.example.test", LastSeen: day(2022, 6, 1)},
			{Name: "inside.example.test", LastSeen: day(2026, 9, 1)},
			{Name: "moved.example.test", LastSeen: day(2026, 9, 1)},
		},
	}), []liveness.Name{
		{Name: "api.example.test", Status: liveness.Live,
			Addresses: addrsFor(t, "93.184.216.34"), Answered: []string{"443"}},
		{Name: "old.example.test", Status: liveness.Gone},
		{Name: "inside.example.test", Status: liveness.Internal,
			Addresses: addrsFor(t, "172.23.0.11")},
		{Name: "moved.example.test", Status: liveness.Dangling, Alias: "target.elsewhere.test"},
	})
	out := buf.String()

	for _, want := range []string{
		"What each name is doing now",
		"live      api.example.test    certificate 93.184.216.34, answering on 443",
		"gone      old.example.test    certificate does not resolve",
		"internal  inside.example.test certificate 172.23.0.11",
		"dangling  moved.example.test  certificate an alias to target.elsewhere.test, which does not resolve",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}

	// The one that cannot be measured says why, in this project's words rather
	// than a resolver's (I6).
	if !strings.Contains(out, "nothing here may dial it") {
		t.Errorf("an internal address is not explained:\n%s", out)
	}

	// A wildcard is not given a status, because nothing resolves one. It is
	// listed apart, with what it is.
	if !strings.Contains(out, "Wildcards, which name no host") {
		t.Errorf("the wildcards are not listed apart:\n%s", out)
	}
	if strings.Contains(out, "live      *.example.test") {
		t.Errorf("a wildcard was given a status:\n%s", out)
	}

	// And the limits are still underneath all of it, including what was sent
	// to establish the statuses above.
	if !strings.Contains(out, "What this does not show") {
		t.Errorf("the limits are missing:\n%s", out)
	}
	if !strings.Contains(flatten(out), "opening a connection to each address it gave") {
		t.Errorf("the report does not say what was sent:\n%s", out)
	}
}

// Every name says what named it, and a name only one source has is still a
// name.
//
// The column is what a reader sorts by. A host in a certificate and in the
// domain's own records is the well-kept case; a host in a certificate alone,
// with nothing in the zone pointing at it, is the one worth the time. Without
// the column those two are one line each and indistinguishable.
func TestEveryNameSaysWhatNamedIt(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, inventory.Merge("example.test",
		ctsearch.Estate{Asked: true, Domain: "example.test", Certificates: 3,
			Names: []ctsearch.Name{
				{Name: "api.example.test", LastSeen: day(2026, 9, 1)},
				{Name: "mail.example.test", LastSeen: day(2026, 9, 1)},
			}},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX, dnsnames.FromSPF}},
			{Name: "ns1.example.test", Sources: []dnsnames.Source{dnsnames.FromNS}},
		}}),
		[]liveness.Name{
			{Name: "api.example.test", Status: liveness.Live,
				Addresses: addrsFor(t, "93.184.216.34"), Answered: []string{"443"}},
			{Name: "mail.example.test", Status: liveness.Live,
				Addresses: addrsFor(t, "93.184.216.35"), Answered: []string{"25"}},
			{Name: "ns1.example.test", Status: liveness.Live,
				Addresses: addrsFor(t, "93.184.216.36"), Answered: []string{"443"}},
		})
	out := buf.String()

	for _, want := range []string{
		"3 distinct names",
		"named 2 of them, across 3 certificates",
		"named 2 of them, from MX, SPF and NS",
		"live      api.example.test  certificate          93.184.216.34",
		"live      mail.example.test certificate, MX, SPF 93.184.216.35",
		"live      ns1.example.test  NS                   93.184.216.36",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}

	// A name only the records carried has no log date, and none is invented
	// for it (R17).
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ns1.example.test") && strings.Contains(line, "certificates to") {
			t.Errorf("a name no certificate covered was given a certificate date: %q", line)
		}
	}
}

// Where nothing asked what the names are doing, the names are still drawn —
// and they still say what named them.
//
// Dropping them would lose the half of the report that was established in
// order to report the half that was not (R4). The heading says which question
// went unanswered.
func TestNamesSurviveAReportThatEstablishedNoStatus(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, inventory.Merge("example.test",
		ctsearch.Estate{Asked: true, Domain: "example.test", Certificates: 1,
			Names: []ctsearch.Name{{Name: "api.example.test", LastSeen: day(2026, 9, 1)}}},
		dnsnames.Found{Asked: true, Names: []dnsnames.Name{
			{Name: "mail.example.test", Sources: []dnsnames.Source{dnsnames.FromMX}},
		}}), nil)
	out := buf.String()

	if !strings.Contains(out, "api.example.test") || !strings.Contains(out, "mail.example.test") {
		t.Errorf("the names were dropped when nothing established their status:\n%s", out)
	}
	if !strings.Contains(out, "none of them asked what it is doing now") {
		t.Errorf("the report does not say the status went unasked:\n%s", out)
	}
	if !strings.Contains(out, "mail.example.test MX          in no logged certificate") {
		t.Errorf("a name is missing what named it:\n%s", out)
	}

	// Nothing was resolved and nothing was dialled, so the report does not say
	// that anything was.
	if strings.Contains(flatten(out), "opening a connection to each address it gave") {
		t.Errorf("a report that asked nothing says it opened connections:\n%s", out)
	}
}

// A wildcard is never put through a resolver.
//
// Nothing resolves `*.example.test`, so asking would produce a failure that
// reads as a fault in the estate — and the estate would then be reported as
// having a dead name that never existed.
func TestAWildcardIsNeverAskedAboutAsAName(t *testing.T) {
	got := fromLogs(ctsearch.Estate{Asked: true, Names: []ctsearch.Name{
		{Name: "*.example.test", Wildcard: true},
		{Name: "api.example.test"},
		{Name: "*.staging.example.test", Wildcard: true},
	}}).Hosts()
	if len(got) != 1 || got[0] != "api.example.test" {
		t.Errorf("the names asked about are %v", got)
	}
}

func addrsFor(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range list {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// A name says what it is doing and when the register last had it, on one line.
//
// The finding that matters most in an old estate needs both halves: a name
// whose newest certificate expired four years ago and which is still answering
// on 443 is a service nobody has looked at since. A reader given only the
// status would chase it as current; one given only the date would not know it
// was still running.
func TestANameSaysWhatItIsDoingAndWhenItWasLastCovered(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, fromLogs(ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 3, Certificates: 3,
		Names: []ctsearch.Name{
			{Name: "forgotten.example.test", FirstSeen: day(2019, 3, 1), LastSeen: day(2021, 6, 1)},
			{Name: "current.example.test", FirstSeen: day(2026, 1, 1), LastSeen: day(2026, 12, 1)},
			{Name: "undated.example.test"},
		},
	}), []liveness.Name{
		{Name: "forgotten.example.test", Status: liveness.Live,
			Addresses: addrsFor(t, "93.184.216.34"), Answered: []string{"443"}},
		{Name: "current.example.test", Status: liveness.Live,
			Addresses: addrsFor(t, "93.184.216.35"), Answered: []string{"443"}},
		{Name: "undated.example.test", Status: liveness.Gone},
	})
	out := buf.String()

	// The one worth finding: still answering, last covered five years ago.
	if !strings.Contains(out, "answering on 443; certificates to 2021-06-01") {
		t.Errorf("a live name does not say when it was last covered:\n%s", out)
	}
	if !strings.Contains(out, "answering on 443; certificates to 2026-12-01") {
		t.Errorf("a current name does not carry its date:\n%s", out)
	}

	// And where the register carried no dates, nothing is invented.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "undated.example.test") && strings.Contains(line, "certificates to") {
			t.Errorf("a name with no dates was given one: %q", line)
		}
	}
}
