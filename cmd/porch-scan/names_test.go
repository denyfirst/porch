package main

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/liveness"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// The inventory prints what was found and, every time, what it cannot show.
//
// The second half is not decoration. A list of names read without it says "this
// is your estate", which is not what a certificate log establishes for anybody:
// a host with no publicly trusted certificate never appears, and a wildcard
// covers hosts without naming them. Somebody who hands this to a security team
// as an estate inventory, and is then shown more hosts by a port scan, loses
// the argument — and the difference between the two methods was knowable in
// advance and is printed here.
func TestTheInventoryAlwaysSaysWhatItCannotShow(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test",
		Distinct: 4, Certificates: 4, Wildcards: 1, Foreign: 1,
		Names: []ctsearch.Name{
			{Name: "*.staging.example.test", Wildcard: true, FirstSeen: day(2025, 6, 1), LastSeen: day(2026, 9, 1)},
			{Name: "api.example.test", FirstSeen: day(2024, 5, 2), LastSeen: day(2026, 1, 20)},
			{Name: "old-portal.example.test", FirstSeen: day(2021, 3, 1), LastSeen: day(2022, 6, 1)},
			{Name: "www.example.test", FirstSeen: day(2023, 2, 14), LastSeen: day(2025, 11, 1)},
		},
	}, nil)
	out := buf.String()

	for _, want := range []string{
		"4 distinct names across 4 certificates",
		"1, each covering hosts it does not name",
		"and 1 of the names\n    above is a wildcard.",
		"1 on the same certificates, under other domains, not listed",
		"old-portal.example.test",
		"from 2021-03-01, certificates to 2022-06-01",
		"What this does not show",
		"nothing was asked of example.test",
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
}

// A search that failed says so, and prints no inventory at all.
//
// The reassuring answer here is "none found", so a failure that printed an
// empty list under the usual heading would be the most comfortable wrong answer
// available (R4). The monitor answered 502 to every request on the day this was
// written, so this is the ordinary case rather than the rare one.
func TestAFailedSearchPrintsNoInventory(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test",
		Reason: "the certificate transparency monitor could not be reached",
	}, nil)
	out := buf.String()

	if !strings.Contains(out, "Not established: the certificate transparency monitor could not be reached") {
		t.Errorf("a failed search does not say so:\n%s", out)
	}
	if strings.Contains(out, "distinct name") {
		t.Errorf("a failed search printed a count:\n%s", out)
	}
}

// One name is not "1 names".
func TestTheInventoryCountsInWords(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 1, Certificates: 1,
		Names: []ctsearch.Name{{Name: "example.test", LastSeen: day(2026, 1, 1)}},
	}, nil)
	if got := buf.String(); !strings.Contains(got, "1 distinct name across 1 certificate\n") {
		t.Errorf("the count reads wrongly:\n%s", got)
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
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 2, Certificates: 2,
		Names: []ctsearch.Name{
			{Name: "example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
			{Name: "www.example.test", FirstSeen: day(2024, 1, 1), LastSeen: day(2026, 1, 1)},
		},
	}, nil)
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
func TestBothFacesSayTheSameThingAboutWhatTheInventoryMisses(t *testing.T) {
	script, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page's script: %v", err)
	}
	page := string(script)

	var buf bytes.Buffer
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 1, Certificates: 1, Wildcards: 1,
		Names: []ctsearch.Name{{Name: "*.example.test", Wildcard: true, LastSeen: day(2026, 1, 1)}},
	}, nil)
	printed := buf.String()

	// Each is a sentence both faces have to carry. Compared against what the
	// command line actually printed, so that a change to one and not the other
	// fails here rather than in front of a reader.
	for _, claim := range []string{
		"these names were published by whoever obtained a certificate for them",
		"no publicly trusted certificate never appears",
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
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 5, Certificates: 5, Wildcards: 1,
		Names: []ctsearch.Name{
			{Name: "*.example.test", Wildcard: true, FirstSeen: day(2025, 6, 1), LastSeen: day(2026, 9, 1)},
			{Name: "api.example.test", LastSeen: day(2026, 9, 1)},
			{Name: "old.example.test", LastSeen: day(2022, 6, 1)},
			{Name: "inside.example.test", LastSeen: day(2026, 9, 1)},
			{Name: "moved.example.test", LastSeen: day(2026, 9, 1)},
		},
	}, []liveness.Name{
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
		"live      api.example.test    93.184.216.34, answering on 443",
		"gone      old.example.test    does not resolve",
		"internal  inside.example.test 172.23.0.11",
		"dangling  moved.example.test  an alias to target.elsewhere.test, which does not resolve",
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

	// And the limits are still underneath all of it.
	if !strings.Contains(out, "What this does not show") {
		t.Errorf("the limits are missing:\n%s", out)
	}
}

// Where nothing asked what the names are doing, the names are still drawn.
//
// Dropping them would lose the half of the report that was established in
// order to report the half that was not (R4). The heading says which question
// went unanswered.
func TestNamesSurviveAReportThatEstablishedNoStatus(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, ctsearch.Estate{
		Asked: true, Domain: "example.test", Distinct: 1, Certificates: 1,
		Names: []ctsearch.Name{{Name: "api.example.test", LastSeen: day(2026, 9, 1)}},
	}, nil)
	out := buf.String()

	if !strings.Contains(out, "api.example.test") {
		t.Errorf("the names were dropped when nothing established their status:\n%s", out)
	}
	if !strings.Contains(out, "none of them asked what it is doing now") {
		t.Errorf("the report does not say the status went unasked:\n%s", out)
	}
}

// A wildcard is never put through a resolver.
//
// Nothing resolves `*.example.test`, so asking would produce a failure that
// reads as a fault in the estate — and the estate would then be reported as
// having a dead name that never existed.
func TestAWildcardIsNeverAskedAboutAsAName(t *testing.T) {
	got := hosts(ctsearch.Estate{Names: []ctsearch.Name{
		{Name: "*.example.test", Wildcard: true},
		{Name: "api.example.test"},
		{Name: "*.staging.example.test", Wildcard: true},
	}})
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
