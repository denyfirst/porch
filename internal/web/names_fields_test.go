package web

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/liveness"
)

// Every source the inventory carries has a line in the report.
//
// Taken from the struct rather than from a list somebody keeps in step: a
// seventh source arrives as a seventh Reading, and this fails until the page
// draws a row for it. That is not a hypothetical. Reverse DNS was sent by the
// service and read by the command line for three weeks while this page never
// mentioned it — so an operator who typed an address range got its names
// folded into the list with nothing saying the walk had happened, how wide it
// was, or that it had failed, and the totals underneath could not be accounted
// for from the lines above them (R4).
func TestThePageDrawsALineForEverySourceTheInventorySends(t *testing.T) {
	src := script(t)

	report := reflect.TypeOf(inventory.Inventory{})
	reading := reflect.TypeOf(inventory.Reading{})
	list := functionBody(t, src, "readings")

	sources := 0
	for i := range report.NumField() {
		field := report.Field(i)
		if field.Type != reading {
			continue
		}
		sources++

		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if key == "" {
			t.Errorf("%s is sent under no name a page could read", field.Name)
			continue
		}

		// The call, not the function — and the closing bracket of the row it
		// sits in, because `saysReverse(data)` is also how the function itself
		// is declared. Deleting the row and leaving the function behind
		// escaped this test on 2026-09-28 for exactly that reason.
		says := "says" + strings.ToUpper(key[:1]) + key[1:] + "(data))"
		if !strings.Contains(src, says) {
			t.Errorf("no row of the report draws %s, so the %s source is read and never reported",
				says, key)
		}
		if !regexp.MustCompile(`\bdata\.` + key + `\b`).MatchString(src) {
			t.Errorf("the page does not read data.%s", key)
		}

		// And the one list the rest of the report reads has it, so a source
		// cannot answer alone and be reported as nothing established.
		if !strings.Contains(list, "data."+key) {
			t.Errorf("readings() leaves out data.%s, so a report resting on that source alone "+
				"says nothing was established", key)
		}

		// Each line tells the three states apart. Not asked, asked and failed,
		// and asked and answered are three different reports, and a summary
		// that collapses any two of them is the shortening this whole mode is
		// written against (R4).
		body := functionBody(t, src, "says"+strings.ToUpper(key[:1])+key[1:])
		for _, field := range []string{".asked", ".reason", ".named"} {
			if !strings.Contains(body, field) {
				t.Errorf("the %s line never reads %s, so two of its three states read alike:\n%s",
					key, field, body)
			}
		}
	}

	if sources < 6 {
		t.Fatalf("the inventory carries %d sources, which is fewer than the six it had", sources)
	}
	if got := strings.Count(list, "data."); got != sources {
		t.Errorf("readings() names %d sources and the inventory sends %d:\n%s", got, sources, list)
	}
}

// functionBody is one function of the script, from its declaration to the
// closing brace in the first column.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()

	at := strings.Index(src, "function "+name+"(")
	if at < 0 {
		t.Fatalf("the script declares no %s", name)
	}
	rest := src[at:]
	if end := strings.Index(rest, "\n}"); end > 0 {
		return rest[:end]
	}
	return rest
}

// And the page reads the field names the service sends for one name.
//
// Marshalled rather than written out, so a field renamed in Go is a field this
// notices. A misspelling on either side reads as undefined, which is falsy —
// and `wildcard` misread would put a wildcard in the table of hosts, where
// every row is a thing a reader may go and look at.
func TestThePageReadsTheNameFieldsTheAPISends(t *testing.T) {
	when := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(inventory.Name{
		Name:      "www.example.test",
		Sources:   []inventory.Source{inventory.FromZone, inventory.FromCertificate},
		FirstSeen: when,
		LastSeen:  when,
		Now:       &liveness.Name{Name: "www.example.test", Status: "live"},
	})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	src := script(t)

	for _, field := range []string{"name", "sources", "firstSeen", "lastSeen", "now"} {
		if _, ok := sent[field]; !ok {
			t.Errorf("the API sends no %s on a name", field)
		}
		if !regexp.MustCompile(`\bname\.` + field + `\b`).MatchString(src) {
			t.Errorf("the page does not read name.%s", field)
		}
	}

	// wildcard is omitted when false, so it is checked for on the page alone.
	if !regexp.MustCompile(`\bn\.wildcard\b|\bname\.wildcard\b`).MatchString(src) {
		t.Error("the page never reads wildcard, so wildcards would be listed as hosts")
	}
}

// The tables of names are shaped like every other table on this site.
//
// Three sabotages escaped every test here on 2026-09-28 — the name column
// losing the class that lets a long host name break, the wildcard table losing
// its heads, and the state of a name collapsing back into one sentence — and
// none of them changes a number. That is the argument for pinning them: a
// report nobody can read is not a smaller fault than a report with a wrong
// figure in it, and this project already keeps a test for the alignment of the
// cipher columns for the same reason.
func TestTheTablesOfNamesCanBeRead(t *testing.T) {
	body := functionBody(t, script(t), "buildNames")

	tables := strings.Count(body, `el("table", "rows")`)
	if tables < 2 {
		t.Fatalf("the report draws %d tables of names", tables)
	}

	// A host name is long and has no spaces. Without this the longest name
	// sets the width of the table and pushes the columns beside it off a
	// narrow screen — in every table of names, which is why this counts them
	// rather than finding one: the hosts lost the class on 2026-09-28 and the
	// wildcards still had it, so looking for the string found it and said
	// nothing.
	if breaks := strings.Count(body, `el("td", "hostname", name.name)`); breaks != tables {
		t.Errorf("%d of the %d tables of names break a long name, so one name sets the width of "+
			"the others", breaks, tables)
	}

	// Every table says what its columns are. The wildcards were two unlabelled
	// columns of names and sentences about certificates.
	if heads := strings.Count(body, `el("thead")`); heads != tables {
		t.Errorf("the report draws %d tables of rows and %d heads, so a column is unlabelled",
			tables, heads)
	}

	// And what a name is doing leads with the state, with the evidence as a
	// note under it rather than as the rest of a sentence.
	if !strings.Contains(body, "doingCell(name)") {
		t.Error("the report no longer draws what each name is doing as a cell of its own")
	}
	cell := functionBody(t, script(t), "doingCell")
	if !strings.Contains(cell, `el("p", "row-note", why)`) {
		t.Error("the evidence for a state is not a row-note, so the column is a column of prose")
	}
	if !strings.Contains(cell, `"mark-faint"`) {
		t.Error("a name nothing asked about is not drawn faint, so unmeasured reads as measured")
	}
}

// A sentence about the demonstration is written only by the demonstration.
//
// The script is one file and both builds serve it, so a claim drawn without
// reading DEMO_SITE is a claim every installation makes about itself. The one
// here — that every source marked "not asked" is one this deployment does not
// use, and a copy you run yourself reads each of them — is false on a copy
// somebody runs: those sources are theirs to switch on, and several may
// already be on. A page telling an operator something false about their own
// installation is the worst thing on this site, because it is the page they
// would quote (N14).
//
// Checked by the guard rather than by the words, because the words are in the
// file on both builds and a test that only looked for them would pass while
// every installation printed them.
func TestAClaimAboutTheDemonstrationIsGuardedByIt(t *testing.T) {
	limits := functionBody(t, script(t), "namesLimits")

	const claim = "this demonstration does not use"
	if !strings.Contains(limits, claim) {
		t.Fatalf("the inventory's limits no longer say what a copy you run yourself adds")
	}

	const guard = "if (DEMO_SITE) {"
	before, after, found := strings.Cut(limits, guard)
	if !found {
		t.Fatalf("the limits say %q without asking which deployment this is", claim)
	}
	if strings.Contains(before, claim) {
		t.Errorf("an installation somebody runs claims to be the demonstration:\n%s", before)
	}

	// And the guard closes before the end, so the claim is inside it rather
	// than merely after it.
	guarded, rest, closed := strings.Cut(after, "\n  }")
	if !closed {
		t.Fatal("the guard around the demonstration's sentence is never closed")
	}
	if !strings.Contains(guarded, claim) {
		t.Errorf("the demonstration's sentence sits outside the guard:\n%s", guarded)
	}
	if strings.Contains(rest, claim) {
		t.Errorf("the sentence is drawn again after the guard:\n%s", rest)
	}
}
