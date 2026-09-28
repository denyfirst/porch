package web

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/knownnames"
)

// The inventory says what leaves the page and where it stops, beside the field
// it leaves from and again on the page that field links to.
//
// On 2026-09-28 the help under the inventory's fields was shortened for the
// layout, and three sentences went with it: that the names in a file leave
// the page in the same request as the domain, though the file itself is not
// uploaded; that a range past its bound is refused; and that a list past its
// bound is. "Never uploaded" stayed, and read alone it says less left the page
// than did. The link under each field promised "the limits on a range" on a
// method page that did not state them.
//
// The bounds are read from the code that enforces them rather than written
// here a second time: ptrnames keeps its own unexported, so they are read
// from its source, as other tests in this package read theirs.
func TestTheInventorySaysWhatLeavesThePageAndWhereItStops(t *testing.T) {
	page := asset(t, "assets/names.html")
	method := asset(t, "assets/names-method.html")

	src, err := os.ReadFile("../ptrnames/ptrnames.go")
	if err != nil {
		t.Fatal(err)
	}
	bound := func(name string) int {
		m := regexp.MustCompile(`(?m)^\s*` + name + `\s*=\s*([0-9]+)\s*$`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("ptrnames no longer declares %s where this test reads it", name)
		}
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	for _, want := range []string{
		"/" + strconv.Itoa(bound("smallestIPv4")),
		"/" + strconv.Itoa(bound("smallestIPv6")),
		grouped(bound("maxAddresses")) + " addresses",
		grouped(knownnames.MaxNames) + " names",
		"same request as the domain",
		"never uploaded",
		"lines beginning with",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the inventory's fields no longer say %q", want)
		}
		if !strings.Contains(method, want) {
			t.Errorf("the names method page, which the fields link to, does not say %q", want)
		}
	}

	// And where a copy anybody can reach stops: only a proven domain.
	if !strings.Contains(page, "proven control") {
		t.Error("the inventory's field no longer says a copy others can reach lists only a proven domain")
	}
}

// A list somebody typed is sent whole, so that the service refuses one past
// its bound rather than the page cutting it without a word.
func TestAListOfNamesIsSentWholeForTheServiceToRefuse(t *testing.T) {
	body := functionBody(t, script(t), "knownAsked")
	if strings.Contains(body, "slice(") {
		t.Error("knownAsked cuts the list before sending it, so a list past the bound loses its tail " +
			"without a word and the service never sees enough to refuse")
	}
	if !strings.Contains(body, "{ names: names }") {
		t.Error("knownAsked no longer sends the names as they were split; this test has stopped checking anything")
	}
}

// Every field in the inventory's column stops at the same measure.
//
// A row of inputs was held to it and the box for names was not, so it ran
// on to the page's edge: the one field in the column with its own right
// margin, beside two that lined up. Measured in a browser on 2026-09-28, all
// of them now end on one line.
func TestEveryFieldInTheColumnStopsAtTheMeasure(t *testing.T) {
	css := asset(t, "assets/style.css")
	for _, selector := range []string{".field-row {", ".field-lines {"} {
		start := strings.Index(css, "\n"+selector)
		if start < 0 {
			t.Fatalf("style.css has no rule %q where this test reads it", selector)
		}
		rule := css[start : start+strings.Index(css[start:], "}")]
		if !strings.Contains(rule, "max-width: var(--measure);") {
			t.Errorf("%s is not held to the measure, so it ends on a different line from the fields beside it",
				strings.TrimSuffix(selector, " {"))
		}
	}
}

// grouped writes a number the way the pages do: 4096 as "4,096".
func grouped(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
