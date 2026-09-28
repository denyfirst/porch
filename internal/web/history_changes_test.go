package web

import (
	"strings"
	"testing"
)

// A report opened from History says what changed since the one kept before
// it, and says nothing where the comparison would mean nothing.
//
// Three conditions, each one a way a comparison would mislead. A verdict set
// beside one graded under another rule set says the server changed when the
// rules did. A finding missing from a report that measured nothing is not a
// finding that went away (R4). And the report compared with must be of the
// same check against the same host, or the list is of differences between two
// different things.
//
// Read from the source, as every script test here is: this project has no
// toolchain that runs JavaScript.
func TestAReportIsComparedOnlyWhereTheComparisonMeansSomething(t *testing.T) {
	source := script(t)
	at := func(needle string) int {
		i := strings.Index(source, needle)
		if i < 0 {
			t.Fatalf("app.js no longer contains %q, so this test has stopped checking anything", needle)
		}
		return i
	}

	// Verdicts side by side only under one rule set.
	at(`samePolicy: typeof now.policy === "string" && now.policy !== "" && now.policy === before.policy,`)
	block := source[at("function changesBlock("):]
	if same, verdict := strings.Index(block, "if (changes.samePolicy) {"), strings.Index(block, `"Verdict: "`); same < 0 || verdict < same {
		t.Error("changesBlock writes a verdict line outside the branch that requires one rule set")
	}
	// And "then and now" is said only of one verdict. A condition that drew
	// every pair that way passed everything above.
	if !strings.Contains(block, "    if (changes.verdictNow === changes.verdictBefore) {\n"+
		"      verdict.appendChild(el(\"span\", markClass(changes.verdictNow), changes.verdictNow));\n"+
		"      verdict.appendChild(document.createTextNode(\" then and now.\"));\n"+
		"    } else {") {
		t.Error("changesBlock says a verdict held \"then and now\" on some condition other than the two being equal")
	}

	// Nothing measured, nothing compared — and the return comes before the
	// findings are read.
	at(`measured: graded(now) && graded(before),`)
	if ret, read := at("if (!changes.measured) return changes;"), at("const a = reportFindings(now);"); ret > read {
		t.Error("reportChanges reads the findings before it has asked whether both reports measured anything")
	}
	if ret, lists := strings.Index(block, "if (!changes.measured) {"), strings.Index(block, "const list = "); ret < 0 || lists < ret {
		t.Error("changesBlock lists findings before it has asked whether both reports measured anything")
	}

	// The same check, the same host.
	at(`if (other.id === entry.id || other.check !== entry.check || other.target !== entry.target) continue;`)

	// Asked for when a report is opened, through the gate, and not when the
	// list is drawn: the list is one request, as it was.
	open := source[at(`open.addEventListener("click", async () => {`):]
	open = open[:strings.Index(open, "remove.addEventListener(")]
	if !strings.Contains(open, `historyRequest("GET", "/api/v1/history/" + previous.id)`) {
		t.Error("the earlier report is not asked for when a report is opened")
	}
	if n := strings.Count(source, `"/api/v1/history/" + previous.id`); n != 1 {
		t.Errorf("the earlier report is asked for in %d places, want the one above", n)
	}
}
