package web

import (
	"strings"
	"testing"
)

// The two chains on a web report are the same measurement begun at two
// addresses, and until 2026-09-24 they were drawn as two tables that each
// sized itself to its own contents.
//
// They never hold the same contents. The secure chain carries long https://
// addresses and often several hops; the plaintext one is frequently a single
// short address, or one that answered nothing at all. So "Response" sat at the
// right edge of the first table and near the middle of the second, and the two
// rows a reader is meant to read against each other did not line up. The
// comment above the code said the columns were identical the whole time.
//
// This is the cipher tables' fault of 2026-09-02 in a second place, and it is
// fixed the same way: the geometry is declared on the columns and the browser
// is told to obey them.

// Both chains are given their columns before they are given their rows.
func TestBothChainsAreGivenTheSameColumns(t *testing.T) {
	source := script(t)

	for _, want := range []string{
		`el("table", "rows chain")`,
		`el("col", "col-address")`,
		`el("col", "col-transport")`,
		`el("col", "col-response")`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("the chain table does not declare %s", want)
		}
	}

	// A colgroup after the first row is ignored, so it has to be declared and
	// attached before the header. Attached is the half worth checking: a
	// colgroup built at the top and appended at the bottom reads correctly and
	// does nothing.
	table := strings.Index(source, `el("table", "rows chain")`)
	head := strings.Index(source, `for (const label of ["Address", "Transport", "Response"])`)
	switch {
	case table < 0 || head < 0:
		t.Error("the chain table is not written where this can find it")
	case !strings.Contains(source[table:head], `table.appendChild(group)`):
		t.Error("the columns are attached after the header row, where a browser ignores them")
	}

	// One table drawn twice, and not two tables that happen to look alike:
	// whatever is wrong with the geometry has to be wrong in both.
	if strings.Count(source, `for (const label of ["Address", "Transport", "Response"])`) != 1 {
		t.Error("the two chains are drawn by two pieces of code, which is how they came apart")
	}
}

// The stylesheet makes the browser obey those columns.
func TestTheChainColumnsAreDeclaredRatherThanMeasured(t *testing.T) {
	sheet := stylesheet(t)

	if !strings.Contains(cssRule(t, sheet, ".chain"), "table-layout: fixed") {
		t.Error("the chain tables are still sized by their contents")
	}
	for _, selector := range []string{".chain .col-transport", ".chain .col-response"} {
		if !strings.Contains(cssRule(t, sheet, selector), "width:") {
			t.Errorf("%s has no width, so it takes whatever its own rows need", selector)
		}
	}
	// Declared rather than left out, because it is what the other two are
	// measured against.
	if !strings.Contains(cssRule(t, sheet, ".chain .col-address"), "width: auto") {
		t.Error("the address column does not say it takes what is left")
	}

	// An address longer than its column has to wrap inside the cell. Anywhere
	// else and it pushes the two columns beside it out of line again, which is
	// the whole fault.
	if !strings.Contains(cssRule(t, sheet, ".chain td.address"), "overflow-wrap: anywhere") {
		t.Error("a long address is not allowed to wrap, so it will widen its column")
	}
	if !strings.Contains(script(t), `el("td", "address", hop.url || "—")`) {
		t.Error("the address cell does not carry the class the rule above is written for")
	}
}
