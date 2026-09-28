package web

import (
	"strings"
	"testing"
)

// The rows of the Porch page's check list share their columns, so every name
// and every sentence starts on one line.
//
// Each row was a grid of its own and sized its name column to its own name:
// "Transport" pushed its sentence two pixels right of the rest, and the row
// that opens the inventory, with no box to put first, began a whole column
// early and did not stack the way the others did on a phone. Measured in a
// browser on 2026-09-28 before and after; this holds the shape that fixed it.
func TestTheCheckRowsShareTheirColumns(t *testing.T) {
	page := asset(t, "assets/porch.html")
	start := strings.Index(page, `<div class="check-rows">`)
	if start < 0 {
		t.Fatal("the Porch page's checks are no longer inside one grid of rows")
	}
	rows := page[start:]
	rows = rows[:strings.Index(rows, "</div>")]

	// The row that opens a page keeps the first column, with a mark in it
	// rather than a box, and carries no second arrow on its name.
	at := strings.Index(rows, `class="check check-elsewhere"`)
	if at < 0 {
		t.Fatal("the row that opens a page is no longer among the rows")
	}
	door := rows[at:]
	door = door[:strings.Index(door, "</a>")]
	if !strings.Contains(door, `class="check-door" aria-hidden="true"`) {
		t.Error("the row that opens a page has nothing in the first column, so it starts a column early")
	}
	if strings.Contains(door, "arrow-ne") {
		t.Error("the row that opens a page carries a second arrow on its name")
	}

	css := asset(t, "assets/style.css")
	for _, want := range []string{
		".check-panel .check-rows {\n  display: grid;",
		".check-panel .check-rows .check {\n  grid-column: 1 / -1;",
		"  grid-template-columns: subgrid;\n",
		"  .check-panel .check-rows .check-says { grid-column: 2; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css no longer has %q, so the rows size their columns one by one again", want)
		}
	}
}
