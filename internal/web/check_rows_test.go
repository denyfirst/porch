package web

import (
	"strings"
	"testing"
)

// An installation's pages line up where a browser found they did not.
//
// Walked page by page on 2026-09-28, at 1280 and 390 pixels, signed in and
// not: the console's two text fields ended on different lines on different
// grounds; a flag broke at its leading hyphen ("-" at the end of one line,
// "verification-secret-file" at the start of the next); the sign-in card had
// twice the room under its button that it had over its title, for an empty
// status line; and History's empty panel kept a paragraph margin under its
// last sentence because a hidden table followed it.
func TestTheInstallationsPagesLineUp(t *testing.T) {
	css := asset(t, "assets/style.css")
	for want, why := range map[string]string{
		".composer-field {\n  width: 100%;\n  max-width: var(--measure);": "the domain field ends short of the selector field under it",
		".composer .field { background: var(--paper); }":                  "the composer's fields sit on different grounds",
		"code.flag { white-space: nowrap; }":                              "a flag may break at its leading hyphen",
		".signin-status:empty { position: absolute; }":                    "an empty status line holds room under the sign-in button",
		".panel p:not(:has(~ :not([hidden]))) { margin-bottom: 0; }":      "a panel's last shown paragraph keeps its margin when a hidden element follows",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css no longer has %q: %s", want, why)
		}
	}

	// Every flag on every page is marked as one, so the rule above reaches it.
	entries, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		if body := asset(t, "assets/"+e.Name()); strings.Contains(body, "<code>-") {
			t.Errorf("%s shows a flag that is not marked as one, so it can break at its hyphen", e.Name())
		}
	}
}

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

	// The chips above the panel name what the panel offers, one each. They
	// named four of five: the inventory was added to the list and not to the
	// row that summarises it.
	chips := page[strings.Index(page, `<p class="chips">`):]
	chips = chips[:strings.Index(chips, "</p>")]
	if n, want := strings.Count(chips, "<span>"), len(consoleChecks()); n != want {
		t.Errorf("the Porch page names %d things above a panel that offers %d", n, want)
	}

	css := asset(t, "assets/style.css")

	// The note beside a band's title is centred on the heading beside it; it
	// hung from the bottom edge and read as having slipped down the page.
	if !strings.Contains(css, ".band-head {\n  display: flex;\n  flex-wrap: wrap;\n  align-items: center;") {
		t.Error("a band's note no longer sits centred on its heading")
	}

	// A note under rows of anything is given room. The section note is pulled
	// up to sit under its heading, and under the DNS report's table of name
	// servers that pull put "Their addresses are in 4 networks" four pixels
	// into the last row; measured at -4px before, 12px after.
	if !strings.Contains(css, ":is(table, .rows, .pairs, ul, ol, dl) + :is(.section-note, .group-note) {\n  margin-top: 0.75rem;") {
		t.Error("a note that follows a table is pulled up into it again")
	}

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
