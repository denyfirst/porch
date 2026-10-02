package web

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A report drawn as rows of label and value fits a phone.
//
// Reach, Mail and DNS draw their evidence in .grid tables; Transport draws its
// own in .pairs, which stack on a narrow screen. The grid's labels were kept on
// one line and its values broke only at spaces, so the longest of each set the
// table's width. Measured on 2026-10-02 at 390 pixels, the report column was
// 342 wide and the Reach table 441: "Cross-Origin-Embedder-Policy" held 251
// pixels on every row, and the page scrolled sideways on every report but
// Transport. DNS ran past the edge the same way, on an IPv6 address beside a
// label of the same kind.
//
// Read out of the stylesheet rather than measured, because nothing in CI runs
// a browser. Both halves are needed: wrapped labels with unbreakable values
// still overflow on a long address, and breakable values beside a label that
// will not wrap leave the value a column a few letters wide.
func TestAReportTableFitsAPhone(t *testing.T) {
	sheet := stylesheet(t)

	if body := cssRule(t, sheet, ".grid td"); !strings.Contains(body, "overflow-wrap: anywhere") {
		t.Error("a value in a report table cannot break, so the longest one sets the table's width")
	}

	phone := regexp.MustCompile(`(?s)@media \(max-width: 34rem\) \{\s*\.grid th \{[^}]*white-space: normal`)
	if !phone.MatchString(sheet) {
		t.Error("on a phone a report table's labels stay on one line, so the longest one holds most of the screen")
	}

	// And the labels are not given `anywhere`. The label column is sized to
	// its narrowest content, so a label that may break between any two
	// letters is a column one letter wide.
	if regexp.MustCompile(`(?m)^\s*\.grid th[^{]*\{[^}]*overflow-wrap: anywhere`).MatchString(sheet) {
		t.Error("a report table's labels may break between any two letters, which shrinks their column to one")
	}
}

// A chain's two short columns hold their own words on a phone.
//
// The columns are shares of the width, and on a phone a fifth of it is
// narrower than the word in it: at 390 pixels the transport column was 62
// pixels, "Transport" needs 69 and "plaintext" 64, and both ran on under
// "Response" and "308" in both chains. Nothing ran off the screen, so the
// check written for that found nothing. A browser found it, on a phone.
//
// The floors are the content: "Transport" in the header's spaced capitals is
// 9.65 characters of the body's monospace, and "no response" is eleven.
func TestAChainsShortColumnsHoldTheirWordsOnAPhone(t *testing.T) {
	sheet := stylesheet(t)

	block := regexp.MustCompile(`(?s)@media \(max-width: 34rem\) \{[^@]*?\.chain \.col-transport[^@]*?\n\}`).FindString(sheet)
	if block == "" {
		t.Fatal("on a phone the chain's columns keep their shares, so a fifth of the width holds a word wider than it")
	}

	for _, c := range []struct {
		col   string
		floor float64
		why   string
	}{
		{"col-transport", 10, `"Transport" in the header`},
		{"col-response", 11, `"no response"`},
	} {
		m := regexp.MustCompile(`\.chain \.` + c.col + `\s*\{\s*width:\s*(?:calc\()?([0-9.]+)ch`).FindStringSubmatch(block)
		if m == nil {
			t.Errorf("on a phone .%s is not given a width in characters", c.col)
			continue
		}
		if n, _ := strconv.ParseFloat(m[1], 64); n < c.floor {
			t.Errorf("on a phone .%s is %sch, narrower than %s", c.col, m[1], c.why)
		}
	}

	if !regexp.MustCompile(`\.chain \.col-address\s*\{\s*width:\s*auto`).MatchString(block) {
		t.Error("on a phone the address keeps a share as well, so the three no longer add up to the table")
	}
}

// A notes section's count goes under its title when the two do not fit.
//
// At 320 pixels "Observed" and "6 measured, not graded" came to 261 pixels in
// a 238-pixel line, and the count ran past the edge of the panel.
func TestANotesCountWrapsRatherThanRunningOff(t *testing.T) {
	if body := cssRule(t, stylesheet(t), ".notes-head"); !strings.Contains(body, "flex-wrap: wrap") {
		t.Error("a notes head cannot wrap, so on a narrow phone its count runs past the edge")
	}
}
