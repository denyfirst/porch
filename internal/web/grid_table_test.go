package web

import (
	"regexp"
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
