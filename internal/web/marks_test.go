package web

import (
	"regexp"
	"strings"
	"testing"
)

// The wordmark ends in the brand's red, and so does it begin.
//
// The full stop was white for a while. It sat inside the pale half of the word
// with nothing to attach it to and read as a typo: an eye running along the
// name stopped at "first" and left a dot behind it. Red at both ends closes the
// word — the mark ends the sentence it begins, which is the whole of what the
// name says.
func TestTheWordmarkEndsInTheBrandColour(t *testing.T) {
	sheet := stylesheet(t)

	if !strings.Contains(cssRule(t, sheet, ".wordmark-deny, .wordmark-stop"), "color: var(--brand)") {
		t.Error("the first half and the full stop are not both the brand's red")
	}

	// And the mark carries the element for the rule to reach.
	body, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(body)
	if strings.Contains(markup, `<span class="wordmark-deny">deny</span>first.`) {
		t.Error("the full stop is still plain text, so no rule can colour it")
	}
	if n := strings.Count(markup, `first<span class="wordmark-stop">.</span>`); n != 3 {
		t.Errorf("the stop is marked up %d times, and the name appears three times in this file", n)
	}
}

// The colour scheme switch is a mark, not a word.
//
// The label said "Dark" while the page was light and "Light" while it was dark,
// which is correct and reads backwards to anybody who does not stop to think
// about it. A circle with one half filled says what pressing it gives without
// being read at all, and it is the figure this site's own icon is built from: a
// shape cut by a straight line.
//
// The word stays in aria-label, because an icon with no name is a button nobody
// using a screen reader can describe.
func TestTheColourSwitchIsAMarkAndKeepsItsName(t *testing.T) {
	body, err := assets.ReadFile("assets/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	for _, want := range []string{
		`const TO_DARK = "M12 4a8 8 0 0 1 0 16Z";`,
		`const TO_LIGHT = "M12 4a8 8 0 0 0 0 16Z";`,
		`half.setAttribute("d", toLight ? TO_LIGHT : TO_DARK);`,
		// Set, and set on its own line: a name added behind a condition is a
		// name a button may not have.
		"\n    button.setAttribute(\"aria-label\",\n",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("theme.js no longer carries %s", want)
		}
	}

	// The words are gone from the face of it: a button holding both a mark and
	// a word is the state this change was made to leave.
	if strings.Contains(src, `button.textContent = current() === "dark" ? "Light" : "Dark";`) {
		t.Error("the switch still writes a word on itself")
	}

	sheet := stylesheet(t)
	if !strings.Contains(cssRule(t, sheet, ".theme-toggle .theme-half"), "fill: currentColor") {
		t.Error("the filled half does not take the button's colour")
	}
	// Square, so the mark is not stretched by a label that is no longer there.
	if rule := cssRule(t, sheet, ".theme-toggle"); !strings.Contains(rule, "width: 34px") ||
		!strings.Contains(rule, "height: 34px") {
		t.Errorf("the switch is not a square target: %q", rule)
	}
}

// Nothing to publish is nothing to show.
//
// A name that was refused produced the proof card with an empty chooser, two
// Copy buttons for nothing, and a Check again for a domain that does not exist.
// And a chooser holding one item asks a question with one answer: above
// example.com there is nothing to offer, so the name is shown as text.
func TestTheProofCardIsShownOnlyWhenThereIsARecord(t *testing.T) {
	body, err := assets.ReadFile("assets/domains.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(body)
	if !strings.Contains(markup, `<div id="domain-proof" hidden>`) {
		t.Error("the record is not in a block that can be hidden, or is not hidden to begin with")
	}
	if !strings.Contains(markup, `<p class="proof-single" id="domain-single" hidden></p>`) {
		t.Error("there is nowhere to write a single choice as text")
	}

	src := script(t)
	for _, want := range []string{
		`proof.hidden = records.length === 0;`,
		`if (records.length === 0) return;`,
		`document.getElementById("domain-proof").hidden = true;`,
		`level.hidden = only;`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js does not carry %s", want)
		}
	}
}

// What a sheet of paper gets, and that every rule for it reaches something.
//
// A report is the thing somebody hands to an auditor, and the only way to take
// one away was the JSON, which is a file for a program. The browser prints what
// is on the screen; the print block decides what "on the screen" means when the
// screen is A4. No PDF is written here: writing one would mean a library, and
// there are none, or a PDF writer limited to the fonts a reader already has —
// which would produce a document in different type from the report it claims
// to be.
//
// Each selector is checked against the assets, because a rule naming a class
// that does not exist does nothing and reads as though it does. Two of them did
// exactly that when this block was written.
func TestWhatPrintsIsTheReportAndNotTheInstallation(t *testing.T) {
	sheet := stylesheet(t)

	start := strings.LastIndex(sheet, "@media print {")
	if start < 0 {
		t.Fatal("the stylesheet says nothing about paper")
	}
	block := sheet[start:]

	// The light values, restated rather than referenced: a report printed from
	// the dark scheme is a black rectangle that empties a cartridge, and the
	// dark values are set on an attribute a media query cannot unset.
	for _, want := range []string{
		`:root, :root[data-theme="dark"]`,
		"--paper:      #ffffff",
		"--ink:        #16181d",
		"color-scheme: light",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("paper does not carry %q, so a dark page prints dark", want)
		}
	}

	// The way around the installation and the things that are pressed do not
	// belong to the document.
	hidden := []string{
		".rail", ".theme-toggle", ".work-heading",
		".summary-actions", ".composer", ".checks", ".colophon-links",
	}
	for _, class := range hidden {
		if !strings.Contains(block, class) {
			t.Errorf("%s is printed, and it is part of the installation rather than the report", class)
		}
	}

	// And every class the block names is one the pages use, read out of the
	// block itself rather than from a list beside it: a list is a second place
	// to forget, and the rule that does nothing is the one nobody added to it.
	assets := assetText(t)
	for _, class := range classesIn(block) {
		if !strings.Contains(assets, class) {
			t.Errorf("the print block styles .%s, which nothing on any page carries", class)
		}
	}

	// The button that reaches it, which exists only where a report is the
	// reader's own to keep.
	src := script(t)
	if !strings.Contains(src, "button.addEventListener(\"click\", () => window.print());") {
		t.Error("nothing on the page opens the print dialogue")
	}
}

// assetText is every page and script this package serves, read as one string,
// for asking whether a class name is used anywhere at all.
func assetText(t *testing.T) string {
	t.Helper()

	names, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, name := range names {
		if strings.HasSuffix(name.Name(), ".css") {
			continue
		}
		body, err := assets.ReadFile("assets/" + name.Name())
		if err != nil {
			t.Fatal(err)
		}
		all.Write(body)
	}
	return all.String()
}

// classesIn returns every class name a stylesheet fragment selects on.
//
// Written out rather than taken from a list beside the block, because a list is
// a second place to forget: the rule that does nothing is precisely the one
// nobody thought to add.
func classesIn(block string) []string {
	// Comments first: this block explains itself in prose, and two names in that
	// prose are there precisely because they select nothing.
	block = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(block, " ")

	var out []string
	seen := map[string]bool{}
	for _, match := range regexp.MustCompile(`\.([a-z][a-z0-9-]*)`).FindAllStringSubmatch(block, -1) {
		if !seen[match[1]] {
			seen[match[1]] = true
			out = append(out, match[1])
		}
	}
	return out
}

// What turns the history on is a flag at start, not a password being typed.
//
// The page said "put a password in front of it with -access-file", which reads
// as though signing in is what begins keeping results. It is not: -access-file
// decides both that nothing is served without signing in and that what is
// served is kept, and a check run before that flag was given was never written
// down at all.
func TestTheHistorySaysWhatTurnsItOn(t *testing.T) {
	body, err := assets.ReadFile("assets/history.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(body)

	for _, want := range []string{
		"signing in does not change that",
		"how <code>porchd</code> was started",
		"Checks run before that were never written down",
	} {
		if !strings.Contains(markup, want) {
			t.Errorf("the empty history does not say %q", want)
		}
	}
	if strings.Contains(markup, "Put a password in front of it with") {
		t.Error("the page still reads as though a password is what starts keeping results")
	}
}
