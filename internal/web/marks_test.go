package web

import (
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
