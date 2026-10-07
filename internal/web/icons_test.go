package web

import (
	"strings"
	"testing"
)

// The rail's marks are drawn, not borrowed from the reader's fonts.
//
// They were six symbol characters until 2026-10-06. The typeface has none of
// them, so each came from whatever fonts the reader had and looked different
// on every system; on some, one became a coloured emoji.
func TestTheRailsMarksAreDrawn(t *testing.T) {
	layout, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(layout)
	if strings.ContainsAny(markup, "▦◎⁙◷⚙≡") {
		t.Error("the rail still marks an entry with a character the reader's fonts draw")
	}
	if n := strings.Count(markup, `<svg class="rail-glyph" viewBox="0 0 24 24" aria-hidden="true" focusable="false">`); n != 6 {
		t.Errorf("the rail draws %d marks, and it has six entries", n)
	}
	if rule := cssRule(t, stylesheet(t), ".rail-glyph"); !strings.Contains(rule, "stroke: currentColor") || !strings.Contains(rule, "fill: none") {
		t.Errorf("the rail's marks do not take their colour from the entry:\n%s", rule)
	}
}

// Each site's tab icon is its mark's first letter and stop, drawn as shapes
// and nothing else.
//
// An SVG can carry a script, a link or a reference to a file elsewhere, and a
// tab icon is fetched by every browser and by search engines. These were cut
// from the typeface's outlines and hold a square, a letter and a stop.
func TestTheTabIconsAreTheMarksAndOnlyShapes(t *testing.T) {
	for _, icon := range []struct{ file, name, stop string }{
		{"assets/favicon.svg", "denyfirst", "#ed4552"},
		{"assets/porch-icon.svg", "porch", "#9b7bf0"},
	} {
		raw, err := assets.ReadFile(icon.file)
		if err != nil {
			t.Fatal(err)
		}
		svg := strings.ToLower(string(raw))
		for _, banned := range []string{"<script", "href", "<image", "<use", "<foreignobject", "<style", "url(", "javascript:", " on"} {
			if strings.Contains(svg, banned) {
				t.Errorf("%s contains %q", icon.file, banned)
			}
		}
		if !strings.Contains(svg, `aria-label="`+icon.name+`"`) || !strings.Contains(svg, `fill="`+icon.stop+`"`) {
			t.Errorf("%s is not %s's mark with its stop", icon.file, icon.name)
		}
		if n := strings.Count(svg, "<path"); n != 2 {
			t.Errorf("%s draws %d paths, not a letter and a stop", icon.file, n)
		}
	}
}
