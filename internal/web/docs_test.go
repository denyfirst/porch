package web

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// Porch's documentation is on GitHub, and every page of Porch's leads there
// from its header and its footer.
func TestEveryPageLeadsToTheDocs(t *testing.T) {
	for path, p := range pages {
		if demo.Enabled && p.Organisation {
			continue
		}
		body := get(t, path).Body.String()
		_, foot, _ := strings.Cut(body, `<footer class="colophon">`)
		if !strings.Contains(foot, `href="`+DocsURL+`">Docs</a>`) {
			t.Errorf("%s: the footer does not lead to the docs", path)
		}
		head, _, _ := strings.Cut(body, "<main>")
		if !strings.Contains(head, `href="`+DocsURL+`"`) {
			t.Errorf("%s: the header does not lead to the docs", path)
		}
	}

	// The index the link opens lists every document.
	raw, err := os.ReadFile("../../docs/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"(checks.md)", "(self-host.md)", "(verify.md)", "(../SECURITY.md)", "(https://github.com/denyfirst/porch/releases)"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("docs/README.md does not link %s", want)
		}
	}
}

// Arrows are drawn by the stylesheet with nothing in their content, so a
// screen reader reads the link and not the arrow.
//
// They were characters until 2026-10-06, with empty alternative text. The
// typeface has no arrows, so each came from the reader's own fonts and was a
// different arrow on every system; they are drawn now, one shape turned to
// face each way, and no arrow character is left for a font to supply.
func TestArrowsAreDecoration(t *testing.T) {
	sheet := stylesheet(t)
	shape := cssRule(t, sheet, ".arrow-ne::after,\n.arrow-se::after,\n.arrow-e::after,\n.arrow-down::after")
	for _, want := range []string{`content: "";`, "border-top:", "border-right:", "linear-gradient(to bottom right"} {
		if !strings.Contains(shape, want) {
			t.Errorf("the arrow is not drawn: its rule lacks %q", want)
		}
	}
	if strings.ContainsAny(sheet, "↗↘→↓▾") {
		t.Error("the stylesheet still sets an arrow as a character, which the reader's fonts draw differently")
	}
	for _, name := range []string{"assets/home.html", "assets/porch.html", "assets/docs.html", "assets/app.js"} {
		body, err := assets.ReadFile(name)
		if err != nil {
			continue
		}
		if strings.ContainsAny(string(body), "↗↘→") && name != "assets/app.js" {
			t.Errorf("%s writes an arrow into its text", name)
		}
	}
}

// Nothing moves for a reader who asked the system for less motion.
func TestHoverMotionRespectsReducedMotion(t *testing.T) {
	sheet := stylesheet(t)
	blocks := regexp.MustCompile(`(?s)@media \(prefers-reduced-motion: reduce\) \{(.*?)\n\}`).FindAllStringSubmatch(sheet, -1)
	all := ""
	for _, b := range blocks {
		all += b[1]
	}
	for _, want := range []string{".card-link:hover { transform: none; }", ".arrow-ne::after", "transition: none;"} {
		if !strings.Contains(all, want) {
			t.Errorf("the reduced-motion rules do not include %q", want)
		}
	}
}

// The demonstration's header lists products under one entry, so the bar does
// not grow with the catalog, and the list works without a script.
func TestProductsAreAMenuNotABar(t *testing.T) {
	src, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	layout := string(src)
	// The demonstration's header is the masthead; an installation's rail comes
	// first in the file and is not it.
	_, brand, _ := strings.Cut(layout, `<header class="masthead">`)
	brand, _, _ = strings.Cut(brand, "</header>")
	// The navigation, without the wordmark, which on Porch's pages is Porch's
	// own link home.
	_, brand, _ = strings.Cut(brand, `<nav class="masthead-nav"`)

	// The source, so the links are as the template writes them: Porch's page
	// is the root of Porch's own name since 2026-10-05.
	if strings.Count(brand, `href="{{.PorchBase}}/"`) != 1 || !strings.Contains(brand, `<ul class="nav-menu-list">`) {
		t.Error("Porch is not listed under the Products menu")
	}
	bar := regexp.MustCompile(`(?s)<ul class="nav-menu-list">.*?</ul>`).ReplaceAllString(brand, "")
	if strings.Contains(bar, `href="{{.PorchBase}}/"`) {
		t.Error("a product sits in the bar itself")
	}
	for _, want := range []string{`href="{{.SiteBase}}/">Home</a>`, `<a class="nav-menu-button" href="{{.SiteBase}}/#products">Products</a>`, `href="` + DocsURL + `">Docs</a>`} {
		if !strings.Contains(brand, want) {
			t.Errorf("the demonstration's header lacks %s", want)
		}
	}

	sheet := stylesheet(t)
	for _, want := range []string{".nav-menu:hover .nav-menu-list", ".nav-menu:focus-within .nav-menu-list", ".nav-menu-list::before"} {
		if !strings.Contains(sheet, want) {
			t.Errorf("the menu does not open with %s", want)
		}
	}
	if !strings.Contains(cssRule(t, sheet, ".nav-menu-list"), "display: none") {
		t.Error("the menu is open before anybody asks for it")
	}
	// It opens towards the page. Anchored by its left edge it ran 67 pixels
	// past the right of a 1280-pixel window and scrolled the page sideways.
	if list := cssRule(t, sheet, ".nav-menu-list"); !strings.Contains(list, "right: -1rem;") || strings.Contains(list, "left:") {
		t.Errorf("the menu is not anchored by its right edge:\n%s", list)
	}
}

// The marks the README shows are drawn shapes and nothing else.
//
// They are SVG, and an SVG can carry a script, a link or a reference to a file
// elsewhere. These were made from the typeface's outlines and hold paths and a
// title; this keeps anything that runs or fetches out of them.
func TestTheReadmesMarksAreOnlyShapes(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"porch-light.svg", "porch-dark.svg"} {
		if !strings.Contains(string(readme), "docs/assets/"+name) {
			t.Errorf("the README does not show %s", name)
		}
		raw, err := os.ReadFile("../../docs/assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		mark := strings.ToLower(string(raw))
		for _, banned := range []string{"<script", "href", "<image", "<use", "<foreignobject", "<style", "url(", "javascript:", " on"} {
			if strings.Contains(mark, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
		if !strings.Contains(mark, "<title>porch.</title>") {
			t.Errorf("%s does not name itself for a reader who cannot see it", name)
		}
	}
}
