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

// The badge a site may show is a shape, a title and a date to fill in.
//
// It goes on other people's pages, so it must not be able to do anything
// there: no script, no link, nothing fetched. The files in the repository
// carry the placeholder rather than a date, so nobody publishes a day they did
// not check by forgetting to change it, and they are ASCII, so whatever edits
// the date cannot garble them. The sizes and the address the page gives are
// the files' own.
func TestTheBadgeIsAShapeAndADate(t *testing.T) {
	page, err := os.ReadFile("../../docs/badge.md")
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile("../../docs/README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "(badge.md)") {
		t.Error("the docs index does not list the badge")
	}
	doc := string(page)
	if !strings.Contains(doc, `<a href="`+PorchURL+`/">`) {
		t.Errorf("the badge does not link to %s/", PorchURL)
	}
	for name, size := range map[string][2]string{
		"porch-badge-light.svg": {"264", "60"},
		"porch-badge-dark.svg":  {"264", "60"},
		"porch-badge-small.svg": {"188", "24"},
	} {
		raw, err := os.ReadFile("../../docs/assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		badge := string(raw)
		lower := strings.ToLower(badge)
		for _, banned := range []string{"<script", "href", "<image", "<use", "<foreignobject", "<style", "url(", "javascript:", " on"} {
			if strings.Contains(lower, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
		for i := 0; i < len(badge); i++ {
			if badge[i] > 0x7e || badge[i] < 0x20 && badge[i] != '\n' {
				t.Errorf("%s has byte %#x at %d, which is not printable ASCII", name, badge[i], i)
				break
			}
		}
		if n := strings.Count(badge, "YYYY-MM-DD"); n != 3 {
			t.Errorf("%s carries the placeholder %d times, not in its title, its label and its text", name, n)
		}
		if regexp.MustCompile(`\d{4}-\d{2}-\d{2}`).MatchString(badge) {
			t.Errorf("%s carries a date; the repository's copy carries the placeholder", name)
		}
		if !strings.Contains(badge, `aria-label="Checked with Porch, YYYY-MM-DD"`) || !strings.Contains(badge, "<title>Checked with Porch, YYYY-MM-DD</title>") {
			t.Errorf("%s does not say what it is to a reader who cannot see it", name)
		}
		if !strings.HasPrefix(badge, `<svg xmlns="http://www.w3.org/2000/svg" width="`+size[0]+`" height="`+size[1]+`" viewBox="0 0 `+size[0]+" "+size[1]+`"`) {
			t.Errorf("%s is not %sx%s", name, size[0], size[1])
		}
		if !strings.Contains(doc, "(assets/"+name+") | "+size[0]+" × "+size[1]+" |") {
			t.Errorf("the page does not give %s at %s × %s", name, size[0], size[1])
		}
	}
	if !strings.Contains(doc, `<img src="/porch-badge-light.svg" width="264" height="60"`) || !strings.Contains(doc, `<img src="/porch-badge-small.svg" width="188" height="24"`) {
		t.Error("the page's snippets do not give the badges' own sizes")
	}
}
