package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// Every document is on one page, and Porch's pages lead there.
func TestEveryDocumentIsOnTheDocsPage(t *testing.T) {
	page := get(t, "/docs").Body.String()
	for _, want := range []string{
		`href="/tls/method"`, `href="/web/method"`, `href="/mail/method"`, `href="/dns/method"`, `href="/names/method"`,
		`href="/privacy"`, `href="/terms"`, `href="/undertakings"`, `href="/organisation"`,
		"docs/self-host.md", "docs/verify.md", "SECURITY.md",
		`href="https://github.com/denyfirst/porch"`, `href="https://github.com/denyfirst/porch/releases"`,
		// Absolute, on both builds: denyfirst.dev is the one place these are
		// served, and an installation's own address would answer with a 404.
		`href="` + SiteURL + PGPKeyPath + `"`, `href="` + SiteURL + SecurityTxtPath + `"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("/docs does not lead to %s", want)
		}
	}

	// A link inside a link is not a link a browser can be relied on to follow.
	cards := regexp.MustCompile(`(?s)<a class="card[^"]*"[^>]*>(.*?)</a>`).FindAllStringSubmatch(page, -1)
	if len(cards) < 10 {
		t.Fatalf("only %d cards on /docs", len(cards))
	}
	for _, c := range cards {
		if strings.Contains(c[1], "<a ") {
			t.Errorf("a card on /docs holds a link of its own: %s", c[1])
		}
	}

	// Every page of Porch's leads to /docs from its header and its footer.
	for path, p := range pages {
		if demo.Enabled && p.Organisation {
			continue
		}
		body := get(t, path).Body.String()
		_, foot, _ := strings.Cut(body, `<footer class="colophon">`)
		if !strings.Contains(foot, `href="`+porchLink("/docs")+`">Docs</a>`) {
			t.Errorf("%s: the footer does not lead to /docs", path)
		}
		head, _, _ := strings.Cut(body, "<main>")
		if !strings.Contains(head, `href="`+porchLink("/docs")+`"`) {
			t.Errorf("%s: the header does not lead to /docs", path)
		}
	}
}

// Arrows are drawn by the stylesheet with empty alternative text, so a screen
// reader reads the link and not the arrow.
func TestArrowsAreDecoration(t *testing.T) {
	sheet := stylesheet(t)
	for _, arrow := range []string{`"↗" / ""`, `"↘" / ""`, `"→" / ""`, `"↓" / ""`} {
		if !strings.Contains(sheet, arrow) {
			t.Errorf("the stylesheet does not draw %s as decoration", arrow)
		}
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

	// The source, so the links are as the template writes them: Porch's page
	// is the root of Porch's own name since 2026-10-05.
	if strings.Count(brand, `href="{{.PorchBase}}/"`) != 1 || !strings.Contains(brand, `<ul class="nav-menu-list">`) {
		t.Error("Porch is not listed under the Products menu")
	}
	bar := regexp.MustCompile(`(?s)<ul class="nav-menu-list">.*?</ul>`).ReplaceAllString(brand, "")
	if strings.Contains(bar, `href="{{.PorchBase}}/"`) {
		t.Error("a product sits in the bar itself")
	}
	for _, want := range []string{`href="{{.SiteBase}}/">Home</a>`, `<a class="nav-menu-button" href="{{.SiteBase}}/#products">Products</a>`, `href="{{.PorchBase}}/docs">Docs</a>`} {
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
}
