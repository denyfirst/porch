package web

import (
	"html"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/promises"
)

// The page about the organisation carries every undertaking, and every way of
// checking one.
//
// Rendered rather than read from the template, because what matters is what a
// visitor is given. A page that ranged over the wrong field, or stopped at the
// first entry, would leave the organisation making fewer promises than it has
// written down — and nothing else would notice.
func TestThePageAboutTheOrganisationCarriesEveryUndertaking(t *testing.T) {
	page := get(t, "/organisation").Body.String()

	// Compared escaped, the way the template writes it. An apostrophe reaches
	// the page as &#39;, and comparing the raw sentence would fail on every
	// undertaking that has one — a test that fails where nothing is wrong is a
	// test somebody edits until it passes.
	says := func(s string) bool { return strings.Contains(page, html.EscapeString(s)) }

	for _, p := range promises.Organisation {
		if !says(p.Says) {
			t.Errorf("the page does not say %s", p.ID)
		}
		if !says(p.Checked) {
			t.Errorf("the page says %s and not how to check it, which makes it a request to be trusted", p.ID)
		}
		// Each is addressable, so that somebody can point at one rather than
		// quote it.
		if !strings.Contains(page, `id="`+p.ID+`"`) {
			t.Errorf("%s cannot be linked to", p.ID)
		}
	}

	for _, product := range promises.Products {
		if !strings.Contains(page, product.Name) || !says(product.What) {
			t.Errorf("the page does not introduce %s", product.Name)
		}
		for _, p := range product.Adds {
			if !says(p.Says) || !says(p.Checked) {
				t.Errorf("the page does not carry %s's %s", product.Name, p.ID)
			}
		}
	}
}

// Whichever privacy page a visitor lands on sends them to the other question.
//
// The two questions are separate on purpose, which only works if a reader who
// arrived with the second one is told where it is answered. A split nobody is
// pointed across is a page that was hidden rather than separated — and this
// project's footer is deliberately three links long, so the pointer has to be
// in the prose where the question comes up.
func TestThePrivacyPageSendsAReaderToTheOrganisation(t *testing.T) {
	page := get(t, "/privacy").Body.String()
	if !strings.Contains(page, `href="/organisation"`) {
		t.Error("the privacy page does not say where the organisation's undertakings are")
	}

	// And the pointer is near the top, before the detail of what a scan does:
	// somebody who came to find out what the makers receive should not have to
	// read a page about port 443 first.
	lede, _, ok := strings.Cut(page, `<nav class="jump">`)
	if !ok {
		t.Fatal("the privacy page has no jump list, so where the top ends cannot be told")
	}
	if !strings.Contains(lede, `href="/organisation"`) {
		t.Error("the pointer to the organisation is below the jump list, where somebody asking that question will not see it")
	}

	// The whole of /docs lists every document, and this is one.
	if !strings.Contains(get(t, "/docs").Body.String(), `href="/organisation"`) {
		t.Error("/docs does not lead to the organisation's undertakings")
	}

	// Both privacy pages, read as templates rather than as whatever this build
	// happens to serve.
	//
	// There are two — one for the service and one for an installation somebody
	// runs — and a build serves exactly one of them, so everything above tested
	// half the site. A sabotage removed the pointer from the other half and
	// nothing failed. The demonstration's own tests run under a build tag, and a
	// guard that only fires there is a guard that fires on a minority of runs.
	for _, name := range []string{"assets/privacy.html", "assets/privacy-selfhost.html"} {
		body := asset(t, name)
		top, _, ok := strings.Cut(body, `<nav class="jump">`)
		if !ok {
			t.Errorf("%s has no jump list, so where its top ends cannot be told", name)
			continue
		}
		if !strings.Contains(top, `href="/organisation"`) {
			t.Errorf("%s does not point a reader at the organisation's undertakings above its jump list", name)
		}
	}
}
