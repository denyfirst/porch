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
	carriesList(t, "/organisation", page, promises.Organisation)

	// It names each product and sends a reader to that product's own page,
	// and it carries none of what a product adds. Until 2026-10-05 it carried
	// Porch's too, so a reader on Porch's name was sent to the organisation's
	// to find what Porch promises, and a second product's promises would have
	// been rendered by this repository's code.
	says := escapedIn(page)
	for _, product := range promises.Products {
		if !strings.Contains(page, product.Name) || !says(product.What) {
			t.Errorf("the page does not introduce %s", product.Name)
		}
		for _, p := range product.Adds {
			if says(p.Says) || strings.Contains(page, `id="`+p.ID+`"`) {
				t.Errorf("the organisation's page carries %s's %s, which is that product's word and on its own page", product.Name, p.ID)
			}
		}
	}
	if !strings.Contains(page, `href="`+porchBase()+undertakingsPath+`"`) {
		t.Errorf("the organisation's page does not lead to Porch's own undertakings at %s", porchBase()+undertakingsPath)
	}
}

// Porch's page carries Porch's undertakings, and links to the organisation's
// rather than repeating them.
func TestPorchsPageCarriesItsOwnUndertakings(t *testing.T) {
	page := get(t, undertakingsPath).Body.String()
	carriesList(t, undertakingsPath, page, promises.Porch.Adds)
	says := escapedIn(page)
	for _, p := range promises.Organisation {
		if says(p.Says) {
			t.Errorf("%s repeats the organisation's %s, which is on the organisation's page", undertakingsPath, p.ID)
		}
	}
	if !strings.Contains(page, `href="`+siteBase()+`/organisation"`) {
		t.Errorf("%s does not lead to the organisation's undertakings", undertakingsPath)
	}
}

// carriesList fails for every undertaking of list the page leaves out, says
// without saying how to check it, or gives no address to point at.
func carriesList(t *testing.T, path, page string, list []promises.Promise) {
	t.Helper()
	says := escapedIn(page)
	for _, p := range list {
		if !says(p.Says) {
			t.Errorf("%s does not say %s", path, p.ID)
		}
		if !says(p.Checked) {
			t.Errorf("%s says %s and not how to check it, which makes it a request to be trusted", path, p.ID)
		}
		// Each is addressable, so that somebody can point at one rather than
		// quote it.
		if !strings.Contains(page, `id="`+p.ID+`"`) {
			t.Errorf("%s: %s cannot be linked to", path, p.ID)
		}
	}
}

// escapedIn says whether page carries a sentence, compared escaped, the way
// the template writes it. An apostrophe reaches the page as &#39;, and
// comparing the raw sentence would fail on every undertaking that has one — a
// test that fails where nothing is wrong is a test somebody edits until it
// passes.
func escapedIn(page string) func(string) bool {
	return func(s string) bool { return strings.Contains(page, html.EscapeString(s)) }
}

// Whichever privacy page a visitor lands on sends them to the other question.
//
// The two questions are separate on purpose, which only works if a reader who
// arrived with the second one is told where it is answered. A split nobody is
// pointed across is a page that was hidden rather than separated — and this
// project's footer is deliberately three links long, so the pointer has to be
// in the prose where the question comes up.
func TestThePrivacyPageSendsAReaderToTheUndertakings(t *testing.T) {
	// To Porch's page, which carries the organisation's list as well as its
	// own, and is on the same name as the privacy page on the demonstration
	// and on an installation alike.
	page := get(t, "/privacy").Body.String()
	if !strings.Contains(page, `href="/undertakings"`) {
		t.Error("the privacy page does not say where the undertakings are")
	}

	// And the pointer is near the top, before the detail of what a scan does:
	// somebody who came to find out what the makers receive should not have to
	// read a page about port 443 first.
	lede, _, ok := strings.Cut(page, `<nav class="jump">`)
	if !ok {
		t.Fatal("the privacy page has no jump list, so where the top ends cannot be told")
	}
	if !strings.Contains(lede, `href="/undertakings"`) {
		t.Error("the pointer to the undertakings is below the jump list, where somebody asking that question will not see it")
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
		if !strings.Contains(top, `href="/undertakings"`) {
			t.Errorf("%s does not point a reader at the undertakings above its jump list", name)
		}
	}
}
