package web

import (
	"html"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/promises"
)

// denyfirst.dev/privacy carries every one of the organisation's promises,
// and every way of checking one, and none of a product's.
//
// Rendered rather than read from the template, because what matters is what a
// visitor is given.
func TestTheOrganisationsPrivacyPageCarriesEveryPromise(t *testing.T) {
	if !demo.Enabled {
		t.Skip("an installation is Porch alone, and links to denyfirst.dev/privacy")
	}
	page := getOn(t, "GET", organisationHost, "/privacy").Body.String()
	carriesList(t, "denyfirst.dev/privacy", page, promises.Organisation)

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
	if !strings.Contains(page, `href="`+PorchURL+`/privacy#promises"`) {
		t.Error("the organisation's page does not lead to Porch's own promises")
	}
	for _, fact := range []string{"No cookies", "no analytics", "Hetzner Online GmbH"} {
		if !strings.Contains(page, fact) {
			t.Errorf("the organisation's page does not say %q about this site", fact)
		}
	}
}

// Porch's privacy page carries Porch's promises, on both builds, and links to
// the organisation's rather than repeating them.
func TestPorchsPrivacyPageCarriesItsPromises(t *testing.T) {
	for name, page := range map[string]string{"served": string(rendered["/privacy"]), "demonstration": demoPrivacy(t)} {
		carriesList(t, name+" /privacy", page, promises.Porch.Adds)
		says := escapedIn(page)
		for _, p := range promises.Organisation {
			if says(p.Says) {
				t.Errorf("the %s privacy page repeats the organisation's %s", name, p.ID)
			}
		}
		if !strings.Contains(page, `href="https://denyfirst.dev/privacy"`) {
			t.Errorf("the %s privacy page does not lead to the organisation's promises", name)
		}
		// First in the jump list, so somebody asking what the makers promise
		// does not read about port 443 first.
		_, jump, _ := strings.Cut(page, `<nav class="jump">`)
		if !strings.HasPrefix(strings.TrimSpace(jump), `<a href="#promises">`) {
			t.Errorf("the %s privacy page's jump list does not begin with the promises", name)
		}
	}
	// The old address of Porch's promises leads to them.
	w := get(t, "/undertakings")
	if w.Code != 301 || w.Header().Get("Location") != "/privacy#promises" {
		t.Errorf("GET /undertakings: %d to %q", w.Code, w.Header().Get("Location"))
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
