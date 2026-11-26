package web

import (
	"html"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/promises"
)

// Porch's privacy page carries Porch's promises, on both builds, and links to
// the organisation's rather than repeating them. The organisation's are
// denyfirst/site's since v0.37.0, written there and nowhere here, so the page
// cannot repeat them; it says where they are.
func TestPorchsPrivacyPageCarriesItsPromises(t *testing.T) {
	for name, page := range map[string]string{"served": string(rendered["/privacy"]), "demonstration": demoPrivacy(t)} {
		carriesList(t, name+" /privacy", page, promises.Porch.Adds)
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
