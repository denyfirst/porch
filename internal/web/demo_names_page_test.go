//go:build demo

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// The demonstration offers the name inventory, and only for its own estate.
//
// Both pages were deleted here until 2026-09-27, on the ground that this
// deployment queries no transparency log. That promise was written when the
// demonstration scanned whatever it was given, and then it protected somebody:
// a visitor's domain would have been named to a monitor. The hosts this build
// may touch are compiled in, so there is no visitor's domain to protect — and
// what the deletion cost was the demonstration of the one mode that reads
// several sources and says which named what.
//
// What the deletion was right about is an open field on a page that then
// refuses. So the field is fixed to the estate this deployment owns, which is
// read from the compiled-in boundary rather than written again beside it.
func TestTheDemonstrationListsItsOwnEstate(t *testing.T) {
	for _, path := range []string{"/names", "/names/method"} {
		w := get(t, path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s on the demonstration returned %d, want 200", path, w.Code)
		}
	}

	domain := demo.Targets()[0]
	page := get(t, "/names").Body.String()

	if !strings.Contains(page, domain) {
		t.Errorf("the page does not name the estate it lists (%s)", domain)
	}
	if !strings.Contains(page, "readonly") {
		t.Error("the field a visitor types into is open on a page that would refuse anything else")
	}
	if !strings.Contains(page, "Run the tool") {
		t.Error("the page does not tell a visitor how to list their own estate")
	}

	// And it does not keep the sentence written for an installation somebody
	// runs themselves, which promises proof of control for a domain the
	// visitor cannot type here.
	if strings.Contains(page, "a domain you have proven control of") {
		t.Error("the demonstration page asks a visitor to prove control of this project's domain")
	}
}
