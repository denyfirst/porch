//go:build demo

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/policy"
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

// The demonstration offers the inventory the same way, and says what a copy
// somebody runs adds.
//
// The same door, for a different reason than the installation's. There the
// console has no field for an address range; here there is no field at all —
// the estate is compiled in (N6) — and every source beyond the two this
// deployment configures is one a visitor cannot switch on from a web page.
// Hiding that would be the version of this page that oversells: a report with
// four sources marked "not asked" and nothing saying where they can be asked
// reads as a tool that has four things it cannot do (N14).
func TestTheDemonstrationOffersTheInventoryAsADoor(t *testing.T) {
	var names *consoleCheck
	offered := consoleChecks()
	for i := range offered {
		if offered[i].ID == "names" {
			names = &offered[i]
		}
	}
	if names == nil {
		t.Fatal("the demonstration's check list has no inventory row")
	}
	if names.Page == "" {
		t.Error("the demonstration offers the inventory as a box, and its form has no target field")
	}
	if names.Policy != policy.Informational {
		t.Errorf("the inventory row carries %q where it should say it grades nothing", names.Policy)
	}

	page := get(t, "/porch").Body.String()
	if !strings.Contains(page, `href="`+names.Page+`"`) {
		t.Errorf("the demonstration draws no way to reach %s", names.Page)
	}
	if strings.Contains(page, `value="names"`) {
		t.Error("the demonstration draws a checkbox for the inventory beside a fixed host list")
	}

	// And the report says where the sources it does not use can be used. Not a
	// list of them, which would be a second place to keep in step with what is
	// configured — a sentence pointing at the lines the report already draws.
	src := script(t)
	if !strings.Contains(src, "DEMO_SITE") {
		t.Fatal("the script no longer knows which deployment it is on")
	}
	limits := functionBody(t, src, "namesLimits")
	if !strings.Contains(limits, "DEMO_SITE") {
		t.Error("the demonstration's inventory never says that a copy you run reads more sources")
	}
}
