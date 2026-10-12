//go:build !demo

package web

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// consoleAs renders the console for one configuration and puts the package
// back as it found it.
//
// Configure replaces a rendered page, which every other test in this package
// reads. Leaving it changed would make this file decide what those tests see.
func consoleAs(t *testing.T, verified bool) string {
	t.Helper()
	return workspaceWith(t, "/", verified)
}

// workspaceWith renders the workspace for one configuration, reads one of its
// pages, and puts every page Configure replaces back as it was.
func workspaceWith(t *testing.T, path string, verified bool) string {
	t.Helper()

	before := map[string][]byte{}
	for _, p := range []string{"/", "/privacy", "/domains", "/history", "/installation"} {
		before[p] = rendered[p]
	}
	t.Cleanup(func() {
		for p, body := range before {
			rendered[p] = body
		}
		delete(rendered, "/login")
		signedIn = false
	})

	Configure(Installation{Verified: verified})
	return flatten(get(t, path).Body.String())
}

// The console says what this installation actually is.
//
// The dangerous direction is one sentence: a page telling an operator that
// proof of control is required when it is not tells them their service is safe
// to expose when it is not. A sabotage hardcoding Verified escaped every test
// in this package on 2026-09-12, which is why this exists.
func TestTheConsoleSaysWhetherABoundaryIsConfigured(t *testing.T) {
	const open = "No proof of control is required"

	unbounded := consoleAs(t, false)
	if !strings.Contains(unbounded, open) {
		t.Errorf("an installation with no boundary does not say so. That is the sentence an "+
			"operator needs before putting this anywhere a stranger can reach:\n%s", unbounded)
	}

	bounded := consoleAs(t, true)
	if strings.Contains(bounded, open) {
		t.Errorf("an installation with a boundary is described as having none, which sends "+
			"somebody to look for a flag they already set:\n%s", bounded)
	}
	if !strings.Contains(bounded, "shown control of") {
		t.Errorf("an installation with a boundary does not say what it scans:\n%s", bounded)
	}
}

// What it says about pages follows from the same fact.
//
// internal/httpapi sets ReadMarkup from the verification scope, so a page that
// described the two independently could say the body is read on an
// installation that reads none — and a report silent about mixed content would
// then read as a site that has none (R4).
func TestTheConsoleSaysWhetherPagesAreRead(t *testing.T) {
	// On the page that describes the installation, beside the scope it follows.
	unbounded := workspaceWith(t, "/installation", false)
	if !strings.Contains(unbounded, "Not read") {
		t.Errorf("an installation that reads no page does not say so:\n%s", unbounded)
	}

	bounded := workspaceWith(t, "/installation", true)
	if strings.Contains(bounded, "Not read.") {
		t.Errorf("an installation that reads pages where control was proven says it reads "+
			"none:\n%s", bounded)
	}
}

// Every rule set this binary carries is offered as a check.
//
// Tested by existing rather than by a list somebody remembers to extend: a
// fourth check arrives with a fourth rule set, and the console has to grow a
// row for it or this fails. A check nobody can run from the page that exists to
// run them is a check nobody runs.
//
// A row that grades nothing is allowed, and it is held to saying so. The name
// inventory is one, and the only thing keeping a reader from mistaking it for
// a graded check is the word in the column where the others carry a version —
// so a row carrying neither a rule set in force nor that word fails here
// rather than reaching somebody who would read the blank as a pass (R4).
func TestTheConsoleOffersEveryCheckThisBinaryHas(t *testing.T) {
	page := consoleAs(t, false)

	inForce := []string{policy.TLSVersion, policy.WebVersion, policy.MailVersion, policy.DNSVersion}
	offered := consoleChecks()

	graded := 0
	for _, c := range offered {
		if c.Policy == policy.Informational {
			continue
		}
		graded++
	}
	if graded != len(inForce) {
		t.Fatalf("the console offers %d graded checks and this binary carries %d rule sets",
			graded, len(inForce))
	}

	for _, version := range inForce {
		found := false
		for _, c := range offered {
			if c.Policy == version {
				found = true
			}
		}
		if !found {
			t.Errorf("%s grades something and the console offers no check for it", version)
		}
		if !strings.Contains(page, version) {
			t.Errorf("the console does not name %s, so a reader cannot tell whether two reports "+
				"are comparable:\n%s", version, page)
		}
	}

	// Each row carries what the box means, because "Mail" alone does not say
	// what will be read — and each says either which rule set grades it or
	// that nothing does.
	for _, c := range offered {
		if c.ID == "" || c.Label == "" || c.Says == "" || c.Policy == "" {
			t.Errorf("the %q row is incomplete: %+v", c.Label, c)
		}
		if c.Policy != policy.Informational && !slices.Contains(inForce, c.Policy) {
			t.Errorf("the %s row carries %q, which is neither a rule set this binary grades by "+
				"nor a word saying it grades nothing", c.Label, c.Policy)
		}
		if !strings.Contains(page, c.Label) {
			t.Errorf("the console does not show the %s check", c.Label)
		}
	}
}

// The console never calls a run "full", "deep" or "active".
//
// docs/scope.md refuses those three words with an argument: each quietly
// authorises something this project has already declined to do, and the axis is
// named for whose network it is rather than for how hard the tool pushes. A
// control labelled "Full scan" would undo that argument in the one place a user
// actually looks.
func TestTheConsoleDoesNotPromiseMoreThanItDoes(t *testing.T) {
	page := strings.ToLower(consoleAs(t, false))

	for _, word := range []string{"full scan", "deep scan", "active scan", "penetration"} {
		if strings.Contains(page, word) {
			t.Errorf("the console offers a %q. docs/scope.md refuses that word, and the reason "+
				"is that it authorises something this tool does not do.", word)
		}
	}
}

// Every installation keeps its reports, sealed under its password, and says
// so where the operator looks: on the page that describes it, and on History.
//
// It said "Not kept" unless started with -results-dir until 2026-10-11, when a
// password became required everywhere and the plain store, which kept results
// in the clear, went with the last installation that could have used it.
func TestTheConsoleSaysResultsAreKeptSealed(t *testing.T) {
	installation := workspaceWith(t, "/installation", true)
	if !strings.Contains(installation, "Kept whole and encrypted") {
		t.Errorf("the installation page does not say how results are kept:\n%s", installation)
	}
	history := workspaceWith(t, "/history", true)
	if !strings.Contains(history, "Kept encrypted under a key your password seals") {
		t.Errorf("History does not say how its reports are kept:\n%s", history)
	}
}

// A kept result is served only through the gate.
//
// The History page is the bytes rendered at startup, before any check has
// run, so there is nothing in it to leak. Its list is fetched by the page,
// from an endpoint porchd puts behind the password; the web package serves
// no result at any path.
func TestAKeptResultIsNotServedOverHTTP(t *testing.T) {
	workspaceWith(t, "/", true)

	for _, path := range []string{"/results", "/api/v1/results", "/api/v1/history"} {
		if w := get(t, path); w.Code == http.StatusOK {
			t.Errorf("%s is served by the pages, and a history of an estate's weaknesses is "+
				"served only through the gate", path)
		}
	}
	w := get(t, "/history")
	if w.Code != http.StatusOK || w.Body.String() != string(rendered["/history"]) {
		t.Error("/history answers with something other than the page rendered when the program started")
	}
}

// The console names the tool in the tab and the page in its heading.
//
// It carried one heading, visually hidden, while the page was a field and
// the facts about the installation. In the workspace every part has a
// visible heading saying what it is for, and the tab still names the tool.
func TestTheConsoleSaysItsNameOnce(t *testing.T) {
	page := get(t, "/").Body.String()
	if !strings.Contains(page, "<title>"+ToolName+"</title>") {
		t.Errorf("the console's title is not the tool's name")
	}
	if n := strings.Count(page, "<h1"); n != 1 || !strings.Contains(page, "<h1>New check</h1>") {
		t.Errorf("the console has %d headings of the first rank, want one: New check", n)
	}
	if !strings.Contains(page, `<a class="rail-item" href="/" aria-current="page">`) {
		t.Error("the rail does not mark New check as the current page")
	}
}

// A self-hosted build has no front page and no Porch page: "/" is the tool.
func TestASelfHostedBuildServesNoMarketing(t *testing.T) {
	if w := get(t, "/porch"); w.Code != http.StatusNotFound {
		t.Errorf("/porch answered %d on a self-hosted build", w.Code)
	}
	if strings.Contains(get(t, "/").Body.String(), `id="products"`) {
		t.Error("the self-hosted root carries the front page")
	}
}

// Every check the console offers is one the script can run and draw, and every
// check is explained in docs/checks.md, which the script links.
//
// Three sabotages escaped the test above, which counts rows: dropping the
// fourth check from the script's order, dropping its card from the documents,
// and pointing that card somewhere else. A row nothing runs is worse than a
// missing row, because the page offers it.
func TestEveryCheckOfferedCanBeRunAndIsExplained(t *testing.T) {
	src := script(t)
	doc := checksDoc(t)

	// Every row, run here or opened elsewhere, is something the script can
	// draw and something the documents explain. A row on the list that no
	// page describes is a row a reader cannot act on.
	run := 0
	for _, c := range consoleChecks() {
		for _, want := range []string{
			`  ` + c.ID + `: {`,
			`endpoint: "/api/v1/` + c.ID + `/scan"`,
			`methodPage: CHECKS_DOC + "#` + c.ID + `"`,
		} {
			if !strings.Contains(src, want) {
				t.Errorf("the script has no %q for the %s check", want, c.ID)
			}
		}
		if !strings.Contains(strings.ToLower(doc), "## "+map[string]string{"tls": "tls", "web": "web", "mail": "mail", "dns": "dns", "names": "names"}[c.ID]) {
			t.Errorf("docs/checks.md has no section for the %s check", c.ID)
		}

		if c.Page != "" {
			// A door, not a box. It is not in the order the console runs,
			// deliberately: the console has no field for the input its page
			// takes, and a row that ran two thirds of itself here is what this
			// replaced.
			continue
		}
		run++
		if !strings.Contains(src, `"`+c.ID+`"`) {
			t.Errorf("the script never names the %s check", c.ID)
		}
	}

	// The order the console runs them in covers every box and invents none.
	order := strings.Index(src, "const CHECK_ORDER = [")
	if order < 0 {
		t.Fatal("the script no longer declares the order it runs checks in")
	}
	line := src[order : strings.Index(src[order:], "]")+order]
	for _, c := range consoleChecks() {
		if c.Page != "" {
			if strings.Contains(line, `"`+c.ID+`"`) {
				t.Errorf("CHECK_ORDER runs %s, which the console offers as a page of its own "+
					"because it cannot be fully run from here", c.ID)
			}
			continue
		}
		if !strings.Contains(line, `"`+c.ID+`"`) {
			t.Errorf("CHECK_ORDER leaves out %s, so the console offers a check it never runs", c.ID)
		}
	}
	if strings.Count(line, `"`) != 2*run {
		t.Errorf("CHECK_ORDER names something the console does not offer: %s", line)
	}
}

// The console offers the inventory as a door, not as a box.
//
// Three things in one test because they are one decision. It is on the list at
// all, so somebody who came to find out what they have got does not have to
// know a page exists. It is a link rather than a checkbox, because the console
// has no field for an address range: a box ran two thirds of the mode and
// reported the reverse walk as never asked, every time, with nothing on the
// page to do about it. And the column where the four checks carry a rule set
// carries a word instead, because a version there would promise two reports
// are comparable when nothing here was graded (R21).
func TestTheConsoleOffersTheInventoryAsADoorNotABox(t *testing.T) {
	var names *consoleCheck
	offered := consoleChecks()
	for i := range offered {
		if offered[i].ID == "names" {
			names = &offered[i]
		}
	}
	if names == nil {
		t.Fatal("the console offers no way to list the names under a domain")
	}
	if names.Page == "" {
		t.Error("the inventory is offered as a check, and the console has no field for a range")
	}
	if _, served := pages[names.Page]; !served {
		t.Errorf("the inventory row opens %q, which this build does not serve", names.Page)
	}
	if names.Policy != policy.Informational {
		t.Errorf("the inventory row carries %q where it should say it grades nothing", names.Policy)
	}

	// And the row that is drawn is the row the list describes: a link, with no
	// box in it for the form to submit.
	page := consoleAs(t, false)
	if !strings.Contains(page, `href="`+names.Page+`"`) {
		t.Errorf("the console draws no way to reach %s:\n%s", names.Page, page)
	}
	if strings.Contains(page, `value="names"`) {
		t.Error("the console still draws a checkbox for the inventory, which it cannot fully run")
	}
	if !strings.Contains(page, policy.Informational) {
		t.Errorf("the console never says the inventory is not graded:\n%s", page)
	}

	// And every row that is a check is still a box, because somebody who typed
	// a name into a scanner wants it scanned.
	for _, c := range offered {
		if c.Page != "" {
			continue
		}
		if !strings.Contains(page, `value="`+c.ID+`" checked`) {
			t.Errorf("the %s check is not offered ticked", c.Label)
		}
	}
}
