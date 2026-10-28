//go:build !demo

package web

import (
	"strings"
	"testing"
)

// Domains offers to add one, and to prove it: every installation requires
// proof.
func TestDomainsOffersAProof(t *testing.T) {
	proved := workspaceWith(t, "/domains")
	if !strings.Contains(proved, `id="domain-form"`) || !strings.Contains(proved, ">Add domain</button>") {
		t.Error("Domains offers no way to add a domain")
	}
}

// The privacy page says where the clipboard is written, because it is.
func TestThePrivacyPageSaysWhatIsCopied(t *testing.T) {
	page := workspaceWith(t, "/privacy")
	if strings.Contains(page, "Nothing is written to the clipboard") {
		t.Error("the privacy page says nothing is copied, and the Copy button beside a record copies it")
	}
	if !strings.Contains(page, "A report is never put there") {
		t.Error("the privacy page does not say a report stays out of the clipboard")
	}
}

// The privacy page names the servers a proof is read from, because they are
// asked directly now.
//
// Until 2026-09-29 the resolver asked them, and they saw the resolver's
// address. The proof is read from the root down since then, so the root, the
// top-level domain and the domain's own servers see this installation's — and
// a page listing who else is asked has to say so.
func TestThePrivacyPageSaysWhoAProofIsReadFrom(t *testing.T) {
	proved := workspaceWith(t, "/privacy")
	for _, want := range []string{"The domain's own name servers", "reached from the root", "this machine's address"} {
		if !strings.Contains(proved, want) {
			t.Errorf("the privacy page of an installation that requires proof does not say %q", want)
		}
	}
}

// New check and Names choose from the domains added under Domains rather than
// taking a typed one, and say where one is added when there is none.
//
// The list is read from the installation's own sealed list as the page opens,
// and nothing asks DNS to draw it: whether a domain is proven is asked by the
// check when it runs, which the service decides whatever the page sent. So
// the picker is a convenience over a boundary that is enforced elsewhere, and
// these hold its shape: the one value each form sends is a field the script
// fills, every door to adding a domain goes to Domains, and what cannot run
// without a domain is marked so the script can hide it.
func TestTheDomainIsChosenNotTyped(t *testing.T) {
	console := workspaceWith(t, "/")
	names := workspaceWith(t, "/names")

	for page, body := range map[string]string{"New check": console, "Names": names} {
		for _, want := range []string{
			`id="domain-choices"`,
			`<a class="check check-elsewhere domain-add" href="/domains">`,
			`id="domain-empty" hidden`,
			`<a class="submit domain-go" href="/domains">Go to Domains</a>`,
			`id="domain-status" role="status"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not carry %s", page, want)
			}
		}
	}

	if !strings.Contains(console, `<input type="hidden" id="console-target" name="target">`) {
		t.Error("New check still takes a typed domain")
	}
	if !strings.Contains(console, `<legend class="composer-step">01 / Domain</legend>`) || !strings.Contains(console, `id="console-host"`) {
		t.Error("New check does not offer a host under the chosen domain")
	}
	for _, needs := range []string{`<fieldset class="composer-part checks" data-needs-domain>`, `<div class="report-empty" id="report-empty" data-needs-domain>`} {
		if !strings.Contains(console, needs) {
			t.Errorf("New check does not mark %s as needing a domain", needs)
		}
	}

	if !strings.Contains(names, `<input type="hidden" id="target" name="target">`) {
		t.Error("Names still takes a typed domain")
	}
	if strings.Contains(names, `id="console-host"`) || strings.Contains(names, "host-row") {
		t.Error("Names offers a host, and the inventory is about the whole domain")
	}
	if n := strings.Count(names, "data-needs-domain"); n != 4 {
		t.Errorf("Names marks %d parts as needing a domain: the run button, its help, the ranges and the names", n)
	}

	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(script)
	_, load, found := strings.Cut(source, "async function loadDomainChoices(")
	if !found {
		t.Fatal("app.js does not load the domain choices")
	}
	load, _, _ = strings.Cut(load, "\n}\n")
	if !strings.Contains(load, `domainRequest("GET", "/api/v1/domains")`) {
		t.Error("the choices are not read from the installation's own list")
	}
	for _, never := range []string{"VERIFY", "check(", "innerHTML"} {
		if strings.Contains(load, never) {
			t.Errorf("drawing the choices uses %s; it should ask nothing of DNS and build no markup from a string", never)
		}
	}

	sheet, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sheet), ".domain-grid[hidden], .domain-empty[hidden], .domain-status[hidden], [data-needs-domain][hidden] { display: none; }") {
		t.Error("what the script hides can still be drawn, by a rule that outranks the attribute")
	}
}
