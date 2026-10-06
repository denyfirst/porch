//go:build demo

package web

import (
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// What a visitor to denyfirst.dev is given.
//
// The deployment connects only to hosts this project owns, so the page offers
// what there is rather than a field that mostly answers no. A control that
// invites a request the server will refuse is a page arguing with its own
// server, and the visitor is the one who loses.
func TestTheDemonstrationPageOffersWhatItCanScan(t *testing.T) {
	page := get(t, "/tls").Body.String()

	if !strings.Contains(page, `<select`) {
		t.Error("the demonstration page still offers a free-text field")
	}
	if strings.Contains(page, `type="text"`) {
		t.Error("the demonstration page carries a text field it cannot answer")
	}

	hosts := demo.Hosts()
	if len(hosts) == 0 {
		t.Fatal("the demonstration page has nothing to offer")
	}
	for _, h := range hosts {
		if !strings.Contains(page, `value="`+h.Host+`"`) {
			t.Errorf("the page does not offer %s, which the deployment can scan", h.Host)
		}
		if !strings.Contains(page, h.Shows) {
			t.Errorf("the page offers %s and does not say what it shows", h.Host)
		}
	}

	// The script reads one id, so the two deployments share one script and
	// there is no branch in it to go stale.
	if !strings.Contains(page, `id="target"`) {
		t.Error("the control the script reads is not on the page")
	}
}

// The page says what this deployment is, and where the tool is.
//
// A visitor who is offered two hosts and no explanation reads a crippled
// service. What they are looking at is a demonstration of a tool they are
// meant to run themselves, and the page has to say so at the moment they
// notice the limit — which is at the control, not in the footer.
func TestTheDemonstrationPageSaysWhatItIsAndWhereTheToolIs(t *testing.T) {
	page := get(t, "/tls").Body.String()

	for _, want := range []string{
		"scans only hosts this project owns",
		"Run it yourself",
		"docs/self-host.md",
		"leaves your machine",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the demonstration page does not say %q", want)
		}
	}
}

// The demonstration serves its own privacy page, written about the machine
// this project runs, and never the self-hosted one (audit A21).
func TestTheDemonstrationKeepsItsOwnPrivacyPage(t *testing.T) {
	page := get(t, "/privacy").Body.String()
	if !strings.Contains(page, "abuse@denyfirst.dev") || strings.Contains(page, "What this installation keeps") {
		t.Error("the demonstration does not serve its own privacy page")
	}
	Configure(Installation{Verified: true, Keeps: true})
	if strings.Contains(get(t, "/privacy").Body.String(), "What this installation keeps") {
		t.Error("configuring the demonstration replaced its privacy page")
	}
	if root := get(t, "/").Body.String(); strings.Contains(root, `id="console-form"`) || !strings.Contains(root, `id="products"`) {
		t.Error("configuring the demonstration replaced its front page with the console")
	}
}

// The Porch page offers what the demonstration can check, every check this
// binary has, and runs them from the page.
func TestThePorchPageRunsEveryCheckOnTheHostsItOffers(t *testing.T) {
	page := get(t, "/porch").Body.String()
	hosts := demo.Hosts()
	for _, h := range hosts {
		offered := strings.Contains(page, `<option value="`+h.Host+`">`)
		if len(hosts) == 1 {
			offered = strings.Contains(page, `<input type="hidden" id="porch-target" name="target" value="`+h.Host+`">`)
		}
		if !offered {
			t.Errorf("the Porch page does not offer %s", h.Host)
		}
	}
	// A menu with one entry is an arrow that opens onto nothing.
	if menu := strings.Contains(page, `<select`); menu != (len(hosts) > 1) {
		t.Errorf("the Porch page draws a menu: %v, for %d hosts", menu, len(hosts))
	}
	if strings.Contains(page, `type="text"`) {
		t.Error("the Porch page offers a free-text field the deployment cannot answer")
	}
	for _, c := range consoleChecks() {
		// A row that opens a page of its own is drawn as that link rather than
		// as a box: the name inventory takes inputs this form does not have,
		// and a ticked box that ran two thirds of it is what the link replaced.
		if c.Page != "" {
			if !strings.Contains(page, `href="`+c.Page+`"`) {
				t.Errorf("the Porch page does not reach %s, so %s is offered and cannot be opened",
					c.Page, c.Label)
			}
			continue
		}
		if !strings.Contains(page, `value="`+c.ID+`" checked`) {
			t.Errorf("the Porch page does not offer the %s check", c.Label)
		}
	}
	if !strings.Contains(page, `<script src="/app.js"></script>`) || !strings.Contains(page, `id="porch-results"`) {
		t.Error("the Porch page cannot run or show a check")
	}
}

// The front page claims nothing about a product that is not available.
func TestTheFrontPageSaysWhatIsNotAvailable(t *testing.T) {
	page := get(t, "/").Body.String()
	if strings.Contains(page, `<script src="/app.js">`) {
		t.Error("the front page loads the check script, and runs no check")
	}
	if strings.Count(page, `class="badge badge-live"`) != 1 {
		t.Error("more or fewer than one offering is marked available")
	}
	if !strings.Contains(page, "not available yet, and no date is promised.") {
		t.Error("the front page does not say its planned offerings are not available")
	}
}

// The catalogue names the products that exist, and the menu agrees with it.
//
// The card and the entry in the Products menu are written in two files, and
// until 2026-09-24 they named a product that was never started while the one
// being built was not mentioned anywhere. A catalogue that is wrong about what
// a company is making is the first thing a reader can check and the first
// thing they find wrong.
func TestTheCatalogueAndTheMenuNameTheSameProducts(t *testing.T) {
	front := get(t, "/").Body.String()

	// Porch's card carries Porch's mark, as Porch's own header draws it.
	if !strings.Contains(front, `<h3 class="product-feature-name">porch<span class="wordmark-porch-stop">.</span></h3>`) {
		t.Error("the front page's card does not name Porch by its mark")
	}
	if !strings.Contains(front, "<h3>Rootwell</h3>") {
		t.Error("the front page does not name Rootwell")
	}
	if strings.Contains(front, "Porch Elite") {
		t.Error("the front page still names a product that was replaced")
	}

	// The menu is on every page, so one page is enough to read it, and it says
	// the same thing about what is being built.
	if !strings.Contains(front, `<span class="nav-menu-name">Porch</span>`) {
		t.Error("the products menu does not name Porch")
	}
	if !strings.Contains(front, `<span class="nav-menu-name">Rootwell</span><span class="nav-menu-note">Being built</span>`) {
		t.Error("the products menu does not name Rootwell as being built")
	}
}

// A kept report says how old it is on the page, as a kept inventory does. The
// demonstration hands each check's report to everybody for an hour, and a copy
// without its age would read as a measurement of now.
func TestTheDemonstrationSaysHowOldAKeptReportIs(t *testing.T) {
	src := script(t)
	body := functionBody(t, src, "summary")
	if !strings.Contains(body, "data.producedAt") || !strings.Contains(body, "producedAt(data.producedAt)") {
		t.Error("the summary does not say when a kept report was made")
	}
}

// The front page tells a reporter where to write and which key to check, and
// the fingerprint it shows is the one the key file has.
func TestTheFrontPageSaysHowToReportAVulnerability(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	page := get(t, "/").Body.String()
	for _, want := range []string{
		`id="security"`,
		`href="mailto:security@denyfirst.dev"`,
		"<code>" + groupedFingerprint(PGPFingerprint) + "</code>",
		`href="` + PGPKeyPath + `"`,
		`href="` + SecurityTxtPath + `"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the front page's security section does not carry %s", want)
		}
	}
	if got := groupedFingerprint("75B7A18A89715E3775DBCA2EA8D994D1221AA045"); got != "75B7 A18A 8971 5E37 75DB  CA2E A8D9 94D1 221A A045" {
		t.Errorf("the fingerprint is grouped as %q, not as gpg prints it", got)
	}
}

// Each of the front page's three rules says how a reader checks it, and the
// one that points at a document points at the one that exists.
//
// A rule with nothing beside it is a claim; the section was rebuilt on
// 2026-10-06 so that each one carries its proof, and this keeps it that way.
func TestEachRuleOnTheFrontPageSaysHowToCheckIt(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	page := get(t, "/").Body.String()
	_, rules, ok := strings.Cut(page, `<ol class="rules">`)
	if !ok {
		t.Fatal("the front page has no list of rules")
	}
	rules, _, _ = strings.Cut(rules, "</ol>")
	if n := strings.Count(rules, "<li>"); n != 3 {
		t.Errorf("the front page lists %d rules, and says it has three", n)
	}
	if n := strings.Count(rules, `<span class="rule-proof-label">How you check it</span>`); n != 3 {
		t.Errorf("%d of the rules say how to check them, not all three", n)
	}
	if !strings.Contains(rules, `href="`+ChecksURL+`"`) {
		t.Error("the rule about scope does not link the document that lists every connection")
	}
}

// The facts under the opening and the lines on the team's card are true of
// this site and this repository, and each line that can link the file that
// shows it does.
//
// "001 — denyfirst" stood there until 2026-10-06: a serial number that meant
// nothing and that a reader asked about. What replaced it is checkable, so it
// is checked. The card names nobody; it says how the team is known instead,
// by the key that signs every release, and that key has to be the one the
// verification guide tells a reader to expect.
func TestTheFrontPagesFactsHold(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	res := get(t, "/")
	if res.Header().Get("Set-Cookie") != "" {
		t.Error("the front page says it sets no cookies, and sets one")
	}
	page := res.Body.String()
	for _, want := range []string{"<span>No cookies</span>", "<span>No trackers</span>", "<span>Open source</span>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the opening does not say %s", want)
		}
	}

	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatalf("the front page links %s, which is not in the repository: %v", name, err)
		}
		return string(body)
	}
	const repo = "https://github.com/denyfirst/porch/blob/main/"
	const key = "SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y"
	for _, line := range []struct{ term, file, says string }{
		{"Known by", "docs/verify.md", "<code>" + key + "</code>"},
		{"Releases", "docs/verify.md", "Signed and reproducible"},
		{"Licence", "LICENSE", "AGPL-3.0"},
		{"Dependencies", "go.mod", "None"},
	} {
		want := "<dt>" + line.term + `</dt><dd><a href="` + repo + line.file + `">` + line.says + "</a></dd>"
		if !strings.Contains(page, want) {
			t.Errorf("the team's card does not say %s", want)
		}
		read(line.file)
	}
	if !strings.Contains(page, "<dt>Investors</dt><dd>None</dd>") {
		t.Error("the team's card does not say it has no investors")
	}

	verify := read("docs/verify.md")
	if !strings.Contains(verify, "Good \"file\" signature for releases@denyfirst.dev with ED25519 key "+key) {
		t.Error("the key on the team's card is not the one the verification guide expects")
	}
	if !strings.Contains(verify, "Builds are reproducible.") {
		t.Error("docs/verify.md no longer says how a release is rebuilt")
	}
	if licence := read("LICENSE"); !strings.Contains(licence, "GNU AFFERO GENERAL PUBLIC LICENSE") || !strings.Contains(licence, "Version 3") {
		t.Error("the licence is not the AGPL-3.0 the card names")
	}
	if strings.Contains(read("go.mod"), "require") {
		t.Error("go.mod requires a module, and the card says there are no dependencies")
	}
	if !strings.Contains(strings.Join(strings.Fields(read("SECURITY.md")), " "), "This is an unfunded project") {
		t.Error("SECURITY.md no longer says the project is unfunded, and the card says it has no investors")
	}
}
