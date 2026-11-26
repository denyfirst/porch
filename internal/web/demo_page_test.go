//go:build demo

package web

import (
	"net/http"
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
	Configure(Installation{})
	if strings.Contains(get(t, "/privacy").Body.String(), "What this installation keeps") {
		t.Error("configuring the demonstration replaced its privacy page")
	}
	if root := get(t, "/").Body.String(); strings.Contains(root, `id="console-form"`) || !strings.Contains(root, `id="porch-form"`) {
		t.Error("configuring the demonstration replaced its front page with the console")
	}
}

// The Porch page offers what the demonstration can check, every check this
// binary has, and runs them from the page.
func TestThePorchPageRunsEveryCheckOnTheHostsItOffers(t *testing.T) {
	page := get(t, "/").Body.String()
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

// The footer's Security link leads to where a report about Porch is made.
//
// Until 2026-10-07 both names led to a band on Porch's page, which sent the
// organisation's visitors to a product's page for the organisation's
// contacts. Porch's pages lead to the policy on GitHub, where its private
// reporting is; denyfirst.dev's, served by denyfirst/site since v0.37.0, to
// its own security.txt.
func TestTheSecurityLinkLeadsToTheContacts(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the footers' Security links are the demonstration's")
	}
	footer := func(body string) string {
		_, foot, _ := strings.Cut(body, `<footer class="colophon">`)
		return foot
	}
	porch := getOn(t, http.MethodGet, porchHost, "/").Body.String()
	if !strings.Contains(footer(porch), `<a href="https://github.com/denyfirst/porch/blob/main/SECURITY.md">Security</a>`) {
		t.Error("Porch's footer does not lead to the security policy")
	}
	if strings.Contains(porch, `id="security"`) {
		t.Error("Porch's page still carries a security band the footer no longer leads to")
	}
}

// The end of Porch's page compares it with an online scanner and answers six
// questions, and each claim there is held to the document it names.
//
// An answer on a page that sells a tool is the easiest place to say a little
// more than is true, so every card links its source and each source is read
// here for the sentence the card stands on. The comparison says plainly what
// Porch does tell third parties, because "only you" was first written about
// the domains and is not true of them: a scan asks Cert Spotter and the
// certificate's authority about a proven domain. The key a reporter encrypts to is the one SECURITY.md publishes,
// and the card says to compare the two, since whoever took the domain could
// serve a key of their own beside a page that says it is ours.
func TestPorchsComparisonAndAnswersHold(t *testing.T) {
	if !demo.Enabled {
		t.Skip("Porch's page is the demonstration's")
	}
	page := getOn(t, http.MethodGet, porchHost, "/").Body.String()

	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatalf("Porch's page cites %s, which is not in the repository: %v", name, err)
		}
		return strings.Join(strings.Fields(string(body)), " ")
	}
	band := func(id string) string {
		t.Helper()
		_, rest, ok := strings.Cut(page, `id="`+id+`"`)
		if !ok {
			t.Fatalf("Porch's page has no %s band", id)
		}
		rest, _, _ = strings.Cut(rest, "</section>")
		return rest
	}

	compare := band("compare")
	rows := strings.Count(compare, "<dt>")
	if rows != 6 || strings.Count(compare, `<dd class="tape-porch"><span class="visually-hidden">Porch: </span>`) != rows ||
		strings.Count(compare, `<dd class="tape-scanner"><span class="visually-hidden">An online scanner: </span>`) != rows {
		t.Error("a row of the comparison does not tell a screen reader which side each answer is on")
	}
	if !strings.Contains(compare, "<dt>Who sees the results</dt>") || strings.Contains(compare, "your domains</dt>") {
		t.Error("the comparison says who sees the domains, and Cert Spotter is asked about each one")
	}
	checks := read("docs/checks.md")
	for _, says := range []string{"Cert Spotter", "revocation list"} {
		if !strings.Contains(compare, says) || !strings.Contains(checks, says) {
			t.Errorf("the comparison and docs/checks.md do not both say what a scan asks of %s", says)
		}
	}

	questions := band("questions")
	const repo = `<a href="https://github.com/denyfirst/porch/blob/main/`
	answers := strings.Split(questions, `<article class="answer">`)[1:]
	if len(answers) != 6 {
		t.Fatalf("Porch's page answers %d questions, and says six", len(answers))
	}
	for _, a := range answers {
		_, src, ok := strings.Cut(a, `<p class="answer-source"><span>Source</span> `+repo)
		name, _, _ := strings.Cut(src, `"`)
		if !ok || !strings.Contains(a, `<p class="answer-short">`) {
			t.Errorf("an answer gives no short answer or names no source: %.80q", a)
			continue
		}
		read(name)
	}

	key := "SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y"
	for _, claim := range []struct{ card, file, says string }{
		{"No account with us, no telemetry.", "docs/self-host.md", "There is no account, no telemetry"},
		{"the proof is read again on every scan", "docs/scope.md", "It is re-read every time."},
		{"every web request names Porch", "docs/checks.md", "Every request carries the user agent"},
		{"The command line also runs on macOS and Windows.", "README.md", "for Linux, macOS and Windows"},
		{`<code class="answer-key">` + key + `</code>`, "docs/verify.md", "with ED25519 key " + key},
		{"Open source under AGPL-3.0.", "LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE"},
		{"Anonymous and pseudonymous reports are accepted without question.", "SECURITY.md", "Anonymous and pseudonymous reports are accepted without question."},
		{"There is no bug bounty.", "SECURITY.md", "There is no bug bounty."},
	} {
		if !strings.Contains(questions, claim.card) {
			t.Errorf("Porch's page no longer says %q", claim.card)
		}
		if !strings.Contains(read(claim.file), claim.says) {
			t.Errorf("%s no longer says %q, which Porch's page stands on", claim.file, claim.says)
		}
	}
	if !strings.Contains(page, `<code class="key-fingerprint">`+key+`</code>`) {
		t.Error("the key in the answers is not the one step 2 checks the signature with")
	}

	_, disclosure, _ := strings.Cut(questions, `<div class="disclosure">`)
	for _, want := range []string{
		`href="https://github.com/denyfirst/porch/security/advisories/new"`,
		`href="mailto:security@denyfirst.dev"`,
		`<a href="https://github.com/denyfirst/porch/blob/main/SECURITY.md">SECURITY.md on GitHub</a>`,
	} {
		if !strings.Contains(disclosure, want) {
			t.Errorf("the vulnerability card does not carry %s", want)
		}
	}
	_, shown, _ := strings.Cut(disclosure, "<code>")
	shown, _, _ = strings.Cut(shown, "</code>")
	grouped := strings.ReplaceAll(shown, "&nbsp;", " ")
	if strings.ReplaceAll(grouped, " ", "") != PGPFingerprint {
		t.Errorf("the vulnerability card shows the key %q, and the key served is %s", grouped, PGPFingerprint)
	}
	read("SECURITY.md")
	if policy, _ := os.ReadFile("../../SECURITY.md"); !strings.Contains(string(policy), grouped) {
		t.Errorf("SECURITY.md does not publish %q, so the comparison the card asks for fails", grouped)
	}
}
