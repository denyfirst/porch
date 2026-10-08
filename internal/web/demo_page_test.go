//go:build demo

package web

import (
	"net/http"
	"os"
	"regexp"
	"strconv"
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

// The footer's Security link leads to where a report is made, on the site
// that answers for it.
//
// Until 2026-10-07 both names led to a band on Porch's page, which sent the
// organisation's visitors to a product's page for the organisation's
// contacts. denyfirst.dev's leads to its own security.txt (RFC 9116), which
// names the address, the key and the policy; Porch's pages lead to the policy
// on GitHub, where its private reporting is.
func TestTheSecurityLinkLeadsToTheContacts(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the footers' Security links are the demonstration's")
	}
	footer := func(body string) string {
		_, foot, _ := strings.Cut(body, `<footer class="colophon">`)
		return foot
	}
	front := footer(getOn(t, http.MethodGet, organisationHost, "/").Body.String())
	if !strings.Contains(front, `<a href="`+SiteURL+SecurityTxtPath+`">Security</a>`) {
		t.Error("denyfirst.dev's footer does not lead to its security.txt")
	}
	txt := getOn(t, http.MethodGet, organisationHost, SecurityTxtPath)
	for _, want := range []string{"Contact: mailto:security@denyfirst.dev", "Encryption: " + SiteURL + PGPKeyPath, "Policy: https://github.com/denyfirst/porch/blob/main/SECURITY.md"} {
		if txt.Code != http.StatusOK || !strings.Contains(txt.Body.String(), want) {
			t.Errorf("the security.txt the footer leads to does not say %s", want)
		}
	}
	porch := getOn(t, http.MethodGet, porchHost, "/").Body.String()
	if !strings.Contains(footer(porch), `<a href="https://github.com/denyfirst/porch/blob/main/SECURITY.md">Security</a>`) {
		t.Error("Porch's footer does not lead to the security policy")
	}
	if strings.Contains(porch, `id="security"`) {
		t.Error("Porch's page still carries a security band the footer no longer leads to")
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

// The index under the opening leads to every section, in order, and the lines
// on the team's card are true of this site and this repository, each line
// that can link the file that shows it doing so.
//
// The opening's foot said "No cookies, No trackers, Open source" until
// 2026-10-08, beside a policy that says each of them; the policy test holds
// those now, and the foot names the page's sections instead.
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
	_, index, ok := strings.Cut(page, `<nav class="hero-index" aria-label="On this page">`)
	if !ok {
		t.Fatal("the opening has no index of the page")
	}
	index, _, _ = strings.Cut(index, "</nav>")
	at := 0
	for i, section := range []struct{ id, name string }{
		{"products", "Products"}, {"principles", "How we work"}, {"releases", "Releases"},
		{"about", "The team"}, {"this-visit", "This visit"},
	} {
		n := strconv.Itoa(i + 1)
		link := `<a href="#` + section.id + `"><span>0` + n + `</span> ` + section.name + `</a>`
		if !strings.Contains(index, link) {
			t.Errorf("the index does not lead to %s", link)
		}
		head := `id="` + section.id + `"`
		where := strings.Index(page, head)
		if where < at {
			t.Errorf("section %s is missing, or out of the index's order", section.id)
			continue
		}
		at = where
		if _, rest, _ := strings.Cut(page[where:], `<p class="eyebrow">`); !strings.HasPrefix(rest, "0"+n+" / "+section.name+"</p>") {
			t.Errorf("section %s is not numbered %s / %s, as the index says", section.id, "0"+n, section.name)
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

// The front page's receipt says what the visit took, and every line is true of
// the responses that make it up.
//
// A reader is told to check each line in their browser's network panel, so
// each is checked here against what this server sends: the headers on the
// page and on every file it loads, and the files themselves.
func TestTheReceiptIsTrue(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	w := getOn(t, http.MethodGet, organisationHost, "/")
	page := w.Body.String()

	_, slip, _ := strings.Cut(page, `<article class="slip"`)
	slip, _, _ = strings.Cut(slip, "</article>")
	rows := map[string]string{}
	for _, m := range regexp.MustCompile(`<div><dt>([^<]+)</dt><dd>([^<]+)</dd></div>`).FindAllStringSubmatch(slip, -1) {
		rows[m[1]] = m[2]
	}
	want := map[string]string{
		"Cookies set": "0", "Trackers": "0", "Other servers asked": "0", "Files loaded": "6",
		"Kept in your cache": "0", "Told to the next site": "nothing",
		"Recorded about you": "nothing", "Total collected": "0",
	}
	if len(rows) != len(want) {
		t.Errorf("the receipt has %d lines, want %d: %v", len(rows), len(want), rows)
	}
	for line, want := range want {
		if rows[line] != want {
			t.Errorf("the receipt says %s %q, want %q", line, rows[line], want)
		}
	}

	// Files loaded: the page, what its head and body ask for, and one icon of
	// the several it offers, since a browser fetches the one it prefers.
	var loads []string
	for _, pattern := range []string{`<link rel="stylesheet" href="([^"]+)"`, `<link rel="preload" href="([^"]+)"`, `<script src="([^"]+)"`} {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(page, -1) {
			loads = append(loads, m[1])
		}
	}
	icons := regexp.MustCompile(`<link rel="(?:icon|apple-touch-icon)" href="([^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(icons) == 0 {
		t.Fatal("the front page links no icon")
	}
	if got := strconv.Itoa(1 + len(loads) + 1); got != rows["Files loaded"] {
		t.Errorf("the page loads %s files, and the receipt says %s: %v", got, rows["Files loaded"], loads)
	}

	// Every one of them from this site, without a cookie, and not kept.
	for _, m := range icons {
		loads = append(loads, m[1])
	}
	for _, path := range append([]string{"/"}, loads...) {
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			t.Errorf("the front page loads %s, which is not this site", path)
			continue
		}
		r := getOn(t, http.MethodGet, organisationHost, path)
		if r.Code != http.StatusOK {
			t.Errorf("%s answers %d", path, r.Code)
		}
		if c := r.Header().Get("Set-Cookie"); c != "" {
			t.Errorf("%s sets a cookie: %s", path, c)
		}
		if c := r.Header().Get("Cache-Control"); c != "no-store" {
			t.Errorf("%s may be kept: Cache-Control %q", path, c)
		}
	}

	// Other servers asked, and trackers: the policy lets the browser reach
	// this site and nothing else.
	for _, directive := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
		fields := strings.Fields(directive)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], "-src") {
			continue
		}
		for _, source := range fields[1:] {
			if source != "'self'" && source != "'none'" {
				t.Errorf("%s allows %s, so the receipt's 0 other servers would not hold", fields[0], source)
			}
		}
	}

	// Cookies, and other servers: nothing the page's scripts do sets one or
	// asks one. The scheme switch keeps its one word in local storage, which
	// is why the receipt makes no claim about what the browser keeps.
	for _, name := range []string{"assets/theme.js", "assets/hero.js"} {
		raw, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		script := string(raw)
		for _, banned := range []string{"document.cookie", "sessionStorage", "indexedDB", "fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket"} {
			if strings.Contains(script, banned) {
				t.Errorf("%s uses %s, which the receipt says nothing of", name, banned)
			}
		}
	}

	// Told to the next site: nothing a link opens is told where it came from.
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy is %q, so the next site is told where its visitor came from", got)
	}

	// And nothing after the total but the line that says no copy was kept.
	_, tail, _ := strings.Cut(page, `<dl class="slip-rows slip-total">`)
	tail, _, _ = strings.Cut(tail, "</article>")
	if strings.Count(tail, "<p") != 1 || !strings.Contains(tail, `<p class="slip-foot">No copy of this receipt was kept.</p>`) {
		t.Errorf("the receipt carries more than its foot after the total:\n%s", tail)
	}
}

// The end of Porch's page compares it with an online scanner and answers six
// questions, and each claim there is held to the document it names.
//
// An answer on a page that sells a tool is the easiest place to say a little
// more than is true, so every card links its source and each source is read
// here for the sentence the card stands on. The comparison says plainly what
// Porch does tell third parties, because "only you" was first written about
// the domains and is not true of them: a scan asks crt.sh about a proven
// domain. The key a reporter encrypts to is the one SECURITY.md publishes,
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
		t.Error("the comparison says who sees the domains, and crt.sh is asked about each one")
	}
	checks := read("docs/checks.md")
	for _, says := range []string{"crt.sh", "revocation list"} {
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
		t.Error("the key in the answers is not the one step 1 checks the signature with")
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

// The policy beside the front page's opening is the one the page is served
// under, and the release record under it is the procedure docs/releasing.md
// describes.
//
// Both are written to be read as evidence: each comment in the policy names
// what a reader can see in this response, and each line of the record names
// who took the step and the public file that shows it. So each is read here
// against the response and the repository. Nothing in either is drawn from a
// file the page loads: the receipt below still counts the same six files.
//
// The policy said "third-party code # go.mod requires nothing" until
// 2026-10-08. True of this site, which is served by the same Go program as
// Porch, but a statement about a language rather than about the page; the
// page's own claim about what it reads replaced it.
func TestTheFrontPagesPolicyAndReleaseStepsHold(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	res := get(t, "/")
	page := res.Body.String()

	_, policy, ok := strings.Cut(page, `<ol class="policy-rules" aria-label="The policy this page is served under">`)
	if !ok {
		t.Fatal("the front page has no policy beside its opening")
	}
	policy, _, _ = strings.Cut(policy, "</ol>")
	line := func(verb, what, why string) string {
		return `<li><span class="policy-` + verb + `">` + verb + `</span> <span class="policy-what">` + what +
			`</span> <span class="policy-why"><span aria-hidden="true">#</span> ` + why + `</span></li>`
	}
	want := []string{
		line("deny", "cookies", "no Set-Cookie, ever"),
		line("deny", "trackers", "none in the page"),
		line("deny", "other servers", "CSP default-src 'none'"),
		line("deny", "fingerprinting", "no canvas, no font probing"),
		line("deny", "accounts, telemetry", "nothing to sign up for"),
		line("allow", "what you can check", "all our code is public"),
	}
	if got := strings.Count(policy, "<li>"); got != len(want) {
		t.Errorf("the policy has %d lines, want %d", got, len(want))
	}
	for _, l := range want {
		if !strings.Contains(policy, l) {
			t.Errorf("the policy does not say %s", l)
		}
	}
	if strings.Index(policy, `policy-allow`) < strings.LastIndex(policy, `policy-deny`) {
		t.Error("the policy allows before it has finished denying")
	}
	if !strings.Contains(page, `<figcaption>Deny first, then allow only what is needed. <a href="#this-visit">What this visit took</a></figcaption>`) {
		t.Error("the policy does not lead to the receipt that shows what the visit took")
	}

	if res.Header().Get("Set-Cookie") != "" {
		t.Error("the policy says no cookie is set, and the front page sets one")
	}
	if csp := res.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none';") || strings.Contains(csp, "http") {
		t.Errorf("the policy says other servers are denied, and the page's CSP is %q", csp)
	}
	for _, external := range []string{`src="http`, `<link rel="stylesheet" href="http`, `url(http`} {
		if strings.Contains(page, external) {
			t.Errorf("the policy says no trackers, and the page loads %s", external)
		}
	}
	if strings.Contains(page, "<form") || strings.Contains(page, `type="password"`) {
		t.Error("the policy says there is nothing to sign up for, and the page asks for something")
	}

	// No script the page loads reads anything that tells one browser from
	// another: no canvas, no fonts, no hardware, no plugins.
	scripts := regexp.MustCompile(`<script src="(/[a-z]+\.js)"`).FindAllStringSubmatch(page, -1)
	if len(scripts) == 0 {
		t.Fatal("the front page loads no script, and this check would pass by reading nothing")
	}
	for _, m := range scripts {
		body := get(t, m[1]).Body.String()
		for _, probe := range []string{"canvas", "getContext", "toDataURL", "measureText", "document.fonts", "navigator.",
			"screen.", "AudioContext", "OfflineAudioContext", "WebGL", "RTCPeerConnection", "getBattery", "deviceMemory", "hardwareConcurrency"} {
			if strings.Contains(body, probe) {
				t.Errorf("the policy says no fingerprinting, and %s uses %s", m[1], probe)
			}
		}
	}
	if licence, err := os.ReadFile("../../LICENSE"); err != nil || !strings.Contains(string(licence), "GNU AFFERO GENERAL PUBLIC LICENSE") {
		t.Error("the policy says the code is public, and the licence that makes it so is gone")
	}

	releasing, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := strings.Join(strings.Fields(string(releasing)), " ")
	_, record, ok := strings.Cut(page, `<ol class="record-rows">`)
	if !ok {
		t.Fatal("the front page does not say how a release reaches a reader")
	}
	record, _, _ = strings.Cut(record, "</ol>")
	tick := `<span class="record-tick" aria-hidden="true"><svg viewBox="0 0 16 16" focusable="false"><path d="M3 8.5l3 3 7-7"/></svg></span>`
	for _, step := range []struct{ title, who, proof, file, guide string }{
		{"Tag signed", "Maintainer", "<code>git tag -s</code>", "", "| Signed tag | Which commit is being released, and by whom |"},
		{"Built in public", "A workflow", "<code>build-release.yml</code>, which cannot sign", ".github/workflows/build-release.yml", "in a public log, and cannot sign"},
		{"Rebuilt, every byte matched, signed", "Maintainer", "<code>release.ps1 -Compare</code>, <code>SHA256SUMS.sig</code>", "scripts/release.ps1", "Any difference refuses the signature"},
		{"Rebuilt again, after publishing", "Another workflow", "<code>reproduce.yml</code>", ".github/workflows/reproduce.yml", "Someone other than the maintainer can rebuild the same bytes"},
	} {
		row := "<li>" + tick + `<strong><span class="visually-hidden">Done: </span>` + step.title + `</strong><span class="record-proof"><span class="record-who">` +
			step.who + "</span> " + step.proof + "</span></li>"
		if !strings.Contains(record, row) {
			t.Errorf("the release record does not carry %s", row)
		}
		if !strings.Contains(guide, step.guide) {
			t.Errorf("docs/releasing.md no longer says %q, which the line %q stands on", step.guide, step.title)
		}
		if step.file != "" {
			if _, err := os.Stat("../../" + step.file); err != nil {
				t.Errorf("the line %q names %s, which is not in the repository", step.title, step.file)
			}
		}
	}
	if !strings.Contains(record, `<li class="record-you"><span class="record-tick" aria-hidden="true"></span><strong><span class="visually-hidden">Yours to do: </span>Checked by you</strong>`+
		`<span class="record-proof"><span class="record-who">You</span> <a href="https://github.com/denyfirst/porch/blob/main/docs/verify.md">Your turn: verify a release</a></span></li>`) {
		t.Error("the release record's last line is not left open for the reader, with the guide that fills it")
	}
	if strings.Count(record, "<li") != 5 {
		t.Error("the release record does not have the five lines it draws")
	}
	if !strings.Contains(guide, "Two parties make a release and neither can do it alone") {
		t.Error("docs/releasing.md no longer says two parties make a release, which the band repeats")
	}
	_, band, _ := strings.Cut(page, `<section class="band" id="releases">`)
	band, _, _ = strings.Cut(band, "</section>")
	if n := strings.Count(band, "docs/verify.md"); n != 1 {
		t.Errorf("the releases band leads to the verification guide %d times; once, from the record's last line, is enough", n)
	}
}

// The front page ends on the sign-up form most sites end on, drawn and
// stamped, and asks the reader for nothing.
//
// It is a picture of a form, and has to stay one: a field that took an
// address, even one that sent it nowhere, would make the sentence beside it
// false. So the drawing holds no control, is hidden from assistive technology
// that would read out an offer nobody makes, and the page holds no form,
// field or button anywhere. The opening's button that led to the products,
// which sit directly under it and which the index also reaches, is gone.
//
// Beside the drawing, ours: one mail link, in the text where a screen reader
// reaches it, to the address for general mail. Not security@, whose reports
// must not wait among letters, and with nothing added to it, no subject or
// body a reader did not write.
func TestTheFrontPageAsksForNothing(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	page := get(t, "/").Body.String()

	_, end, ok := strings.Cut(page, `<section class="band band-tint" id="no-sign-up">`)
	if !ok {
		t.Fatal("the front page does not end on the sign-up it declines")
	}
	end, _, _ = strings.Cut(end, "</section>")
	if !strings.Contains(end, "We don&rsquo;t need your email, your name, or\n      anything else about you.") {
		t.Error("the ending no longer says what it does not need")
	}
	text, drawing, ok := strings.Cut(end, `<div class="sign-up" aria-hidden="true">`)
	if !ok {
		t.Fatal("the drawn sign-up is missing, or read aloud")
	}
	const ours = `<a class="farewell-field" href="mailto:hello@denyfirst.dev">`
	if n := strings.Count(end, "<a "); n != 1 {
		t.Errorf("the ending carries %d links; it should carry one, the mail link beside the drawing", n)
	}
	if !strings.Contains(text, ours) {
		t.Errorf("the text beside the drawing does not give our address as %s", ours)
	}
	if !strings.Contains(drawing, `<p class="sign-up-stamp">Denied</p>`) {
		t.Error("the drawn sign-up is not stamped")
	}
	for _, control := range []string{"<form", "<input", "<textarea", "<select", "<button", "<a ", "contenteditable", "tabindex"} {
		if strings.Contains(drawing, control) || control != "<a " && strings.Contains(end, control) {
			t.Errorf("the ending carries %s, and asks for nothing", control)
		}
		if control != "<a " && control != "<button" && strings.Contains(page, control) {
			t.Errorf("the front page carries %s, and says it needs nothing about the reader", control)
		}
	}
	if n := strings.Count(page, `href="#products"`); n != 1 {
		t.Errorf("the front page leads to its products %d times; the index under the opening is enough", n)
	}
}

// The address the front page ends on is one the organisation's privacy page
// accounts for: what a letter carries, what it is used for, and that it is
// passed on to nobody. An address published without that would be the one
// thing the site takes that its privacy page does not mention.
func TestTheAddressTheFrontPageGivesIsOnThePrivacyPage(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the front page is the demonstration's")
	}
	const address = "hello@denyfirst.dev"
	if !strings.Contains(get(t, "/").Body.String(), `href="mailto:`+address+`"`) {
		t.Fatalf("the front page does not give %s", address)
	}
	privacy := get(t, orgPrivacy).Body.String()
	_, mail, ok := strings.Cut(privacy, `<h2 id="mail">Writing to us</h2>`)
	if !ok {
		t.Fatal("denyfirst's privacy page does not say what happens to a letter")
	}
	mail, _, _ = strings.Cut(mail, "<h2")
	said := strings.Join(strings.Fields(mail), " ")
	for _, want := range []string{
		`<a href="mailto:` + address + `">` + address + `</a>`,
		"with the address and headers it was sent with",
		"We use it to answer you and for nothing else",
		"it is not passed on",
		`<a href="/.well-known/security.txt">security.txt</a>`,
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the privacy page's section on mail no longer says %q", want)
		}
	}
}
