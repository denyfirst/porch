//go:build !demo

package web

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// configured runs Configure for one test and puts the package back as it
// found it when the test ends: every rendered page, including the ones
// Configure adds, and whether pages offer a way out.
//
// One helper for every test that configures, because the tests run shuffled
// and each one reads what the last left behind. A helper that put back only
// the pages it expected to change left /login answering for the next test
// once every installation had one.
func configured(t *testing.T, in Installation) {
	t.Helper()
	before := map[string][]byte{}
	for p, body := range rendered {
		before[p] = body
	}
	wasSignedIn := signedIn
	t.Cleanup(func() {
		for p := range rendered {
			if _, ok := before[p]; !ok {
				delete(rendered, p)
			}
		}
		for p, body := range before {
			rendered[p] = body
		}
		signedIn = wasSignedIn
	})
	Configure(in)
}

// guardedAs renders the whole site as an installation, behind its password,
// reads one page, and puts every rendered page back as it was.
func guardedAs(t *testing.T, path string) string {
	t.Helper()
	configured(t, Installation{})
	return get(t, path).Body.String()
}

// Every page offers a way out, at the foot of the rail, and loads the one
// script that signs out: every installation has a password, since porchd
// does not start without one. There is no bar across the top for it to sit
// in (redrawn 2026-11-20).
func TestEveryPageBehindAPasswordOffersAWayOut(t *testing.T) {
	paths := []string{"/", "/domains", "/history", "/security", "/installation", "/privacy", "/terms"}
	for _, path := range paths {
		page := guardedAs(t, path)
		foot := strings.Index(page, `<div class="rail-foot">`)
		out := strings.Index(page, `<button class="rail-signout" id="sign-out" type="button">`)
		if !strings.Contains(page, `<span class="rail-label">Sign out</span></button>`) {
			t.Errorf("%s: the way out has no label a narrowed rail can hide", path)
		}
		if foot < 0 || out < foot || out > strings.Index(page, "</aside>") {
			t.Errorf("%s: behind a password, no way to sign out at the rail's foot", path)
		}
		if strings.Contains(page, `class="topbar"`) {
			t.Errorf("%s: still draws a bar across the top", path)
		}
		if !strings.Contains(page, `<script src="/session.js"></script>`) {
			t.Errorf("%s: behind a password, the script that signs out is not loaded", path)
		}
	}
}

// The sign-in page shows nothing about the installation: no rail, no scope,
// no links into what is behind the gate.
func TestTheSignInPageShowsNothingBehindTheGate(t *testing.T) {
	page := guardedAs(t, "/login")
	for _, never := range []string{`<aside class="rail">`, `class="topbar"`, "shown control of", `href="/domains"`, `href="/history"`, `href="/docs"`, `src="/app.js"`, "command-box", "docker compose logs"} {
		if strings.Contains(page, never) {
			t.Errorf("the sign-in page carries %q", never)
		}
	}
	for _, want := range []string{`<form class="panel signin-form" id="signin-form"`, `type="password"`, `autocomplete="current-password"`, `<script src="/session.js"></script>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the sign-in page lacks %q", want)
		}
	}
}

// The first visit is the setup page: the code from the log and the password
// chosen with it, and the one command that finds the code. Nothing about
// the installation is on it, as on the sign-in page.
//
// It replaced a password the installation made itself and printed to the
// log, which stayed there, working, until somebody changed it (2026-11-20).
func TestTheSetupPageAsksForTheCodeAndThePassword(t *testing.T) {
	page := guardedAs(t, "/setup")
	for _, never := range []string{`<aside class="rail">`, "shown control of", `href="/domains"`, `href="/history"`, `src="/app.js"`, `id="sign-out"`} {
		if strings.Contains(page, never) {
			t.Errorf("the setup page carries %q", never)
		}
	}
	for _, want := range []string{
		`<form class="panel signin-form" id="setup-form" autocomplete="off">`,
		`id="setup-code"`,
		`id="setup-password" name="password" required minlength="12"`,
		`autocomplete="new-password"`,
		`<script src="/session.js"></script>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the setup page lacks %q", want)
		}
	}

	// The one command on it is copied as it reads, by session.js: app.js is
	// behind the gate, so the Copy the other pages use is not here. The
	// Copy is an icon inside the command's box, named for a screen reader,
	// not a button under it that read as one more step (reported 2026-11-18).
	box := strings.Index(page, `<div class="command-box">`)
	command := strings.Index(page, `<code id="setup-command">`)
	button := strings.Index(page, `<button class="command-box-copy" type="button" data-copy="setup-command" aria-label="Copy the command"`)
	if box < 0 || command < box || button < command {
		t.Error("the setup page's command has no Copy inside its box")
	}
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		`document.querySelector(".signin-first [data-copy]")`,
		"copyIcon(copy, source.textContent, source)",
		`send("POST", "/api/v1/setup", { code: code.value.trim(), password: password.value })`,
		`window.location.assign("/security")`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("session.js no longer contains %q", want)
		}
	}
}

// Confirming it's you is a page behind the gate, drawn as the sign-in card
// is: a code where the second factor is on, the password where it is not,
// and the warning that five wrong answers end the session.
func TestTheConfirmPageAsksForACodeOrThePassword(t *testing.T) {
	if !slices.Contains(PublicPaths(), "/setup") || slices.Contains(PublicPaths(), "/confirm") {
		t.Error("the confirm page is public, or the setup page is not")
	}
	page := guardedAs(t, "/confirm")
	for _, want := range []string{
		`<form class="panel signin-form" id="confirm-form" autocomplete="off">`,
		`id="confirm-code-row" hidden`,
		`id="confirm-password-row" hidden`,
		`autocomplete="one-time-code"`,
		`<a class="signin-back" href="/security">`,
		"Five wrong answers end this session",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the confirm page lacks %q", want)
		}
	}
	if strings.Contains(page, `<aside class="rail">`) {
		t.Error("the confirm page draws the rail")
	}
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		`send("POST", "/api/v1/session/confirm", body)`,
		`if (code !== "confirm_required") return false;`,
		`window.location.assign("/confirm");`,
		`} else if (refusal === "signed_out" || refusal === "sign_in") {`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("session.js no longer contains %q", want)
		}
	}
}

// What anybody may reach is the sign-in page and what it draws and runs
// with, and nothing that says anything about the installation.
func TestOnlyTheSignInPageAndWhatItNeedsArePublic(t *testing.T) {
	got := PublicPaths()
	sort.Strings(got)
	want := []string{"/apple-touch-icon.png", "/favicon.ico", "/icon-porch.svg", "/login", "/schibsted-grotesk.woff2", "/session.js", "/setup", "/style.css", "/theme.js"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("public paths are %v, want %v", got, want)
	}
}

// The installation, security and privacy pages say a password is there, and
// what it means, exactly where it is.
//
// Signing in has a page of its own, Security: the password form sat at the
// foot of This installation, under the update settings, and was hard to find,
// and the two together read as one long page (reported 2026-11-18). This
// installation says how the copy runs and points to Security; it carries no
// form.
func TestThePagesSayWhetherAPasswordIsInFront(t *testing.T) {
	installation := flatten(guardedAs(t, "/installation"))
	if !strings.Contains(installation, "Behind a password") || !strings.Contains(installation, `<a href="/security">Security</a>`) {
		t.Error("the installation page behind a password does not say so, or where to change it")
	}
	for _, never := range []string{`id="password-form"`, `id="factor"`} {
		if strings.Contains(installation, never) {
			t.Errorf("the installation page still carries %q, which is Security's", never)
		}
	}
	if !strings.Contains(installation, `<h2 class="work-section">How it runs</h2>`) || !strings.Contains(installation, `<h2 class="work-section" id="updates">Updates</h2>`) {
		t.Error("the installation page does not head its parts")
	}

	security := flatten(guardedAs(t, "/security"))
	factor := strings.Index(security, `<h2 class="factor-title" id="factor-title">Two-step sign-in</h2>`)
	password := strings.Index(security, `<h2 class="factor-title" id="password-title">Password</h2>`)
	if !strings.Contains(security, "<h1>Security</h1>") || factor < 0 || password < factor {
		t.Error("the security page does not head two-step sign-in and then the password")
	}
	// A change is confirmed on a page of its own, not by a password and a
	// code typed again beside each button.
	for _, never := range []string{`id="password-code-row"`, `id="factor-step"`, `id="factor-password"`} {
		if strings.Contains(security, never) {
			t.Errorf("the security page still asks again in place: %q", never)
		}
	}
	// On and off is one switch, which says its state in a word as well.
	for _, never := range []string{`id="factor-start"`, `id="factor-turn-off"`, "Listed in the app as"} {
		if strings.Contains(security, never) {
			t.Errorf("the security page still carries %q, which the switch replaced", never)
		}
	}
	for _, want := range []string{`id="factor-state"`, `<input type="checkbox" role="switch" id="factor-switch" aria-labelledby="factor-title" aria-describedby="factor-lead" disabled>`, `id="factor-qr"`, `id="factor-code-list"`, `id="password-form"`, `id="factor-new-codes"`} {
		if !strings.Contains(security, want) {
			t.Errorf("the security page lacks %q", want)
		}
	}
	privacy := flatten(guardedAs(t, "/privacy"))
	if !strings.Contains(privacy, "One cookie, set when you sign in") || strings.Contains(privacy, "No cookies") {
		t.Error("the privacy page behind a password does not describe its one cookie")
	}

	// And no page has a sentence left for an installation without one: there
	// is no such installation to describe.
	for _, path := range []string{"/", "/security", "/installation", "/privacy", "/history", "/domains"} {
		page := flatten(guardedAs(t, path))
		for _, gone := range []string{"No password", "No cookies", "-results-dir", "porch-scan -history", "Not kept"} {
			if strings.Contains(page, gone) {
				t.Errorf("%s still says %q, which describes an installation porchd no longer starts", path, gone)
			}
		}
	}
}

// session.js asks the session endpoints and moves the browser. It reads no
// report, stores nothing and builds no markup.
func TestTheSessionScriptDoesOnlyThat(t *testing.T) {
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{`send("POST", "/api/v1/session"`, `send("DELETE", "/api/v1/session")`, `send("POST", "/api/v1/password"`, `window.location.assign("/login")`} {
		if !strings.Contains(js, want) {
			t.Errorf("session.js no longer contains %q", want)
		}
	}
	for _, never := range []string{"localStorage", "sessionStorage", "document.cookie", "innerHTML", "/api/v1/tls", "/api/v1/web", "/api/v1/mail", "sendBeacon"} {
		if strings.Contains(js, never) {
			t.Errorf("session.js contains %q", never)
		}
	}
}

// The second factor is drawn by session.js from what the installation sends:
// the code to scan as SVG built element by element, the recovery codes as
// text, and nothing kept. The sign-in page keeps the password when it is told
// a code is needed, which it is told before the password is read.
func TestTheSessionScriptDrawsTheSecondFactor(t *testing.T) {
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		`ask("GET", "/api/v1/factor")`,
		`ask("POST", "/api/v1/factor/setup")`,
		`ask("POST", "/api/v1/factor/on", { code: setupCode.value.trim() })`,
		`"/api/v1/factor/off" : "/api/v1/factor/recovery"`,
		`document.createElementNS(svg, "path")`,
		`text.textContent = c;`,
		`} else if (refusal === "code_required") {`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("session.js no longer contains %q", want)
		}
	}
	// On "code_required" the password field is left as it is.
	i := strings.Index(js, `} else if (refusal === "code_required") {`)
	j := strings.Index(js[i:], "} else {")
	if i < 0 || j < 0 || strings.Contains(js[i:i+j], "field.value") {
		t.Error("the sign-in page clears the password when it is only asked for a code")
	}

	// The code is a second step in the same card, with a way back: the
	// password stays in its field and goes with the code in one request.
	if !strings.Contains(js, "step(true);") || !strings.Contains(js, "passwordStep.hidden = toCode;") {
		t.Error("the sign-in page does not ask for the code as a second step")
	}
	login := flatten(guardedAs(t, "/login"))
	for _, want := range []string{`id="signin-password-step"`, `id="signin-code-row" hidden`, `id="signin-back"`, `autocomplete="one-time-code"`, `id="signin-recovery"`} {
		if !strings.Contains(login, want) {
			t.Errorf("the sign-in page lacks %q", want)
		}
	}
}

// Behind a password, History lists what is kept and opens it with the same
// builders New check uses; the list is asked for after the page loads, and
// nothing of it is in the page.
func TestHistoryBehindAPasswordListsOpensAndDeletes(t *testing.T) {
	page := guardedAs(t, "/history")
	for _, want := range []string{`<script src="/app.js"></script>`, `id="history-table"`, `<tbody id="history-rows"></tbody>`, `id="history-report"`} {
		if !strings.Contains(page, want) {
			t.Errorf("History behind a password lacks %q", want)
		}
	}

	src := script(t)
	start := strings.Index(src, "const historyBox = ")
	if start < 0 {
		t.Fatal("app.js has no history module")
	}
	history := src[start:]
	for _, want := range []string{
		`historyRequest("GET", "/api/v1/history")`,
		`historyRequest("GET", "/api/v1/history/" + entry.id)`,
		`historyRequest("DELETE", "/api/v1/history/" + entry.id)`,
		"if (!window.confirm(",
		"reportShow(frame, frame.entries[0], record.report);",
		`window.location.assign("/login")`,
	} {
		if !strings.Contains(history, want) {
			t.Errorf("the history module no longer contains %q", want)
		}
	}
	// Asked before it is deleted: the confirmation comes first.
	if strings.Index(history, "if (!window.confirm(") > strings.Index(history, `historyRequest("DELETE"`) {
		t.Error("a report is deleted before anybody is asked")
	}
	if strings.Contains(history, "innerHTML") {
		t.Error("the history module builds markup from strings")
	}

	privacy := flatten(guardedAs(t, "/privacy"))
	if !strings.Contains(privacy, "encrypted under a key the password seals") {
		t.Error("the privacy page behind a password does not say how results are kept")
	}
}

// The sign-in page's footer is at the foot of the window and centred under
// the card, not floating mid-page flush left.
func TestTheSignInFooterSitsAtTheFootCentred(t *testing.T) {
	css := stylesheet(t)
	for _, want := range []string{
		".workspace-signin .workspace-main { min-height: 100vh; }",
		".workspace-signin .colophon-row { justify-content: center; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css no longer contains %q", want)
		}
	}
}

// Behind a password, Domains keeps a list and asks DNS about each domain on
// it, one after another, stopping when the budget says wait.
func TestDomainsBehindAPasswordKeepsAListAndAsksEachOne(t *testing.T) {
	page := guardedAs(t, "/domains")
	for _, want := range []string{`id="domain-table"`, `<tbody id="domain-rows"></tbody>`, `<h2 class="work-section">Your domains</h2>`} {
		if !strings.Contains(page, want) {
			t.Errorf("Domains behind a password lacks %q", want)
		}
	}

	src := script(t)
	start := strings.Index(src, "const domainTable = ")
	if start < 0 {
		t.Fatal("app.js has no domain list module")
	}
	list := src[start:]
	if end := strings.Index(list, "if (domainTable) loadDomains();"); end > 0 {
		list = list[:end]
	}
	for _, want := range []string{
		`domainRequest("GET", "/api/v1/domains")`,
		`domainRequest("DELETE", "/api/v1/domains/" + encodeURIComponent(domain.name))`,
		"const answer = await check(domain.name, VERIFY);",
		"if (!(await proveRow(m.domain, m.proof))) {",
		`return err.status !== 429;`,
		"if (!window.confirm(",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("the domain list module no longer contains %q", want)
		}
	}
	if !strings.Contains(src, `await domainRequest("POST", "/api/v1/domains", { domain: target.value.trim() });`) {
		t.Error("adding a domain behind a password does not keep it on the list")
	}
	// Proven or not is asked, never kept.
	if strings.Contains(list, "localStorage") || strings.Contains(list, "innerHTML") {
		t.Error("the domain list module stores state or builds markup from strings")
	}

	if privacy := flatten(guardedAs(t, "/privacy")); !strings.Contains(privacy, "The domains you add under Domains are kept") {
		t.Error("the privacy page behind a password does not say the domain list is kept")
	}
}

// Every form in session.js gets its button back and says what happened,
// whatever the answer, and signing out moves to the sign-in page only once
// the server has said the session ended (audit 2026-09-18, D07). A network
// that failed used to leave the buttons disabled, and a sign-out the server
// never saw looked exactly like one it did.
func TestTheSessionScriptRecoversAndSignsOutOnlyOnSuccess(t *testing.T) {
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)

	// send never throws: no answer, or one too late, is a sentence.
	start := strings.Index(js, "async function send(")
	end := strings.Index(js, "const signinForm")
	if start < 0 || end < start {
		t.Fatal("session.js no longer has send before the forms")
	}
	send := js[start:end]
	for _, want := range []string{"} catch {\n      return \"The installation could not be reached.", "abort.abort()", "signal: abort.signal"} {
		if !strings.Contains(send, want) {
			t.Errorf("send no longer contains %q", want)
		}
	}

	block := func(from, to string) string {
		t.Helper()
		i := strings.Index(js, from)
		j := strings.Index(js[i+1:], to)
		if i < 0 || j < 0 {
			t.Fatalf("session.js has no block from %q to %q", from, to)
		}
		return js[i : i+1+j]
	}
	forms := map[string]string{
		"sign-in":  block("const signinForm", "const signOut"),
		"sign-out": block("const signOut", "const passwordForm"),
		"password": block("const passwordForm", "})();"),
	}
	for name, b := range forms {
		fin := strings.Index(b, "} finally {")
		if fin < 0 {
			t.Errorf("the %s handler has no finally", name)
			continue
		}
		if !strings.Contains(b[fin:], ".disabled = false;") {
			t.Errorf("the %s handler does not give its button back in finally", name)
		}
	}

	out := forms["sign-out"]
	fin := strings.Index(out, "} finally {")
	if fin < 0 || !strings.Contains(out[fin:], "if (problem === null) {\n          window.location.assign(\"/login\");") {
		t.Error("signing out moves to the sign-in page without the server saying the session ended")
	}
	if strings.Count(out, `window.location.assign("/login")`) != 1 {
		t.Error("signing out moves to the sign-in page by another path")
	}
	if !strings.Contains(out, `signOutLabel.textContent = "Not signed out. Try again";`) {
		t.Error("a failed sign-out is not said")
	}
}
