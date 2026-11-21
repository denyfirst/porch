package web

import (
	"regexp"
	"strings"
	"testing"
)

// While a run is on, nothing in the form leads away from it.
//
// A disabled fieldset disables its controls and not its links: on 2026-11-21
// Add a domain and the Names card still opened their pages mid-run, under a
// cursor that said they would not. The links are taken out of the tab order,
// said to be unavailable, and their clicks refused before they reach them.
func TestTheLinksInTheFormWaitForTheRun(t *testing.T) {
	src := script(t)
	for _, want := range []string{
		`const COMPOSER_LINKS = "fieldset.composer-part a[href]";`,
		`for (const link of consoleForm.querySelectorAll(COMPOSER_LINKS)) {`,
		`link.setAttribute("aria-disabled", "true");`,
		`link.setAttribute("tabindex", "-1");`,
		`link.removeAttribute("aria-disabled");`,
		`link.removeAttribute("tabindex");`,
		// Capturing, so the refusal comes before the link acts; and only
		// while a run is on.
		"if (consoleRun && event.target.closest(COMPOSER_LINKS)) event.preventDefault();\n  }, true);",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js does not carry %s", want)
		}
	}

	// And there are links in the form for it to stop: were they moved out,
	// this test would pass over nothing.
	body, err := assets.ReadFile("assets/console.html")
	if err != nil {
		t.Fatal(err)
	}
	links := 0
	for _, part := range regexp.MustCompile(`(?s)<fieldset class="composer-part[^"]*"[^>]*>.*?</fieldset>`).FindAllString(string(body), -1) {
		links += strings.Count(part, "<a ")
	}
	if links < 2 {
		t.Errorf("the form holds %d links; Add a domain and the Names card were expected", links)
	}

	sheet := stylesheet(t)
	if !strings.Contains(sheet, `.composer-part:disabled a[aria-disabled="true"]:not(.check) { color: var(--ink-faint); cursor: not-allowed; }`) {
		t.Error("a link that waits is not drawn as waiting")
	}
}

// New check shows the last run of this sign-in, and nothing older.
//
// Asked for on 2026-11-21: leaving the page and coming back keeps the run,
// and signing out leaves it empty, because earlier runs are History's. The
// first version drew History's newest run whenever the page opened, in every
// session after it. Now the page asks the session which reports its last run
// kept, and the session forgets them when it ends (internal/access/last.go).
func TestTheLastRunIsTheSessionsAndNotHistorysNewest(t *testing.T) {
	src := script(t)
	for _, want := range []string{
		`last = await historyRequest("GET", "/api/v1/session/last");`,
		`fetch("/api/v1/session/last", {`,
		`method: "PUT",`,
		// The run replaces the last one from its start, and names its
		// reports as each check lands, so leaving mid-run keeps what is done.
		"const before = await historyNewest();\n      await sessionLast([]);",
		`if (entry.data) await consoleRemember(frame, target, before);`,
		// Only reports this run added, for this target.
		`Number(e.seq) > before &&`,
		`String(e.target).toLowerCase() === target.toLowerCase()`,
		`"/api/v1/history/" + encodeURIComponent(id)`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js does not carry %s", want)
		}
	}

	// History's newest run is no longer what the page draws.
	fn := regexp.MustCompile(`(?s)async function consoleLast\(\) \{.*?\n\}\n`).FindString(src)
	if fn == "" {
		t.Fatal("consoleLast is gone; read this test against app.js")
	}
	if strings.Contains(fn, `"/api/v1/history")`) {
		t.Error("New check still draws History's newest run, from any session")
	}

	// And nothing of it is kept in the browser.
	for _, name := range []string{"assets/app.js", "assets/session.js"} {
		body, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, never := range []string{"localStorage", "sessionStorage", "indexedDB"} {
			if strings.Contains(string(body), never) {
				t.Errorf("%s uses %s", name, never)
			}
		}
	}
}
