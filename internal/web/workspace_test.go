package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// An installation is a workspace: four parts, each an address, and the rail
// says which one a page is.
//
// The rail is links rather than tabs drawn by the script, so every part works
// without it and can be bookmarked, and the current one is said to assistive
// technology with aria-current as well as drawn. The demonstration is a site
// and has none of this.
func TestAnInstallationIsAWorkspaceOfFourParts(t *testing.T) {
	parts := map[string]string{
		"/":             "New check",
		"/domains":      "Domains",
		"/history":      "History",
		"/installation": "This installation",
	}
	for path, name := range parts {
		w := get(t, path)
		if demo.Enabled {
			if path != "/" && w.Code != http.StatusNotFound {
				t.Errorf("%s answered %d on the demonstration, which has no workspace", path, w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", path, w.Code)
			continue
		}
		body := w.Body.String()
		rail, _, _ := strings.Cut(body, "<main>")

		// Every part is in the rail, and only this one is current.
		for other := range parts {
			if !strings.Contains(rail, `<a class="rail-item" href="`+other+`"`) {
				t.Errorf("%s: the rail does not lead to %s", path, other)
			}
		}
		if n := strings.Count(rail, `aria-current="page"`); n != 1 {
			t.Errorf("%s: %d rail items are marked current, want one", path, n)
		}
		if !strings.Contains(rail, `href="`+path+`" aria-current="page">`) {
			t.Errorf("%s: the rail does not mark this page as current", path)
		}
		if !strings.Contains(body, "<h1>"+name+"</h1>") {
			t.Errorf("%s: the page is not headed %q", path, name)
		}
	}
}

// The rail is three groups, each named: what is done here, how the
// installation is set, and the documents, which leave it for GitHub and say
// so. The way out and the colour switch are at its foot.
func TestTheRailIsThreeNamedGroups(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration has no rail")
	}
	body := get(t, "/privacy").Body.String()
	rail, _, _ := strings.Cut(body, "</aside>")
	_, rail, _ = strings.Cut(rail, "<body")
	workspace := strings.Index(rail, `<p class="rail-caption" id="rail-workspace">Workspace</p>`)
	settings := strings.Index(rail, `<p class="rail-caption" id="rail-settings">Settings</p>`)
	reference := strings.Index(rail, `<p class="rail-caption" id="rail-reference">Reference</p>`)
	if workspace < 0 || settings < workspace || reference < settings {
		t.Fatal("the rail is not Workspace, Settings and Reference, in that order")
	}
	for _, part := range []struct{ href, group string }{
		{`href="/history"`, rail[workspace:settings]},
		{`href="/security"`, rail[settings:reference]},
		{`href="/installation"`, rail[settings:reference]},
		{`href="https://github.com/denyfirst/porch/tree/main/docs"`, rail[reference:]},
	} {
		if !strings.Contains(part.group, part.href) {
			t.Errorf("%s is not in its group", part.href)
		}
	}
	if !strings.Contains(rail[reference:], `<svg class="rail-out"`) {
		t.Error("Docs does not say it leaves the installation")
	}
	if strings.Contains(strings.ToLower(regexp.MustCompile(`href="[^"]*"`).ReplaceAllString(rail, "")), "denyfirst") {
		t.Error("the rail names the maker")
	}
}

// On a wide screen the rail narrows to its marks, and the page takes the
// room. The choice is remembered in this browser as one word under its own
// key, beside the colour scheme, and the privacy page says so; nothing is
// sent anywhere. Each part keeps its name in the page for a screen reader.
func TestTheRailNarrowsToItsMarksAndSaysWhatItKeeps(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration has no rail")
	}
	body := get(t, "/history").Body.String()
	if !strings.Contains(body, `<button class="rail-fold" id="rail-fold" type="button" aria-label="Narrow the menu" title="Narrow the menu" hidden>`) {
		t.Error("the rail has no button that narrows it, hidden until the script shows it")
	}
	for _, name := range []string{"New check", "Domains", "Names", "History", "Security", "This installation", "Docs"} {
		if !strings.Contains(body, `<span class="rail-label">`+name+`</span>`) {
			t.Errorf("the rail's %q has no label a narrowed rail can hide and a screen reader still reads", name)
		}
	}
	src, err := assets.ReadFile("assets/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`const RAIL = "rail";`, `window.localStorage.getItem(RAIL) === "narrow"`, `window.localStorage.setItem(RAIL, "narrow");`} {
		if !strings.Contains(string(src), want) {
			t.Errorf("theme.js no longer contains %q", want)
		}
	}
	css := stylesheet(t)
	if !strings.Contains(css, `:root[data-rail="narrow"] .workspace { --content: 73rem; grid-template-columns: 4.5rem minmax(0, 1fr); }`) {
		t.Error("a narrowed rail does not give the page its room")
	}
	if !strings.Contains(flatten(get(t, "/privacy").Body.String()), "whether you narrowed the menu") {
		t.Error("the privacy page does not say the browser keeps the rail's width")
	}
}
