package web

import (
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// explainEntry is one entry of assets/explain.js.
type explainEntry struct {
	About string   `json:"about"`
	What  string   `json:"what"`
	Good  string   `json:"good"`
	How   string   `json:"how"`
	Src   []string `json:"src"`
}

// explainSep joins a section title and a label in a scoped key.
const explainSep = " › "

func readExplain(t *testing.T) map[string]explainEntry {
	t.Helper()
	raw, err := assets.ReadFile("assets/explain.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	const open = "const EXPLAIN = Object.freeze("
	start := strings.Index(source, open)
	end := strings.LastIndex(source, ");")
	if start < 0 || end < start {
		t.Fatal("explain.js no longer holds one frozen object")
	}
	var entries map[string]explainEntry
	if err := json.Unmarshal([]byte(source[start+len(open):end]), &entries); err != nil {
		t.Fatalf("explain.js is not JSON where the tests read it: %v", err)
	}
	return entries
}

// reportLabels is every label and section title a report draws, read from
// the code that draws them: the rows and facts in app.js, and the rows the
// web check's declarations carry from internal/policy.
func reportLabels(t *testing.T) (rows, sections map[string]bool) {
	t.Helper()
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(script)
	declared, err := os.ReadFile("../policy/declared.go")
	if err != nil {
		t.Fatal(err)
	}

	rows, sections = map[string]bool{}, map[string]bool{}
	collect := func(into map[string]bool, source, pattern string) {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(source, -1) {
			if m[1] != "" {
				into[m[1]] = true
			}
		}
	}
	collect(rows, app, `\brow\(\s*"([^"]+)"`)
	collect(rows, app, `\bpair\(\s*"([^"]+)"`)
	collect(rows, app, `\bfact\(\s*"([^"]+)"`)
	collect(rows, app, `el\("dt", null, "([^"]+)"\)`)
	collect(sections, app, `sectionTitle\(\s*"([^"]+)"\)`)
	collect(sections, app, `\bchain\(\s*"([^"]+)"`)
	collect(rows, string(declared), `Label: "([^"]+)"`)
	collect(rows, string(declared), `\{"([^"]+)", "[^"]+"\},`)
	if len(rows) < 80 || len(sections) < 12 {
		t.Fatalf("read %d labels and %d section titles: the patterns no longer find them", len(rows), len(sections))
	}
	return rows, sections
}

// Every label and section title a report draws is explained, so a row added
// later is explained when it is added, not when somebody notices it is not
// (reported on 2026-11-12: values nobody could read without looking them up).
// An entry nothing draws any more is stale and goes too.
func TestEveryReportLabelIsExplained(t *testing.T) {
	entries := readExplain(t)
	rows, sections := reportLabels(t)

	var missing []string
	for label := range rows {
		e, ok := entries[label]
		switch {
		case !ok:
			missing = append(missing, label)
		case e.About == "":
			t.Errorf("%q has no line to show under it", label)
		}
	}
	for title := range sections {
		if _, ok := entries[title]; !ok {
			missing = append(missing, title)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("a report draws %q and explain.js does not explain it", m)
	}

	for key := range entries {
		section, label, scoped := strings.Cut(key, explainSep)
		switch {
		case scoped && (!sections[section] || !rows[label]):
			t.Errorf("explain.js scopes %q to a section or a label no report draws", key)
		case !scoped && !rows[key] && !sections[key]:
			t.Errorf("explain.js explains %q, which no report draws", key)
		}
	}
}

// Each entry is short where it is read beside a row, says what the thing is,
// and points only at a standards body's page: a link out is something a
// reader follows from a report about their own estate, so it goes nowhere
// that profiles who follows it.
func TestExplanationsAreShortAndSourcedFromStandards(t *testing.T) {
	sources := map[string]bool{
		"www.rfc-editor.org":    true,
		"www.w3.org":            true,
		"fetch.spec.whatwg.org": true,
		"html.spec.whatwg.org":  true,
		"cabforum.org":          true,
	}
	for key, e := range readExplain(t) {
		if strings.TrimSpace(e.What) == "" {
			t.Errorf("%q says nothing about what it is", key)
		}
		if len(e.About) > 48 {
			t.Errorf("%q has a line of %d characters under it; keep it under 48", key, len(e.About))
		}
		if e.Src == nil {
			continue
		}
		if len(e.Src) != 2 || e.Src[0] == "" {
			t.Errorf("%q names a source without a title and an address", key)
			continue
		}
		u, err := url.Parse(e.Src[1])
		if err != nil || u.Scheme != "https" || !sources[u.Host] || u.RawQuery != "" {
			t.Errorf("%q links to %q, which is not a standards body's page", key, e.Src[1])
		}
	}
}

// The explanations are read by the script that draws every report, on every
// page that draws one, and are data: nothing in them can reach a parser.
func TestExplanationsLoadBeforeTheScriptAsData(t *testing.T) {
	layout, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), `{{if .Script}}<script src="/explain.js"></script><script src="/app.js"></script>{{end}}`) {
		t.Error("explain.js is not loaded before app.js wherever app.js is")
	}
	raw, err := assets.ReadFile("assets/explain.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.", "fetch(", "eval(", "<script"} {
		if strings.Contains(string(raw), never) {
			t.Errorf("explain.js contains %q; it holds words and nothing else", never)
		}
	}
	if got := get(t, "/explain.js"); got.Code != 200 || !strings.HasPrefix(got.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("/explain.js is served as %d %q", got.Code, got.Header().Get("Content-Type"))
	}
}
