package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// Everything a report folds starts folded, the limits included (asked for on
// 2026-11-20: "all of them closed; whoever wants to, reads them").
//
// The limits opened for an ungraded report, and before that opened always,
// on the ground that what a scan could not establish is the half of a report
// that says what the rest is worth (R4). Folded, it is still never out of
// sight: the summary of the fold carries the count, the coverage line under
// the verdict says how much was reached, the cover counts every limit as
// "not established", and an ungraded report says on its face, in words, that
// nothing could be graded and why. What folds is the list, not the fact.
func TestEveryFoldStartsFoldedAndSaysWhatItHolds(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	body := source
	if i := strings.Index(body, "function notes(list, verdict, methodPage)"); i >= 0 {
		body = body[i:]
		if end := strings.Index(body, "\n}\n"); end >= 0 {
			body = body[:end]
		}
	} else {
		t.Fatal("the script has no notes renderer")
	}
	if !strings.Contains(body, "box.open = section.open;") || strings.Contains(body, `verdict === "ungraded"`) {
		t.Error("a fold opens itself for some verdict")
	}
	if !strings.Contains(body, `chosen.length === 1 ? section.one : section.many(chosen.length)`) {
		t.Error("a fold's summary no longer says how much it holds")
	}
	for _, kind := range []string{"observed", "unsettled"} {
		i := strings.Index(source, `kind: "`+kind+`"`)
		if i < 0 {
			t.Errorf("the script has no %q section", kind)
			continue
		}
		section := source[i:]
		if end := strings.Index(section, "},"); end >= 0 {
			section = section[:end]
		}
		if !strings.Contains(section, "open: false") {
			t.Errorf("the %q section opens by default", kind)
		}
	}
	// And an ungraded report says so on its face, without a fold opened.
	if !strings.Contains(functionBody(t, source, "reportShow"), "Nothing was measured, so nothing could be graded.") {
		t.Error("an ungraded report no longer says on its face why it is ungraded")
	}
}

// A reader can keep the report they are looking at.
//
// It happens entirely in the browser: the JSON already arrived, so nothing is
// asked of the service again and nothing is kept anywhere. A server endpoint
// returning the same bytes would have to store the result or scan a second
// time, and this project does neither.
func TestTheReportCanBeSaved(t *testing.T) {
	source := script(t)

	for _, required := range []struct{ text, why string }{
		{`el("a", "download"`, "the control has to be on the page"},
		{"JSON.stringify(data", "it has to save the report the reader is looking at, not fetch another"},
		{"application/json", "the type has to say what the bytes are"},
		{"anchor.download =", "without the attribute a browser navigates to the blob instead of saving it"},
		{"URL.revokeObjectURL", "an object URL keeps its blob alive for as long as the document does"},
	} {
		if !strings.Contains(source, required.text) {
			t.Errorf("app.js does not contain %q — %s", required.text, required.why)
		}
	}

	// The name is built from a value somebody typed, and shortened.
	for _, required := range []string{`replace(/[^a-z0-9.-]+/g`, "slice(0, 60)"} {
		if !strings.Contains(source, required) {
			t.Errorf("the filename is not bounded or not sanitised: %q is missing", required)
		}
	}
}

// One format, and the reason is the strings a report carries.
//
// Every subject, name and issuer in a report is chosen by the server that was
// scanned. Each format below hands those strings to something that executes
// them: a spreadsheet reads a leading =, + or @ as a formula; a terminal reads
// an escape sequence as an instruction, which is a defect this project found
// in its own command line output; a browser reads HTML as markup. JSON escapes
// a control byte and carries no executable meaning anywhere.
func TestTheReportIsOfferedInOneFormatOnly(t *testing.T) {
	source := script(t)

	// One exception, and it is not a report: a proof-of-control record, which
	// exists to be pasted into a DNS provider's form and proves nothing until
	// it is published in the zone. copyRecord is the only writer, it copies the
	// element a data-copy button names, and it is attached to the two places a
	// record is shown and nowhere else.
	start := strings.Index(source, "async function copyRecord(button) {")
	end := -1
	if start >= 0 {
		if n := strings.Index(source[start:], "\n}\n"); n >= 0 {
			end = start + n
		}
	}
	if start < 0 || end < 0 {
		t.Fatal("copyRecord was not found; if the proof record is no longer copied, delete this exception")
	}
	copier := source[start:end]
	if strings.Count(copier, "clipboard.writeText") != 1 ||
		!strings.Contains(copier, "const source = document.getElementById(button.dataset.copy);") ||
		!strings.Contains(copier, "const text = source.textContent;") ||
		!strings.Contains(copier, "await navigator.clipboard.writeText(text);") {
		t.Errorf("copyRecord writes something other than the record its button names:\n%s", copier)
	}
	if !strings.Contains(source, `for (const holder of [proofDialog, document.getElementById("domain-record"), document.querySelector("#start .steps"), document.getElementById("update-banner")]) {`) {
		t.Error("copyRecord is attached somewhere other than the two places a proof record is shown, " +
			"the install steps on the Porch page and the update commands on New check")
	}
	// The update commands are the install steps' case on New check: text
	// written in app.js and a version read as a release name, naming no host
	// and nothing found (TestTheBannerUsesOnlyAVersionThatIsAReleaseName).
	for _, page := range []string{"assets/console.html", "assets/domains.html"} {
		body, err := assets.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range regexp.MustCompile(`data-copy="([^"]+)"`).FindAllStringSubmatch(string(body), -1) {
			if id[1] == "update-commands" && page == "assets/console.html" {
				continue
			}
			if !strings.HasPrefix(id[1], "proof-") && !strings.HasPrefix(id[1], "domain-") {
				t.Errorf("%s offers %q to the clipboard, which is not a proof record", page, id[1])
			}
		}
	}

	// The Porch page offers its install commands, and each is fixed text the
	// page shows: an element whose id the button names, holding no template
	// value, so what is copied is the same for every visitor and is what they
	// read. A command built from anything a request carried is not this case.
	porch, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	offered := regexp.MustCompile(`data-copy="([^"]+)"`).FindAllStringSubmatch(string(porch), -1)
	if len(offered) == 0 {
		t.Error("the Porch page no longer offers its commands; if that is intended, narrow the holder list above")
	}
	// And the demonstration's privacy page says so, as the installation's
	// says where its own Copy writes.
	if privacy, err := assets.ReadFile("assets/privacy.html"); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(string(privacy), "The clipboard is written in one place") ||
		!strings.Contains(string(privacy), "A report is never put there.") {
		t.Error("the Porch page writes install commands to the clipboard and the privacy page does not say so")
	}
	for _, id := range offered {
		if !strings.HasPrefix(id[1], "command-") {
			t.Errorf("the Porch page offers %q to the clipboard, which is not an install command", id[1])
			continue
		}
		at := strings.Index(string(porch), `<code id="`+id[1]+`">`)
		if at < 0 {
			t.Errorf("the Porch page's button names %q and no command carries that id", id[1])
			continue
		}
		block := string(porch)[at:]
		block = block[:strings.Index(block, "</code>")]
		// One value is allowed in, and it is not a request's: the release
		// this build is, compiled in and read as a release name or dropped
		// (pageRelease), the same for every visitor. Nothing else.
		for _, allowed := range []string{"{{if .Release}}", "{{.Release}}", "{{else}}", "{{end}}"} {
			block = strings.ReplaceAll(block, allowed, "")
		}
		if strings.Contains(block, "{{") {
			t.Errorf("the command %q is built from a template value, so what is copied is not fixed text", id[1])
		}
	}
	source = source[:start] + source[end:]

	for _, forbidden := range []struct{ text, why string }{
		{"text/csv", "a spreadsheet would read a name beginning with = as a formula"},
		{"text/html", "a browser would read a name as markup"},
		{"text/plain", "a terminal would read an escape sequence in a name as an instruction"},
		{"application/vnd.ms-excel", "the same as text/csv, under another name"},

		// The clipboard reads as the same offer and is not. It is shared with
		// every process on the machine, Windows keeps a history of it, and a
		// cloud clipboard sends it off the machine. What is sensitive in a
		// report is not its contents, which are public, but that somebody
		// asked about that host — and this service undertakes to keep no
		// record of exactly that.
		{"clipboard.writeText", "the clipboard is readable by every process on the machine and is sometimes synced off it"},
		{"execCommand(\"copy\")", "the same, by the older name"},
	} {
		if strings.Contains(source, forbidden.text) {
			t.Errorf("the report is offered as %s — %s", forbidden.text, forbidden.why)
		}
	}
}

// The standing limits left the report and are pointed at instead.
//
// Moving them is only defensible if the report still says they exist, how
// many there are, and where to read them. A section quietly dropped would be
// hiding, which is the thing this project objects to in other tools.
func TestTheStandingLimitsAreNamedAndLinked(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	// Read from the page, a link is the first check's on a page that runs three.
	if strings.Contains(source, "CHECK.methodPage") {
		t.Error("a method link is read from the page rather than from the check that drew it")
	}
	if strings.Contains(source, `kind: "standing"`) {
		t.Error("the script still renders the standing limits as a section of every report")
	}
	for _, required := range []string{
		`methodPage: CHECKS_DOC + "#tls"`,
		`methodPage: CHECKS_DOC + "#web"`,
		`methodPage: CHECKS_DOC + "#mail"`,
		"notes(data.notes, verdict, CHECKS.tls.methodPage)",
		"notes(data.notes, verdict, CHECKS.web.methodPage)",
		"notes(data.notes, verdict, CHECKS.mail.methodPage)",
		"a.href = methodPage;",
		"limits of this method apply to every scan",
		"standing.length",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the report does not say where the standing limits went: missing %q", required)
		}
	}

	// And the document it points at lists every one of them, in the words
	// the program states them (TestEveryStandingLimitIsInTheChecksDocument).
	doc := checksDoc(t)
	for _, limit := range policy.StandingLimits() {
		if !strings.Contains(doc, limit.Text) {
			t.Errorf("docs/checks.md does not carry the limit %q", limit.Title)
		}
	}
}

// One sentence about how grading works, in the same words on both faces.
//
// A weak or insecure verdict needs it: kapitalbank.az is graded insecure with
// a trusted chain, a verified staple, transparency, CAA and an accepted
// post-quantum group beside the stamp, and nothing else on the page says why
// one option outweighs the rest.
//
// Written twice, in Go for the terminal and in the script for the page, and
// compared here — the same arrangement as the section titles. A sentence
// explaining a verdict that itself differs between two renderings of one
// report would be worse than not saying it.
func TestBothFacesSayWhatAVerdictMeansInTheSameWords(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}

	// The page builds it from two concatenated string literals, as the file
	// wraps at eighty columns; compare on the words rather than the source.
	source := strings.Join(strings.Fields(string(script)), " ")
	want := strings.Join(strings.Fields(policy.WorstCase), " ")

	// Rebuild the concatenation the way the script writes it.
	joined := strings.ReplaceAll(source, `" + "`, "")
	if !strings.Contains(joined, want) {
		t.Errorf("the page does not carry policy.WorstCase:\n  %s", policy.WorstCase)
	}
}
