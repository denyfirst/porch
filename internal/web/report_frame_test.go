package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// Every report is drawn in one frame, and each check in it has a row and a
// state of its own.
//
// Read from the source, as the other script tests are: nothing here runs it.
// What matters is that a check's verdict is written to that check's row only,
// that a failure is written as "not run" rather than left as "running", that
// the checks run one at a time, and that every page that draws a report draws
// it through the frame.
func TestEachCheckHasARowAndAStateOfItsOwn(t *testing.T) {
	src := script(t)
	for _, want := range []string{
		`entry.state.className = "stamp stamp-small " + verdictClass("stamp", verdict);`,
		`entry.state.textContent = "not run";`,
		`entry.body.appendChild(entry.spec.build(data));`,
		`board.setAttribute("aria-label", "Checks in this report");`,
		`title.href = "#report-" + name;`,
		// The console, the demonstration, a check's own page and History.
		`const frame = reportFrame(consoleResults, target, CHECK_ORDER, chosen);`,
		`const frame = reportFrame(porchResults, target, CHECK_ORDER, chosen);`,
		`const frame = reportFrame(result, domainOnly(target), [CHECK_NAME], [CHECK_NAME]);`,
		`frame = reportFrame(historyReport, entry.target, [record.check], [record.check], { when: record.date });`,
		`await reportRun(frame, entry, () => check(target, entry.spec));`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the report frame no longer contains %q", want)
		}
	}
	// One at a time: each check spends from the host's budget.
	if strings.Contains(src, "Promise.all(") {
		t.Error("a page runs its checks at once, which the per-host budget exists to discourage")
	}
	// The builders draw evidence; the frame draws the verdict and the list of
	// what needs doing, so neither is drawn twice.
	for _, builder := range []string{"buildTLS", "buildWeb", "buildDNS", "buildMail"} {
		if body := functionBody(t, src, builder); strings.Contains(body, "summary(data)") {
			t.Errorf("%s draws the summary the frame draws", builder)
		}
	}
}

// A check's verdict is stamped at the head of its card, beside the check's
// name, before the name it is a verdict on and before the evidence, and the
// head stays in view while the card is read.
//
// Between 2026-10-10 and 2026-10-11 it was a pill in a column beside the
// evidence, under the check's name and its description, and a reader looking
// for how a check ended had to find it; and with the checks set one after
// another down the page, a reader scrolling could not tell where one check
// ended and the next began.
func TestAVerdictIsStampedAtTheHeadOfItsCard(t *testing.T) {
	show := functionBody(t, script(t), "reportShow")
	at := func(needle string) int {
		i := strings.Index(show, needle)
		if i < 0 {
			t.Fatalf("reportShow no longer contains %q", needle)
		}
		return i
	}
	if !(at("entry.mark.replaceWith(stamp);") < at("entry.top.appendChild(sum);") &&
		at("entry.top.appendChild(sum);") < at("entry.body.appendChild(entry.spec.build(data));")) {
		t.Error("a check's verdict is not given first, at the head of its card, above its evidence")
	}
	frame := functionBody(t, script(t), "reportFrame")
	if strings.Index(frame, `"report-check-head"`) > strings.Index(frame, `"report-check-top"`) ||
		strings.Index(frame, `"report-check-top"`) > strings.Index(frame, `"report-body"`) {
		t.Error("a card's head, the name it grades and its evidence are not made in that order")
	}
	css := stylesheet(t)
	_, head, _ := strings.Cut(css, ".report-check-head {")
	head, _, _ = strings.Cut(head, "}")
	if !strings.Contains(head, "position: sticky") {
		t.Error("a card's head no longer stays in view while the card is read")
	}
}

// A check that has no verdict, because it is running, was not chosen or did
// not run, is marked in a dashed stamp in the faint ink, never in a verdict's
// colour, so an absence never reads as a result (R4).
func TestAnAbsentVerdictIsNeverDrawnAsOne(t *testing.T) {
	src := script(t)
	for _, want := range []string{
		`el("span", "stamp stamp-small stamp-pending", on ? "running" : "off")`,
		`entry.state.className = "stamp stamp-small stamp-pending";`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the frame no longer contains %q", want)
		}
	}
	css := stylesheet(t)
	_, rule, _ := strings.Cut(css, ".stamp-pending {")
	rule, _, _ = strings.Cut(rule, "}")
	if !strings.Contains(rule, "border-style: dashed") || !strings.Contains(rule, "var(--ink-faint)") {
		t.Errorf("a pending stamp is not dashed in the faint ink: %s", rule)
	}
	for _, verdict := range []string{"--strong", "--weak", "--insecure"} {
		if strings.Contains(rule, verdict) {
			t.Errorf("a pending stamp is drawn in %s", verdict)
		}
	}
}

// Every check keeps its row when fewer are chosen.
//
// One chosen check drew a single tab across the whole row once. The others are
// drawn switched off, saying so, with no section behind them.
func TestAnUnchosenCheckKeepsARowItCannotOpen(t *testing.T) {
	body := functionBody(t, script(t), "reportFrame")
	for _, want := range []string{
		"names.forEach((name, i) => {",
		`const on = chosen.includes(name);`,
		`on ? "report-row" : "report-row report-row-off"`,
		`on ? "running" : "not selected"`,
		"if (!on) return;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the frame no longer contains %q", want)
		}
	}
	// The switch-off comes before the section is made, so an unchosen check
	// has none.
	if strings.Index(body, "if (!on) return;") > strings.Index(body, `el("section", "report-check`) {
		t.Error("an unchosen check is given a section before it is skipped")
	}
	if !strings.Contains(stylesheet(t), ".report-row-off .report-row-title") {
		t.Error("a switched-off row is not styled")
	}
}

// The help under the form says one thing and leads to the steps on the page.
func TestThePorchHelpLeadsToTheSteps(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the Porch page is the demonstration's")
	}
	page := get(t, "/porch").Body.String()
	_, help, _ := strings.Cut(page, `id="porch-help"`)
	help, _, _ = strings.Cut(help, "</p>")
	if !strings.Contains(help, `<a href="#start">run Porch yourself</a>`) || !strings.Contains(page, `id="start"`) {
		t.Errorf("the help does not lead to the steps on this page:%s", help)
	}
	if strings.Contains(help, "/privacy") || strings.Contains(help, "/terms") {
		t.Errorf("the help repeats what /docs lists:%s", help)
	}
}

// The inventory is drawn in the same frame, with a row for every source it
// reads and nothing above the list but a name somebody else could take.
func TestTheNamesAreDrawnInTheFrame(t *testing.T) {
	src := script(t)

	// One row per source, and the same sources the inventory reads: a source
	// added to one and not the other is a row missing, or a row for nothing.
	readings := functionBody(t, src, "readings")
	start := strings.Index(src, "const NAME_SOURCES = [")
	if start < 0 {
		t.Fatal("the names frame names no sources")
	}
	sources := src[start:]
	sources = sources[:strings.Index(sources, "];")]
	for _, field := range []string{"zone", "nsec", "logs", "records", "passive", "presented", "reverse", "known"} {
		if !strings.Contains(readings, "data."+field) || !strings.Contains(sources, `"`+field+`"]`) {
			t.Errorf("the source %q is not both read and listed", field)
		}
	}

	frame := functionBody(t, src, "namesFrame")
	for _, want := range []string{
		`if (reading.reason) state = "not established";`,
		`else if (!reading.asked) state = "not asked";`,
		`status(n) === "dangling"`,
		"Whoever claims that name next",
		"body.appendChild(buildNames(data));",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("the names frame no longer contains %q", want)
		}
	}
	for _, want := range []string{
		`if (CHECK_NAME === "names") namesFrame(result, domainOnly(target), data);`,
		`namesFrame(historyReport, entry.target, record.report, { when: record.date });`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("an inventory is drawn outside the frame: %q is missing", want)
		}
	}
}

// A report saved as a PDF is the report, in the same design, whole.
//
// Printed on 2026-10-11, the first card design left a check's name at the
// foot of one sheet and its verdict at the head of the next; ran the cipher
// tables past the card's edge, because the screen's minimum width applied on
// paper; lost every grade's dot and every key's square, because a browser
// leaves backgrounds off paper unless asked; printed the installation's own
// path bar above the report; and printed the whole Porch page, introduction
// and form and every band, around the report it was asked to keep.
func TestAReportOnPaperIsTheReport(t *testing.T) {
	css := stylesheet(t)
	rule := func(selector string) string {
		_, body, ok := strings.Cut(css, selector+" {")
		if !ok {
			t.Fatalf("the stylesheet has no rule for %s", selector)
		}
		body, _, _ = strings.Cut(body, "}")
		return body
	}
	for _, want := range []string{
		".report-check-head { position: static; break-inside: avoid; break-after: avoid; }",
		".report-check-top { break-before: avoid; }",
		".report-body .suites { min-width: 0; }",
		"main:has(> .porch-report:not([hidden])) > :not(.porch-report) { display: none !important; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("the print rules no longer contain %q", want)
		}
	}
	// Marks a printer prints: drawn with a border, never only a fill.
	for _, selector := range []string{
		".report-key::before",
		".report-body :is(.mark-strong, .mark-weak, .mark-insecure)::before",
	} {
		body := rule(selector)
		if !strings.Contains(body, "border:") || strings.Contains(body, "background:") {
			t.Errorf("%s is drawn as a fill, which a browser leaves off paper: %s", selector, body)
		}
	}
}
