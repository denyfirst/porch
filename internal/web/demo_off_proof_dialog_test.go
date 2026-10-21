//go:build !demo

package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/verify"
)

// The proof dialog is on the console, because every installation requires
// proof.
func TestTheProofDialogIsOfferedOnlyWhereProofIsRequired(t *testing.T) {
	bounded := consoleAs(t)
	for _, want := range []string{`id="proof-dialog"`, `data-proof="required"`, `id="proof-name"`, `id="proof-value"`} {
		if !strings.Contains(bounded, want) {
			t.Errorf("the console has no %s", want)
		}
	}
}

// The checks run only after the proof is asked for, and the script asks the
// endpoint the service registers.
func TestTheConsoleAsksForProofBeforeItRuns(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if !strings.Contains(src, `const VERIFY = { endpoint: "/api/v1/verify" };`) {
		t.Error("the script does not ask /api/v1/verify")
	}
	proof := strings.Index(src, "if (!(await proven(target))) return;")
	run := strings.Index(src, "await reportRun(frame, entry, () => check(target, entry.spec, selectorsAsked(entry.name)));")
	if proof < 0 || run < 0 || proof > run {
		t.Error("the checks can run before proof is asked for")
	}
	if !strings.Contains(src, `consoleForm.dataset.proof !== "required"`) {
		t.Error("the script asks for proof on an installation that requires none")
	}
	if !strings.Contains(src, "if (answer.verified) {") {
		t.Error("the dialog does not end when the record is seen")
	}
}

// A name that is not proven is not let through.
func TestAnUnprovenNameOpensTheDialog(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		"if (!answer.required || answer.verified) return true;",
		"return waitForProof(target, answer);",
		"cancel.onclick = () => finish(false);",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the proof flow no longer contains %q", want)
		}
	}
}

// Both places that show the record default to the name itself, the first in
// the list, and never to the broadest (audit 2026-09-18, D05): the last entry
// for www.shop.co.uk is co.uk, a zone its owner does not run. A parent is
// the operator's choice, and the hint says what choosing one gives away.
func TestTheProofDefaultsToTheNameItself(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, fill := range []string{"function fillProof(records) {", "function showDomainRecord(answer) {"} {
		start := strings.Index(src, fill)
		if start < 0 {
			t.Fatalf("the script no longer has %q", fill)
		}
		end := strings.Index(src[start:], "\n}\n")
		fn := src[start : start+end]
		if !strings.Contains(fn, `level.value = "0";`) {
			t.Errorf("%s does not default to the name itself", fill)
		}
		if strings.Contains(fn, "records.length - 1") {
			t.Errorf("%s still reaches for the broadest domain", fill)
		}
	}
	for _, page := range []string{"assets/console.html", "assets/domains.html"} {
		if !strings.Contains(asset(t, page), "choose one only if you run its DNS") {
			t.Errorf("%s does not say what a domain above the name gives away", page)
		}
	}
}

// Domains says whether the proof was signed, as the resolver's word (A06).
func TestDomainsSaysWhetherTheProofWasSigned(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`"The resolver reported the record DNSSEC-signed."`,
		`"Whether the record is DNSSEC-signed was not asked: -verification-requires-dnssec asks."`,
		`answer.signed ? "proven, signed" : "proven"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer says %s", want)
		}
	}

	// The record is read from the zone's own servers, so no proof rests on a
	// resolver's answer, and an unasked question is not a finding.
	if strings.Contains(src, "rests on the resolver's answer alone") {
		t.Error("app.js says a proof rests on the resolver, which reads nothing from one")
	}
}

// The DNS report says which address kind found nothing, keeps the records the
// domain publishes apart from the sentences this program writes, and the
// console heading no longer repeats a verdict the report carries.
func TestTheDNSReportSeparatesWhatWasReadFromWhatWasWritten(t *testing.T) {
	src := script(t)

	for _, want := range []string{
		`row("IPv4 (A)", listOrNone(facts.ipv4));`,
		`row("IPv6 (AAAA)", listOrNone(facts.ipv6));`,
		`row("Alias (CNAME)", "none");`,
		`sectionTitle("Text records, as published")`,
		"function textRecords(records) {",
		"records.slice(0, 8)",
		"record.slice(0, 120)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer carries %s", want)
		}
	}

	// The published records are written as text and never as markup, which is
	// the rule the whole script is built on.
	block := src[strings.Index(src, "function textRecords(records) {"):]
	block = block[:strings.Index(block, "\n}\n")]
	if !strings.Contains(block, "list.textContent =") || strings.Contains(block, "innerHTML") {
		t.Errorf("the published records are not written as text:\n%s", block)
	}

	// And one result is said once in its section: the column beside the
	// evidence carries the report's own stamp, and nothing else in the section
	// repeats it. The tile on the cover is the index to it, and says the
	// states a report cannot show — running, and a check that did not run.
	show := functionBody(t, src, "reportShow")
	if strings.Count(show, "summary(data)") != 1 {
		t.Error("a check's section does not carry its verdict exactly once")
	}
	run := functionBody(t, src, "reportRun")
	if !strings.Contains(run, `entry.state.textContent = "not run";`) {
		t.Error("a check that did not run is not said to have not run")
	}
}

// Where the name goes at the common providers, the same on both pages that
// show a record, and saying what it is not.
//
// Help with a form, never a list of where the record is looked for: it is
// read from whichever servers the zone names. A provider chosen from a list
// would prove less than the zone does — a zone moved elsewhere is still its
// owner's — so the page says so, where somebody would otherwise assume it.
func TestTheProviderHelpIsTheSameWhereverARecordIsShown(t *testing.T) {
	block := func(page string) string {
		src := asset(t, page)
		start := strings.Index(src, `<details class="provider-help">`)
		end := -1
		if start >= 0 {
			if n := strings.Index(src[start:], "</details>"); n >= 0 {
				end = start + n
			}
		}
		if start < 0 || end < start {
			t.Fatalf("%s has no provider help beside its record", page)
		}
		var lines []string
		for _, line := range strings.Split(src[start:end], "\n") {
			lines = append(lines, strings.TrimSpace(line))
		}
		return strings.Join(lines, "\n")
	}

	console, domains := block("assets/console.html"), block("assets/domains.html")

	// The one rule nearly every provider needs is also said outside the fold,
	// under the record, with the short name ready to copy. On 2026-10-20 the
	// full name typed into deSEC's Subname was served as
	// _porch-challenge.denyfirst.dev.denyfirst.dev, the help that says so was
	// closed, and the name typed again by hand came back misspelt.
	for page, id := range map[string]string{"assets/console.html": "proof-label", "assets/domains.html": "domain-label"} {
		src := asset(t, page)
		record := strings.Index(src, `<dl class="proof-record">`)
		short := strings.Index(src, `<p class="proof-hint proof-short">Most providers add your domain to the name themselves: type only the part before it.`)
		help := strings.Index(src, `<details class="provider-help">`)
		if record < 0 || short < record || help < short {
			t.Errorf("%s does not say under the record, outside the fold, to type only the part before the domain", page)
		}
		if !strings.Contains(src, `<code id="`+id+`">`+verify.Label+`</code> <button class="proof-copy" type="button" data-copy="`+id+`">Copy</button>`) {
			t.Errorf("%s does not offer %s to copy", page, verify.Label)
		}
	}
	if console != domains {
		t.Error("the provider help differs between the console and the Domains page")
	}
	for _, want := range []string{
		"type only the part before it",
		"<td>Cloudflare</td>",
		"<td>deSEC</td><td>Subname</td>",
		"<td>Amazon Route 53</td><td>Record name, with the value inside double quotes</td>",
		"not part of the proof",
		"whichever servers your zone names",
	} {
		if !strings.Contains(console, want) {
			t.Errorf("the provider help does not say %q", want)
		}
	}
}
