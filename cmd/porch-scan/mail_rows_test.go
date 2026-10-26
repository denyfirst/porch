package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/dnsscan"
	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/webprobe"
	"github.com/denyfirst/porch/internal/webscan"
)

// The rows under MX are drawn whatever the MX row says.
//
// Three of the four MX states used to end the block, so a domain whose MX
// lookup failed, or that accepts no mail, was shown no MTA-STS row and no DANE
// row at all. MTA-STS is a separate lookup at a separate name and may well have
// answered; a reader who could not see the row had no way to tell a domain that
// announces no policy from one nobody asked about (R4).
func TestTheMailPathDrawsItsRowsWhateverTheMXSays(t *testing.T) {
	draw := func(f policy.MailFacts) string {
		var buf bytes.Buffer
		printMailPath(&buf, &f)
		return buf.String()
	}

	for _, tc := range []struct {
		name  string
		facts policy.MailFacts
		dane  string
	}{
		{"the lookup failed", policy.MailFacts{MXReason: "the lookup did not complete"},
			"DANE       not checked: the exchangers are not known"},
		{"the domain accepts no mail", policy.MailFacts{MXRead: true, NullMX: true},
			"DANE       not checked: the domain accepts no mail"},
		{"nothing was read", policy.MailFacts{},
			"DANE       not checked: the exchangers are not known"},
		{"no exchanger is published", policy.MailFacts{MXRead: true},
			"DANE       not checked: the domain publishes no exchanger"},
	} {
		text := draw(tc.facts)
		if !strings.Contains(text, "MTA-STS") {
			t.Errorf("%s: the MTA-STS row is missing, and it is a separate lookup:\n%s", tc.name, text)
		}
		if !strings.Contains(text, tc.dane) {
			t.Errorf("%s: the report does not say %q:\n%s", tc.name, tc.dane, text)
		}
	}

	// And a domain with exchangers still counts them.
	counted := draw(policy.MailFacts{
		MXRead: true, MXHosts: []string{"a.example.net", "b.example.net"},
		DANEHosts: []string{"a.example.net"},
	})
	if !strings.Contains(counted, "DANE       at 1 of the 2 exchangers: a.example.net") {
		t.Errorf("the count is wrong:\n%s", counted)
	}
	// And names what it counts where it counts nothing.
	none := draw(policy.MailFacts{MXRead: true, MXHosts: []string{"a.example.net", "b.example.net"}})
	if !strings.Contains(none, "DANE       none at the 2 exchangers") {
		t.Errorf("the count does not say what it counted:\n%s", none)
	}

	// An exchanger nobody spoke to says so, even where the reason was not
	// recorded: this returned in silence when it was empty.
	silent := draw(policy.MailFacts{MXRead: true, MXHosts: []string{"a.example.net"}})
	if !strings.Contains(silent, "STARTTLS   not measured: this scan did not contact them") {
		t.Errorf("an exchanger nobody asked was drawn as nothing at all:\n%s", silent)
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		// Two spaces of indentation, which in this file is the top level of
		// the function. Nested one branch deeper the row still exists and is
		// still drawn from the same helper — and is lost whenever the MX was
		// not read, which is the whole fault.
		"\n  row(\"MTA-STS\", stsSays(facts));\n",
		"\n  row(\"DANE\", daneSummary(facts));\n",
		`"not checked: the exchangers are not known"`,
		`"not measured: " + (facts.exchangersReason || "this scan did not contact them")`,
		// An unread record is drawn as unread on both faces (2026-10-25).
		`row("TLS-RPT", facts.tlsReportingReason ? "not read: " + facts.tlsReportingReason`,
		`return "not read: " + facts.mtaStsReason;`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}
}

// A chain nothing was attempted at says so, in both faces.
//
// The terminal skipped the heading as well as the rows, so a report with no
// plaintext section left a reader unable to tell an address nothing was tried
// at from a section that had been left out. The page has carried the sentence
// since it was written (R16, R4).
func TestAChainNothingWasAttemptedAtSaysSo(t *testing.T) {
	var buf bytes.Buffer
	printChains(&buf, webResult{
		Host: "example.com",
		Result: &webscan.Result{
			Host: "example.com", Policy: policy.WebVersion,
			Observed: &webprobe.Report{
				Secure: &webprobe.Chain{Hops: []webprobe.Hop{{Status: 200, URL: "https://example.com/"}}},
			},
		},
	})
	text := buf.String()

	if !strings.Contains(text, "Over plaintext") {
		t.Errorf("the heading for the address nothing was tried at is missing:\n%s", text)
	}
	if !strings.Contains(text, "Nothing was attempted at this address.") {
		t.Errorf("the report does not say nothing was attempted:\n%s", text)
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if !strings.Contains(string(page), `"Nothing was attempted at this address."`) {
		t.Error("the page no longer carries the sentence, so the two faces disagree")
	}
}

// The DKIM row is drawn by the page alone, so its wording is held here: a
// selector whose lookup failed is not one that holds no key, and a resolver
// that answered none of them is not a domain with no keys at the names tried
// (R4). Until 2026-10-26 it drew "none at the selectors tried" either way.
func TestTheDKIMRowDoesNotCallAnUnreadSelectorEmpty(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(page)
	start := strings.Index(src, "if (facts.dkimLooked) {")
	if start < 0 {
		t.Fatal("the page no longer draws a DKIM row")
	}
	end := strings.Index(src[start:], `row("DKIM", "not checked: a selector has to be named");`)
	if end < 0 {
		t.Fatal("the DKIM row's branches could not be found")
	}
	body := src[start : start+end]

	// In this order: what was found, then nothing read, then some read, and
	// only then "none", so "none" is never reached with a selector unread.
	at := 0
	for _, piece := range []string{
		`const unread = keys.filter(k => k.reason).length;`,
		`if (found.length) {`,
		`} else if (unread === keys.length) {`,
		`"not read: none of the " + keys.length + " selectors tried could be read"`,
		`} else if (unread) {`,
		`" selectors tried that answered" + notRead`,
		`} else {`,
		`row("DKIM", "none at the " + keys.length + " selectors tried");`,
	} {
		i := strings.Index(body[at:], piece)
		if i < 0 {
			t.Fatalf("the DKIM row does not have, in its place, %s", piece)
		}
		at += i + len(piece)
	}
}

// A grade withheld where something was measured says why, on both faces.
//
// Until 2026-10-26 both said nothing had been measured under every ungraded
// verdict: a domain whose SPF, DMARC, DKIM and MTA-STS were all read, and
// whose exchangers the scanning machine could not reach on port 25, read as
// one nothing was known about (R4a). Nothing measured at all still says so.
func TestAWithheldGradeSaysWhyOnBothFaces(t *testing.T) {
	why := "not every mail exchanger was measured"
	var buf bytes.Buffer
	printMail(&buf, mailResult{Domain: "example.test", Result: &mailscan.Result{
		Domain: "example.test", Policy: policy.MailVersion, Withheld: why,
		Observed: &policy.MailFacts{},
	}})
	if out := buf.String(); !strings.Contains(out, "Verdict   ungraded ("+why+")") || strings.Contains(out, "nothing was established") {
		t.Errorf("the terminal does not say why the mail grade was withheld:\n%s", out)
	}

	buf.Reset()
	printDNS(&buf, dnsResult{Domain: "example.test", Result: &dnsscan.Result{
		Domain: "example.test", Policy: policy.DNSVersion, Withheld: "something the DNS rules read was not established",
		Observed: &policy.DNSFacts{Apex: true, SOAFound: true},
	}})
	if out := buf.String(); !strings.Contains(out, "Verdict   ungraded (something the DNS rules read was not established)") ||
		strings.Contains(out, "no zone begins") {
		t.Errorf("the terminal does not say why the DNS grade was withheld:\n%s", out)
	}

	// The TLS and web checks the same way.
	buf.Reset()
	printReport(&buf, result{Result: &scan.Result{Target: "example.test:443", Policy: policy.TLSVersion,
		Withheld: "the transport was not graded; why is said below"}})
	if !strings.Contains(buf.String(), "Verdict   ungraded (the transport was not graded; why is said below)") {
		t.Errorf("the terminal does not say why the TLS grade was withheld:\n%s", buf.String())
	}
	buf.Reset()
	printWebReport(&buf, webResult{Host: "example.test", Result: &webscan.Result{
		Withheld: "where the site leads a visitor was not established; why is said below"}})
	if !strings.Contains(buf.String(), "Verdict   ungraded (where the site leads a visitor was not established; why is said below)") {
		t.Errorf("the terminal does not say why the web grade was withheld:\n%s", buf.String())
	}

	// Nothing measured, and nothing withheld: the old line, which is then true.
	buf.Reset()
	printMail(&buf, mailResult{Domain: "example.test", Result: &mailscan.Result{
		Domain: "example.test", Policy: policy.MailVersion, Observed: &policy.MailFacts{},
	}})
	if !strings.Contains(buf.String(), "ungraded (nothing was found wrong, and nothing was established)") {
		t.Errorf("an ungraded mail check with no reason reads:\n%s", buf.String())
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(page)
	reason := strings.Index(src, `if (verdict === "ungraded" && data.withheld) {`)
	said := strings.Index(src, `"Not graded: " + data.withheld + ". What was measured is below; a verdict on part of it would read as one on the whole."`)
	absent := strings.Index(src, `"Nothing was measured, so nothing could be graded. This is not a clean result; it is an absent one."`)
	if reason < 0 || said < reason || absent < said || strings.Count(src, "Nothing was measured, so nothing could be graded") != 1 {
		t.Error("the page says nothing was measured before it asks whether a grade was withheld, so the two faces disagree")
	}
}
