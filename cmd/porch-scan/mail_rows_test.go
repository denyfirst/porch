package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
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
	if !strings.Contains(counted, "DANE       1 of the 2: a.example.net") {
		t.Errorf("the count is wrong:\n%s", counted)
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
