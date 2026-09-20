package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/policy"
)

// mailSample is a domain with a policy worth printing.
func mailSample() mailResult {
	facts := policy.MailFacts{
		SPFRecords:   1,
		SPFAll:       "-",
		SPFLookups:   4,
		SPFIncludes:  []string{"spf.provider.example"},
		DMARCRecords: 1,
		DMARCPolicy:  "reject",
		DMARCPercent: 100,
	}
	graded := policy.GradeMail(facts)

	return mailResult{
		Domain: "example.test",
		Result: &mailscan.Result{
			Domain:   "example.test",
			Policy:   policy.MailVersion,
			Verdict:  graded.Verdict,
			Findings: graded.Findings,
			Notes:    graded.Notes,
			Observed: &facts,
		},
	}
}

func mailReport(t *testing.T, r mailResult) string {
	t.Helper()
	var b bytes.Buffer
	printMail(&b, r)
	return b.String()
}

func TestTheMailReportShowsWhatTheZoneSays(t *testing.T) {
	text := mailReport(t, mailSample())
	for _, want := range []string{
		"Sender policy", "ends in -all", "4 of the ten lookups allowed",
		"Authentication policy", "DMARC", "p=reject at 100%", "TLS-RPT",
		policy.MailVersion,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not carry %q:\n%s", want, text)
		}
	}
}

func TestTheMailReportNamesTheMailRuleSet(t *testing.T) {
	// Three rule sets in one binary now, and a report carrying the wrong name
	// sends a reader to a changelog that never mentions the rule that graded
	// them.
	text := mailReport(t, mailSample())
	for _, wrong := range []string{policy.TLSVersion, policy.WebVersion} {
		if strings.Contains(text, wrong) {
			t.Errorf("the mail report names %q:\n%s", wrong, text)
		}
	}
}

// Every check points its reader at its own page, and never at another's.
//
// The defect this was written for shipped and was caught by hand: the mail
// report ended with "porch-scan -limits, or https://denyfirst.dev/tls/method",
// which is a page about cipher suites and certificates under a report that
// looked at neither. The mail check had no page of its own then, and the rule
// was to print its limits in full rather than point anywhere. It has one now,
// and the rule that survives is the one that mattered: the page a report names
// describes the check that produced it.
func TestEveryCheckPointsAtItsOwnPage(t *testing.T) {
	text := mailReport(t, mailSample())

	if !strings.Contains(text, mailMethodPage) {
		t.Errorf("the mail report does not point at %s:\n%s", mailMethodPage, text)
	}
	for _, wrong := range []string{tlsMethodPage, webMethodPage, dnsMethodPage} {
		if strings.Contains(text, wrong) {
			t.Errorf("the mail report sends its reader to %s, which describes a different "+
				"check:\n%s", wrong, text)
		}
	}

	// And each check's -limits names its own page beside its own limits.
	for check, page := range map[string]string{
		checkTLS:  tlsMethodPage,
		checkWeb:  webMethodPage,
		checkMail: mailMethodPage,
		checkDNS:  dnsMethodPage,
	} {
		var buf bytes.Buffer
		limits, named := limitsFor(check)
		if named != page {
			t.Errorf("-check %s names the page %q, want %q", check, named, page)
		}
		if len(limits) == 0 {
			t.Errorf("-check %s declares no limits", check)
			continue
		}
		printLimits(&buf, limits, named)
		if !strings.Contains(buf.String(), "Read alongside") {
			t.Errorf("-check %s -limits no longer points at %s", check, page)
		}
		for _, l := range limits {
			if !strings.Contains(buf.String(), l.Title) {
				t.Errorf("-check %s -limits omits %q", check, l.ID)
			}
		}
	}
}

// A mail limit is not a TLS limit and not a web limit.
func TestTheThreeChecksDeclareDifferentLimits(t *testing.T) {
	sets := map[string][]policy.StandingLimit{
		checkTLS:  policy.StandingLimits(),
		checkWeb:  policy.WebStandingLimits(),
		checkMail: policy.MailStandingLimits(),
	}
	seen := map[string]string{}
	for check, limits := range sets {
		for _, l := range limits {
			if other, ok := seen[l.ID]; ok {
				t.Errorf("%s appears under both -check %s and -check %s", l.ID, other, check)
			}
			seen[l.ID] = check
		}
	}
}

// A domain that could not be scanned exits non-zero, and one that was scanned
// and graded exits by its verdict — the same two numbers the other checks use.
func TestTheMailExitStatusMatchesTheOtherChecks(t *testing.T) {
	failed := mailResult{Domain: "example.test", Error: "refused"}
	if got := exitCode(mailOutcomes([]mailResult{failed})); got == 0 {
		t.Error("a domain that could not be scanned exited zero")
	}

	good := mailSample()
	if got := exitCode(mailOutcomes([]mailResult{good})); got != 0 {
		t.Errorf("a correctly configured domain exited %d", got)
	}

	broken := mailSample()
	broken.Verdict = policy.Insecure
	if got := exitCode(mailOutcomes([]mailResult{broken})); got == 0 {
		t.Error("an insecure domain exited zero")
	}
}

// A record with no all mechanism is described, never printed as "ends in all".
func TestAPolicyWithNoAllIsNotPrintedAsHavingOne(t *testing.T) {
	if got := allOrNone(""); got != "no " {
		t.Errorf("allOrNone(\"\") = %q, want %q", got, "no ")
	}
	for _, q := range []string{"-", "~", "?", "+"} {
		if got := allOrNone(q); got != q {
			t.Errorf("allOrNone(%q) = %q", q, got)
		}
	}
}

// The command line reads the MTA-STS policy.
//
// Asserted because the alternative is a field that is set, documented and handed
// to nothing — which has happened twice in this repository, and which a sabotage
// found again by turning ReadMarkup off here and watching every test pass.
func TestTheCommandLineReadsTheSTSPolicy(t *testing.T) {
	s := mailScanner(5*time.Second, nil, "")

	if !s.ReadSTSPolicy {
		t.Error("the command line does not read the MTA-STS policy. It runs on the operator's " +
			"own machine, from their own address, and the report goes to whoever ran it — so a " +
			"report saying only that a policy is announced is withholding the one fact DNS " +
			"cannot carry.")
	}
	if s.STS == nil {
		t.Error("no fetcher was installed, so the flag above is set and nothing acts on it")
	}
}

// Four states on the MTA-STS row, not two.
//
// "announced" on its own covers a domain fully protected and a domain that has
// been rehearsing for two years, and telling those apart is the whole reason the
// policy is fetched. R16 says the browser draws the same four (see stsSays).
func TestTheMTASTSRowSaysWhatWasRead(t *testing.T) {
	for name, tc := range map[string]struct {
		facts policy.MailFacts
		want  string
	}{
		"nothing announced": {
			facts: policy.MailFacts{},
			want:  "no",
		},
		"announced and not read": {
			facts: policy.MailFacts{MTASTSRecords: 1,
				MTASTSPolicyReason: "this deployment reads the record and not the policy file"},
			want: "not read: this deployment reads the record",
		},
		"read and enforcing": {
			facts: policy.MailFacts{MTASTSRecords: 1, MTASTSPolicyRead: true,
				MTASTSMode: "enforce"},
			want: "mode enforce",
		},
		"read and testing": {
			facts: policy.MailFacts{MTASTSRecords: 1, MTASTSPolicyRead: true,
				MTASTSMode: "testing"},
			want: "mode testing",
		},
		"read and naming no mode": {
			facts: policy.MailFacts{MTASTSRecords: 1, MTASTSPolicyRead: true},
			want:  "names no mode",
		},
		"enforcing and excluding an exchanger": {
			facts: policy.MailFacts{MTASTSRecords: 1, MTASTSPolicyRead: true,
				MTASTSMode:      "enforce",
				MXHosts:         []string{"mx1.example.net", "mx2.example.net"},
				MTASTSUncovered: []string{"mx2.example.net"}},
			want: "1 of the 2 exchangers not covered",
		},
	} {
		facts := tc.facts
		if got := stsLine(&facts); !strings.Contains(got, tc.want) {
			t.Errorf("%s: the row says %q, and does not carry %q", name, got, tc.want)
		}
	}

	// And a policy that was read is never drawn as one that was not. The
	// reassuring direction is the other one, so this is the assertion that
	// matters: a reader told "not read" goes and looks, and a reader told
	// "mode enforce" about a policy nobody fetched does not.
	read := policy.MailFacts{MTASTSRecords: 1, MTASTSPolicyRead: true, MTASTSMode: "testing"}
	if got := stsLine(&read); strings.Contains(got, "not read") {
		t.Errorf("a policy that was read is drawn as unread: %q", got)
	}
}

// A lookup count that is a lower bound says so on the terminal, in the words the
// page uses (R16).
func TestALowerBoundLookupCountIsSaidAsOne(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if !strings.Contains(string(page), `facts.spfLookupsAtLeast ? "at least " : ""`) {
		t.Error("the page does not read spfLookupsAtLeast, so the two faces disagree about the count")
	}

	r := mailSample()
	r.Observed.SPFLookups = 11
	r.Observed.SPFLookupsAtLeast = true
	var buf bytes.Buffer
	printMail(&buf, r)
	if !strings.Contains(buf.String(), "at least 11 of the ten lookups allowed") {
		t.Errorf("the SPF line does not say the count is a lower bound:\n%s", buf.String())
	}
}

// The relay answer reaches both faces of the report, in the same words (R16).
//
// Three states, and a row only where the question was put: an exchanger that
// was never asked says nothing here, because a blank row reads as an answer.
func TestTheRelayAnswerReachesBothFacesOfTheReport(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`"forwards mail for a domain it does not serve"`,
		`"refuses to forward for other domains"`,
		`"not established: " + x.relayReason`,
		`row("RELAY", x.host + ": " + relaySays(x)`,
		// And the function the row calls exists under that name: a page whose
		// call and definition disagree is a page that throws where the row
		// should be, and no text test sees a name that is merely absent.
		"function relaySays(x) {",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	r := mailSample()
	r.Observed.Exchangers = []policy.ExchangerTLS{
		{Host: "mail.example.com", Measured: true, RelayAsked: true, RelayAccepted: true},
		{Host: "mx2.example.com", Measured: true, RelayAsked: true, RelayReason: "the server refused it (554)"},
		{Host: "aspmx.provider.net", Measured: true},
	}
	r.Observed.MXRead = true
	r.Observed.MXHosts = []string{"mail.example.com", "mx2.example.com", "aspmx.provider.net"}
	r.Observed.ExchangersContacted = true

	var buf bytes.Buffer
	printMail(&buf, r)
	text := buf.String()

	for _, want := range []string{
		"RELAY      mail.example.com: forwards mail for a domain it does not serve",
		"RELAY      mx2.example.com: refuses to forward for other domains",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "RELAY      aspmx.provider.net") {
		t.Errorf("an exchanger that was never asked has a relay row:\n%s", text)
	}
}
