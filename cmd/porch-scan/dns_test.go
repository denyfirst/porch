package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsscan"
	"github.com/denyfirst/porch/internal/policy"
)

// Every check this command names is one it can run.
//
// -check wbe running the TLS check and exiting zero is a pipeline that
// believes it is testing something it has never tested; -check dns being
// refused by a binary that carries the check is the same failure from the
// other side, and a sabotage leaving it out of checkKnown escaped everything
// here until this existed.
func TestEveryCheckNamedCanBeRunAndReachesItsOwnCode(t *testing.T) {
	for _, name := range []string{checkTLS, checkWeb, checkMail, checkDNS} {
		if err := checkKnown(name); err != nil {
			t.Errorf("-check %s: %v", name, err)
		}
	}
	if err := checkKnown("wbe"); err == nil {
		t.Error("a misspelled check was accepted")
	} else if !strings.Contains(err.Error(), checkDNS) {
		t.Errorf("the refusal does not list every check: %v", err)
	}

	// And each one is dispatched to its own runner. Read from the source
	// because run() takes flags, prints and returns a status: a branch inside
	// it is a branch nothing here can drive, which is the same reason
	// limitsFor exists as a function.
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, pair := range [][2]string{
		{"case checkWeb:", "runWeb("},
		{"case checkMail:", "runMail("},
		{"case checkDNS:", "runDNS("},
	} {
		at := strings.Index(source, pair[0])
		if at < 0 {
			t.Errorf("run() has no branch for %q", pair[0])
			continue
		}
		rest := source[at:]
		if end := strings.Index(rest, "\tcase "); end > 0 {
			rest = rest[:end]
		}
		if !strings.Contains(rest, pair[1]) {
			t.Errorf("%q does not call %s", pair[0], pair[1])
		}
	}
}

// A DNS report says what was read and what it means, and says the two apart.
func TestTheDNSReportSaysWhatWasReadAndWhatItMeans(t *testing.T) {
	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain:  "example.com",
			Policy:  policy.DNSVersion,
			Verdict: policy.Weak,
			Notes: []policy.Note{
				policy.Observed("The zone is not signed."),
				policy.LimitDNSAsksTheResolver.Note(),
			},
			Observed: &policy.DNSFacts{
				Apex: true,
				IPv4: []string{"192.0.2.10"},
				Text: []string{"v=spf1 -all", "google-site-verification=abc"},
				NameServers: []policy.NameServer{
					{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}},
					{Name: "ns2.example.net"},
				},
				Networks:   1,
				SOAFound:   true,
				SOAPrimary: "ns1.example.net",
				SOASerial:  7,
				Signed:     true,
				Keys:       []policy.KeyDigest{{KeyTag: 1, Algorithm: 13}},
			},
		},
	})
	text := buf.String()

	for _, want := range []string{
		policy.DNSVersion,
		"192.0.2.10",
		"IPv6 (AAAA)          none",
		"Alias (CNAME)        none",
		"as published",
		"v=spf1 -all",
		"google-site-verification=abc",
		"ns1.example.net",
		"ns2.example.net",
		"resolves to nothing",
		"one network",
		"serial 7",
		"no key here matches its digest",
		dnsMethodPage,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}
}

// The records a domain publishes are bounded twice before they are printed: a
// TXT record is whatever somebody put there, and a report that printed all of
// it would be a report written by whoever is being measured.
func TestThePublishedRecordsAreBounded(t *testing.T) {
	long := strings.Repeat("x", 400)
	var records []string
	for range 11 {
		records = append(records, long)
	}

	var buf bytes.Buffer
	printText(&buf, records)
	text := buf.String()

	if strings.Contains(text, strings.Repeat("x", maxTextLength+1)) {
		t.Errorf("a record was printed in full:\n%s", text)
	}
	if !strings.Contains(text, "…") {
		t.Errorf("a record was cut without saying so:\n%s", text)
	}
	if lines := strings.Count(text, "…"); lines != maxTextShown {
		t.Errorf("%d records were printed, want the bound of %d", lines, maxTextShown)
	}
	if !strings.Contains(text, "and 3 more") {
		t.Errorf("the records left out are not counted:\n%s", text)
	}
	if !strings.Contains(text, "11 records, as published") {
		t.Errorf("the report does not say how many there are:\n%s", text)
	}

	// And each record is indented past the label column, so a reader running an
	// eye down the labels does not meet a zone's own text among them.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "x") &&
			!strings.HasPrefix(line, strings.Repeat(" ", 4+fieldWidth)) {
			t.Errorf("a published record starts in the label column:\n%q", line)
		}
	}
}

// A signed zone says which algorithm signs it and how it proves a name absent,
// in the words the page uses (R16), and an aliased name server is drawn as
// that rather than as an address.
func TestASignedZoneSaysItsAlgorithmAndHowItProvesAbsence(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`"named plainly, so the zone can be listed"`,
		`"hashed, " + iterations + " extra times"`,
		`row("Signed with (DNSKEY)", [...new Set(names)].join(", "));`,
		`text = "an alias for " + server.alias;`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain:  "example.com",
			Policy:  policy.DNSVersion,
			Verdict: policy.Strong,
			Observed: &policy.DNSFacts{
				Apex:            true,
				IPv4:            []string{"192.0.2.10"},
				Signed:          true,
				ChainMatched:    true,
				Keys:            []policy.KeyDigest{{KeyTag: 1, Algorithm: 13, Name: "ECDSAP256SHA256"}},
				NSEC3Read:       true,
				NSEC3:           true,
				NSEC3Iterations: 5,
				NameServers: []policy.NameServer{
					{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}},
					{Name: "ns2.example.net", Alias: "ns2.provider.example"},
				},
			},
		},
	})
	text := buf.String()

	for _, want := range []string{
		"Signed with (DNSKEY) ECDSAP256SHA256",
		"Absent (NSEC3)       hashed, 5 extra times",
		"ns2.example.net              an alias for ns2.provider.example",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}

	// An unsigned zone says none of it, because none of it applies.
	buf.Reset()
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain:   "example.com",
			Policy:   policy.DNSVersion,
			Observed: &policy.DNSFacts{Apex: true},
		},
	})
	if strings.Contains(buf.String(), "Signed with") || strings.Contains(buf.String(), "Absent") {
		t.Errorf("an unsigned zone was described as signed:\n%s", buf.String())
	}
}

// The two states only asking a server directly can produce are drawn in both
// faces: a server that does not answer for the zone, and one that answers for
// other domains as well.
func TestWhatAskingAServerFoundIsDrawnInBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`text = "does not answer for this zone";`,
		`text = text + " — answers for other domains too";`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion, Verdict: policy.Weak,
			Observed: &policy.DNSFacts{
				Apex: true,
				NameServers: []policy.NameServer{
					{Name: "ns1.example.com", Addresses: []string{"192.0.2.53"}, Asked: true, Authoritative: true, Recursion: true},
					{Name: "ns2.example.com", Addresses: []string{"198.51.100.53"}, Asked: true},
					{Name: "ns3.example.com", Addresses: []string{"203.0.113.53"}, AskedReason: "the lookup did not complete"},
				},
			},
		},
	})
	text := buf.String()

	for _, want := range []string{
		"ns1.example.com              192.0.2.53 — answers for other domains too",
		"ns2.example.com              does not answer for this zone",
		"ns3.example.com              203.0.113.53",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ns3.example.com              does not answer") {
		t.Errorf("a server that could not be asked was drawn as one that answered:\n%s", text)
	}
}

// The command line asks the zone's own servers, because it runs on the
// operator's machine from their address — the argument -allow-private rests on
// for the other checks. Read from the source, because runDNS takes flags and
// prints, so nothing here can drive the branch itself.
func TestTheCommandLineAsksTheZonesOwnServers(t *testing.T) {
	body, err := os.ReadFile("dns.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "dnsscan.Scanner{AskServers: true}") {
		t.Error("the command line no longer asks the servers the zone names")
	}
}

// What the zone above hands out is drawn in both faces, in all four states:
// not asked, not read, the same list, and a different one.
//
// Four and not two, because this is the line that says whether a resolver
// starting at the root reaches the servers the zone names. "The same servers"
// where nobody asked would be the worst sentence in the report.
func TestWhatTheZoneAboveHandsOutIsDrawnInBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`"The zone above this one was not asked which servers it delegates to."`,
		`" hands out the same servers."`,
		`"hands out " + atParent.join(", ") + " as well"`,
		`"does not hand out " + atZone.join(", ")`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	facts := func(f policy.DNSFacts) string {
		f.Apex = true
		f.NameServers = []policy.NameServer{
			{Name: "ns1.example.com", Addresses: []string{"192.0.2.53"}},
			{Name: "ns2.example.com", Addresses: []string{"198.51.100.53"}},
		}
		var buf bytes.Buffer
		printDNS(&buf, dnsResult{
			Domain: "example.com",
			Result: &dnsscan.Result{
				Domain: "example.com", Policy: policy.DNSVersion, Observed: &f,
			},
		})
		return buf.String()
	}

	for _, tc := range []struct {
		name  string
		facts policy.DNSFacts
		want  string
	}{
		{"not asked", policy.DNSFacts{}, "the zone above               not asked"},
		{
			"not read",
			policy.DNSFacts{Parent: "com", ParentReason: "the lookup did not complete"},
			"the zone above               not read: the lookup did not complete",
		},
		{
			"agreed",
			policy.DNSFacts{Parent: "com", ParentServer: "a.gtld.test", ParentAsked: true},
			"the zone above               com hands out the same servers",
		},
		{
			"both ways",
			policy.DNSFacts{
				Parent: "com", ParentServer: "a.gtld.test", ParentAsked: true,
				OnlyAtParent: []string{"ns9.example.com"},
				OnlyAtZone:   []string{"ns2.example.com"},
			},
			"com hands out ns9.example.com as well, and does not hand out ns2.example.com",
		},
	} {
		if text := facts(tc.facts); !strings.Contains(text, tc.want) {
			t.Errorf("%s: the report does not say %q:\n%s", tc.name, tc.want, text)
		}
	}
}

// At a name inside a zone, the chain is said to be unread rather than absent.
//
// Nothing about DNSSEC is asked there — the chain is a property of the zone,
// and the zone begins above the name. "Not signed" would be a claim about a
// zone this never looked at, and for the name that prompted this, the zone
// above was signed (R4).
func TestANameInsideAZoneSaysTheChainWasNotRead(t *testing.T) {
	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "www.example.com",
		Result: &dnsscan.Result{
			Domain: "www.example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{IPv4: []string{"192.0.2.10"}},
		},
	})
	text := buf.String()

	if !strings.Contains(text, "DNSSEC (DS)          not read: the chain belongs to the zone above this name") {
		t.Errorf("the report does not say the chain was not read:\n%s", text)
	}
	if strings.Contains(text, "not signed") {
		t.Errorf("a zone nobody asked about was reported unsigned:\n%s", text)
	}

	// And the top of a zone that publishes no delegation signer still reads as
	// what it is, so this did not silence the ordinary answer.
	buf.Reset()
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{Apex: true, SOAFound: true},
		},
	})
	if !strings.Contains(buf.String(), "DNSSEC (DS)          not signed") {
		t.Errorf("an unsigned zone no longer reads as one:\n%s", buf.String())
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if !strings.Contains(string(page), `if (!facts.apex) return "not read: the chain belongs to the zone above this name";`) {
		t.Error("the page still reports a zone nobody asked about as unsigned")
	}
}

// A server that hands out the whole zone says so in both faces.
//
// On the server's own line rather than in the notes alone, because it is the
// line a reader of that block acts on: every other row there says how the zone
// is reached, and this one says the whole of it can be taken.
func TestAServerThatHandsOutTheZoneIsDrawnInBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if !strings.Contains(string(page), `" — hands out the whole zone to anybody"`) {
		t.Error("the page does not draw a server that hands out the zone, so the two faces disagree")
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{
				Apex: true,
				NameServers: []policy.NameServer{
					{Name: "ns1.example.com", Addresses: []string{"192.0.2.53"}, Asked: true, Authoritative: true, TransferAsked: true, Transfer: true},
					{Name: "ns2.example.com", Addresses: []string{"198.51.100.53"}, Asked: true, Authoritative: true, TransferAsked: true},
				},
			},
		},
	})
	text := buf.String()

	if !strings.Contains(text, "ns1.example.com              192.0.2.53 — hands out the whole zone to anybody") {
		t.Errorf("the report does not say the zone can be taken:\n%s", text)
	}
	// And the server that refused reads as an ordinary one: a line on every
	// server would bury the one that matters.
	if !strings.Contains(text, "ns2.example.com              198.51.100.53\n") {
		t.Errorf("a server that refused a transfer was drawn as something else:\n%s", text)
	}
}

// The date the signatures run out is drawn in both faces.
//
// On its own row, because it is the one fact in that block which becomes
// wrong by itself: nobody changes anything, and on a date the zone stops
// resolving for everybody behind a validating resolver.
func TestWhenTheSignatureRunsOutIsDrawnInBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)
	for _, want := range []string{
		`facts.signatureRead && facts.signatureExpires`,
		`row("Signature (RRSIG)", "runs out " + facts.signatureExpires.slice(0, 10) +`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{
				Apex: true, SOAFound: true, Signed: true, ChainMatched: true,
				SignatureRead:    true,
				SignatureExpires: time.Date(2026, 10, 1, 3, 4, 5, 0, time.UTC),
				SignatureKeyTag:  53731,
			},
		},
	})
	if !strings.Contains(buf.String(), "Signature (RRSIG)    runs out 2026-10-01, made by key 53731") {
		t.Errorf("the report does not say when the signature runs out:\n%s", buf.String())
	}

	// A zone whose signature was not read says nothing rather than a date.
	buf.Reset()
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{Apex: true, SOAFound: true, Signed: true, ChainMatched: true},
		},
	})
	if strings.Contains(buf.String(), "Signature (RRSIG)") {
		t.Errorf("a signature nobody read was given a line:\n%s", buf.String())
	}
}

// Every line of the DNS report says which record it came from.
//
// What a reader does with this report is open their DNS provider's interface,
// and there the field is not called "alias" — it is called CNAME. The plain
// word stays in front for whoever does not know the type, which is the rule
// R16 states about the DNSSEC algorithm and is the same rule here.
func TestEveryLineSaysWhichRecordItCameFrom(t *testing.T) {
	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{
				Apex: true, SOAFound: true, SOASerial: 7, SOAPrimary: "ns1.example.net",
				IPv4: []string{"192.0.2.10"}, Text: []string{"v=spf1 -all"},
				Signed: true, ChainMatched: true, NSEC3Read: true, NSEC3: true,
				Keys:             []policy.KeyDigest{{KeyTag: 1, Algorithm: 13, Name: "ECDSAP256SHA256"}},
				SignatureRead:    true,
				SignatureExpires: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
				NameServers:      []policy.NameServer{{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}}},
			},
		},
	})
	text := buf.String()

	for _, want := range []string{
		"IPv4 (A)", "IPv6 (AAAA)", "Alias (CNAME)", "Zone (SOA)", "Text (TXT)",
		"DNSSEC (DS)", "Signed with (DNSKEY)", "Signature (RRSIG)", "Absent (NSEC3)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not label a line %q:\n%s", want, text)
		}
	}

	// The labels are one column, including the long one. "Signed with" ran two
	// characters past the others from the day it was added, and a block whose
	// labels are mostly aligned reads worse than one where they are not.
	for _, line := range strings.Split(text, "\n") {
		for _, label := range []string{"IPv4 (A)", "Zone (SOA)", "Signed with (DNSKEY)", "Absent (NSEC3)"} {
			if strings.HasPrefix(line, "    "+label) && !strings.HasPrefix(line, "    "+label+strings.Repeat(" ", fieldWidth-len(label))) {
				t.Errorf("the value after %q does not start in the same column:\n%s", label, line)
			}
		}
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	for _, want := range []string{
		`row("IPv4 (A)"`, `row("IPv6 (AAAA)"`, `row("Alias (CNAME)"`, `row("Zone (SOA)"`,
		`row("Text records (TXT)"`, `row("DNSSEC (DS)"`, `row("Signed with (DNSKEY)"`,
		`row("Signature (RRSIG)"`, `row("Absent names (NSEC3)"`, `"Server (NS)"`,
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}
}

// What the zone above hands out as a server's address is drawn in both faces.
func TestTheGlueTheZoneAboveHandsOutIsDrawnInBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	for _, want := range []string{
		`"The zone above hands out " + listOrNone(server.glue) + " for " + server.name + "."`,
		// And the guard that decides which servers get the line: a server
		// outside the zone it serves has no glue, and one inside it must not
		// be skipped.
		"    if (!server.glueRead) continue;",
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{
				Apex: true,
				NameServers: []policy.NameServer{
					{Name: "ns1.example.com", Addresses: []string{"192.0.2.53"}, GlueRead: true, Glue: []string{"192.0.2.99"}},
					{Name: "ns2.provider.net", Addresses: []string{"198.51.100.53"}},
				},
			},
		},
	})
	text := buf.String()

	if !strings.Contains(text, "ns1.example.com              the zone above hands out 192.0.2.99") {
		t.Errorf("the report does not say what the parent hands out:\n%s", text)
	}
	// And a server with no glue gets no line: a server outside the zone it
	// serves has none, and a line about every one of those would be about DNS
	// in general rather than about this zone.
	if strings.Contains(text, "ns2.provider.net             the zone above hands out") {
		t.Errorf("a server with no glue was given a line:\n%s", text)
	}
}
