package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

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
		"porch-dns-v1",
		"192.0.2.10",
		"IPv6       none",
		"Alias      none",
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
}
