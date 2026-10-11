package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/certinfo"
	"github.com/denyfirst/porch/internal/dnsscan"
	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/scan"
)

// What the checks measured all along is on both faces, under the same labels
// (R16).
//
// The zone's SOA timers and contact, its keys and the digests the parent holds,
// when its signature was made, each name server's serial, the SPF policy's
// void lookups, how long senders keep the MTA-STS policy, whether the
// certificate covers the name and what is above it in the chain: every one
// was in the JSON, and none, or only a folded note, reached a reader.
func TestWhatWasMeasuredIsOnBothFaces(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(page)
	for _, want := range []string{
		`row("Timers (SOA)", facts.timersLine)`,
		`row("Mailbox (SOA)", facts.soaMailbox)`,
		`row("Keys (DNSKEY)", facts.keysLine)`,
		`row("Digests (DS)", facts.digestLine)`,
		`["Server (NS)", "Addresses", "Serial (SOA)"]`,
		`row("Void lookups", facts.spfVoidLookups + " of the two RFC 7208 allows",`,
		`out += ", max_age " + maxAge(facts.mtaStsMaxAge);`,
		`pair("Name match", cert.nameLine, "not checked");`,
		"for (const line of cert.chainLines || []) {",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s", want)
		}
	}

	var buf bytes.Buffer
	printDNS(&buf, dnsResult{
		Domain: "example.com",
		Result: &dnsscan.Result{
			Domain: "example.com", Policy: policy.DNSVersion,
			Observed: &policy.DNSFacts{
				Apex: true, SOAFound: true, Signed: true, ChainMatched: true,
				SOASerial: 7, SOAPrimary: "ns1.example.net", SOAMailbox: "hostmaster.example.com",
				TimersLine: "refresh 1d, retry 1h, expire 28d, negative answers kept 1h",
				Keys:       []policy.KeyDigest{{KeyTag: 53731, Algorithm: 13, Name: "ECDSAP256SHA256", KeySigning: true}},
				KeysLine:   "key 53731, key signing, ECDSAP256SHA256",
				DigestLine: "key 53731, SHA-256, matches a key here",
				NameServers: []policy.NameServer{{Name: "ns1.example.net", Addresses: []string{"192.0.2.1"},
					Asked: true, Authoritative: true, Serial: 7, SerialRead: true}},
			},
		},
	})
	for _, want := range []string{
		"Timers (SOA)         refresh 1d, retry 1h, expire 28d, negative answers kept 1h",
		"Mailbox (SOA)        hostmaster.example.com",
		"Keys (DNSKEY)        key 53731, key signing, ECDSAP256SHA256",
		"Digests (DS)         key 53731, SHA-256, matches a key here",
		"192.0.2.1, serial 7",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the terminal does not print %q:\n%s", want, buf.String())
		}
	}
	// The keys line names the algorithm, so it is not said a second time.
	if strings.Contains(buf.String(), "Signed with") {
		t.Errorf("the algorithm is said twice beside the keys line:\n%s", buf.String())
	}

	buf.Reset()
	printMail(&buf, mailResult{Domain: "example.com", Result: &mailscan.Result{Observed: &policy.MailFacts{
		SPFRecords: 1, SPFAll: "-", SPFLookups: 3, SPFVoidLookups: 1,
		MTASTSRecords: 1, MTASTSPolicyRead: true, MTASTSMode: "enforce", MTASTSMaxAge: 604800,
	}}})
	for _, want := range []string{
		"Void lookups 1 of the two RFC 7208 allows",
		"mode enforce, max_age 7 days",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the terminal does not print %q:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	printCertificate(&buf, result{Result: &scan.Result{Certificate: &certinfo.Report{
		Chain: []certinfo.Certificate{
			{Subject: "CN=example.com", NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
			{Subject: "CN=Example CA"},
		},
		Trusted:    true,
		NameLine:   "covers the name asked for",
		ChainLines: []string{"CN=CA: ECDSA 384, runs out 2028-09-02, an authority"},
	}}})
	for _, want := range []string{
		"Name match   covers the name asked for",
		"· CN=CA: ECDSA 384, runs out 2028-09-02, an authority",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the terminal does not print %q:\n%s", want, buf.String())
		}
	}
}

// An MTA-STS max_age is said in the unit it was most likely chosen in, in the
// same words on both faces.
func TestAMaxAgeReadsInItsOwnUnit(t *testing.T) {
	for seconds, want := range map[int]string{
		86400: "1 day", 604800: "7 days", 31557600: "8766 hours", 7200: "2 hours", 90: "90 seconds", 1: "1 second",
	} {
		if got := maxAge(seconds); got != want {
			t.Errorf("maxAge(%d) = %q, want %q", seconds, got, want)
		}
	}
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`if (seconds % 86400 === 0) return unit(seconds / 86400, "day");`,
		`if (seconds % 3600 === 0) return unit(seconds / 3600, "hour");`,
		`return unit(seconds, "second");`,
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the page's maxAge no longer reads %s", want)
		}
	}
}
