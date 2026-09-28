package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/certinfo"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/scan"
)

// Nothing is left out of a report because it was empty.
//
// Eight rows in the certificate block were drawn only when there was something
// to put in them, so a certificate with no names, or a scan that never searched
// the transparency logs, produced a report with the row simply missing. A row
// that is not there reads as a question nobody had; a row saying "not checked"
// reads as what it is, and the difference decides what a reader does next (R4).
//
// "Logged" is the one that made the case. Empty means nothing asked the public
// logs what else exists for this name, and a reader who could not see the row
// had no way to tell that from "nothing else exists".
func TestNothingIsLeftOutOfTheCertificateBlockBecauseItIsEmpty(t *testing.T) {
	var buf bytes.Buffer
	printCertificate(&buf, result{Result: &scan.Result{
		Certificate: &certinfo.Report{
			Chain: []certinfo.Certificate{{
				Subject:            "CN=example.com",
				Issuer:             "CN=Example CA",
				NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				KeyAlgorithm:       "ECDSA",
				KeyBits:            256,
				SignatureAlgorithm: "ECDSA-SHA256",
				FingerprintSHA256:  "ab:cd",
			}},
			Grade: policy.LeafFinding{DaysRemaining: 30, ValidityDays: 90, MaxValidityDays: 398},
		},
	}})
	text := buf.String()

	// Every row is present, and each says which kind of nothing it found.
	for _, want := range []string{
		"Validation   not stated by the certificate",
		"Names        none",
		"Addresses    none",
		"Revocation   not checked",
		"Issuance     not read",
		"Transparency not read",
		"Logged       not searched",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	script := string(page)

	// The page drew these the same way and stopped for the same reason: its
	// helper returned early on an empty value.
	if !strings.Contains(script, `if (value === undefined || value === null || value === "") value = absent || "none";`) {
		t.Error("the page's row helper does not turn an empty value into words, so the row is dropped")
	}
	for _, want := range []string{
		`pair("Validation", leaf.validation, "not stated by the certificate");`,
		`pair("Names", (leaf.dnsNames || []).join(", "), "none");`,
		`pair("Addresses", (leaf.ipAddresses || []).join(", "), "none");`,
		`pair("Revocation", report && report.revocationLine, "not checked");`,
		`pair("Issuance", issuance && issuance.line, "not read");`,
		`pair("Transparency", report && report.transparencyLine, "not read");`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page does not carry %s, so the two faces disagree", want)
		}
	}
}

// The certificates the Logged line counts are printed under it, in the words
// internal/policy wrote, and the page draws the same field (R16).
func TestTheCertificatesTheLoggedLineCountsArePrinted(t *testing.T) {
	stranger := policy.UnaccountedLine("0badc0de", "CN=Somebody Else", []string{"example.com"},
		time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))

	var buf bytes.Buffer
	printCertificate(&buf, result{Result: &scan.Result{
		Certificate: &certinfo.Report{
			Chain: []certinfo.Certificate{{Subject: "CN=example.com", Issuer: "CN=Example CA"}},
		},
		LoggedLine:        "2 certificates for this exact name, one of which is valid today and was not the one presented here",
		LoggedUnaccounted: []string{stranger},
	}})
	text := buf.String()
	for _, want := range []string{"serial 0badc0de", "CN=Somebody Else", "2026-09-01 to 2026-12-01"} {
		if !strings.Contains(text, want) {
			t.Errorf("the terminal does not print %q under the Logged line:\n%s", want, text)
		}
	}
	if logged, listed := strings.Index(text, "Logged"), strings.Index(text, "serial 0badc0de"); listed < logged {
		t.Errorf("the certificates are not under the line that counts them:\n%s", text)
	}

	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "report.loggedUnaccounted") {
		t.Error("the page does not draw the certificates the Logged line counts")
	}
}
