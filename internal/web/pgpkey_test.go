package web

import (
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// The fingerprint is written in three places in this repository and they have
// to agree: the constant, SECURITY.md, and the card on Porch's page that tells
// a reporter to compare the two.
//
// A key served from a domain and identified only by that domain proves
// nothing: whoever takes the domain serves their own key beside their own
// fingerprint, and a reporter encrypts an unpublished vulnerability straight
// to them. SECURITY.md lives on GitHub, behind a different account and
// different credentials, which is what makes it worth comparing against. The
// key itself and security.txt are denyfirst.dev's, served by denyfirst/site,
// whose tests hold them to the same fingerprint.
//
// Two sources that agree because nobody checks are one source written twice.
// This is the check.
func TestFingerprintAgreesAcrossSources(t *testing.T) {
	// Written without spaces in the constant and with them in the prose, so
	// both forms are compared against the same value.
	compact := strings.NewReplacer(" ", "", "\t", "").Replace

	if len(PGPFingerprint) != 40 {
		t.Fatalf("PGPFingerprint is %d characters, want 40 hex digits", len(PGPFingerprint))
	}
	for _, r := range PGPFingerprint {
		if !strings.ContainsRune("0123456789ABCDEF", r) {
			t.Fatalf("PGPFingerprint contains %q; want uppercase hex", r)
		}
	}

	// The card is written once, in the page's source, and rendered on the
	// demonstration only; the source is read so both builds hold it.
	card, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compact(strings.ReplaceAll(string(card), "&nbsp;", "")), PGPFingerprint) {
		t.Errorf("Porch's page does not carry the fingerprint %s", PGPFingerprint)
	}
	if demo.Enabled && !strings.Contains(compact(strings.ReplaceAll(get(t, "/").Body.String(), "&nbsp;", "")), PGPFingerprint) {
		t.Errorf("Porch's page as served does not carry the fingerprint %s", PGPFingerprint)
	}

	// The second source, read from disk because it is not served from here.
	// A test that only compared the page against itself would pass while the
	// two published fingerprints drifted apart.
	policy, err := os.ReadFile("../../SECURITY.md")
	if err != nil {
		t.Fatalf("reading SECURITY.md: %v", err)
	}
	if !strings.Contains(compact(string(policy)), PGPFingerprint) {
		t.Errorf("SECURITY.md does not carry the fingerprint %s; a reporter has nothing to compare against", PGPFingerprint)
	}
}
