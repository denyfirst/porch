package policy

import (
	"testing"
	"time"
)

// The zone's own settings are said in one line each, and a zone that did not
// give them says nothing rather than a line of zeros.
func TestTheZonesOwnSettingsAreSaidInALineEach(t *testing.T) {
	f := DNSFacts{SOAFound: true, SOARefresh: 86400, SOARetry: 3600, SOAExpire: 2419200, SOAMinimum: 3600}
	if got, want := DNSTimersLine(f), "refresh 1d, retry 1h, expire 28d, negative answers kept 1h"; got != want {
		t.Errorf("timers = %q, want %q", got, want)
	}
	if got := DNSTimersLine(DNSFacts{SOAFound: true}); got != "" {
		t.Errorf("a zone whose timers were not read says %q", got)
	}
	if got := DNSTimersLine(DNSFacts{SOARefresh: 86400}); got != "" {
		t.Errorf("a name with no zone of its own says %q", got)
	}

	keys := []KeyDigest{
		{KeyTag: 53731, Algorithm: 13, Name: "ECDSAP256SHA256", KeySigning: true},
		{KeyTag: 1234, Algorithm: 99},
	}
	if got, want := DNSKeysLine(keys), "key 53731, key signing, ECDSAP256SHA256; key 1234, zone signing, algorithm 99"; got != want {
		t.Errorf("keys = %q, want %q", got, want)
	}

	signers := []DelegationSigner{
		{KeyTag: 53731, DigestType: 2, Matched: true},
		{KeyTag: 53731, DigestType: 1},
		{KeyTag: 7, DigestType: 9, Unsupported: true},
	}
	want := "key 53731, SHA-256, matches a key here; key 53731, SHA-1, matches no key here; " +
		"key 7, digest type 9, not a hash this check computes"
	if got := DNSDigestLine(signers); got != want {
		t.Errorf("digests = %q, want %q", got, want)
	}
}

// Each certificate above the leaf is said with its key, when it runs out and
// what it is in the chain, and the name match in so many words.
func TestTheChainIsSaidOneCertificateALine(t *testing.T) {
	until := time.Date(2028, 9, 2, 23, 59, 59, 0, time.UTC)
	for _, c := range []struct {
		isCA, self bool
		want       string
	}{
		{true, false, "CN=YE1,O=Let's Encrypt,C=US: ECDSA 384, runs out 2028-09-02, an authority"},
		{true, true, "CN=YE1,O=Let's Encrypt,C=US: ECDSA 384, runs out 2028-09-02, a root, signed by itself"},
		{false, false, "CN=YE1,O=Let's Encrypt,C=US: ECDSA 384, runs out 2028-09-02, not an authority, so it should not be in the chain"},
	} {
		if got := ChainLine("CN=YE1,O=Let's Encrypt,C=US", "ECDSA", 384, until, c.isCA, c.self); got != c.want {
			t.Errorf("chain line = %q, want %q", got, c.want)
		}
	}
	if got := ChainLine("", "Ed25519", 0, until, true, false); got != "a certificate with no subject: Ed25519, runs out 2028-09-02, an authority" {
		t.Errorf("a certificate with no subject and no key size reads %q", got)
	}
	if NameLine(true) != "covers the name asked for" || NameLine(false) != "does not cover the name asked for" {
		t.Errorf("name lines read %q and %q", NameLine(true), NameLine(false))
	}
}
