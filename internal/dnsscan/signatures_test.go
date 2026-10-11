package dnsscan

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/policy"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}
	return b
}

func wire(t *testing.T, name string) []byte {
	t.Helper()
	b, err := wireName(name)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}
	return b
}

// The examples the RFCs publish verify, and their digests are the ones the
// RFCs print. The test zone signs with this package's own signedData, so
// these are what hold it to the standard rather than to itself: a canonical
// form that was wrong in the same way on both sides would pass every other
// test here.
func TestTheRFCExamplesVerify(t *testing.T) {
	stamp := func(s string) time.Time {
		at, err := time.Parse("20060102150405", s)
		if err != nil {
			t.Fatalf("test data is wrong: %v", err)
		}
		return at
	}
	type example struct {
		rfc    string
		zone   string
		key    dnsclient.DNSKEY
		digest uint8
		want   string
		owner  string
		rrType uint16
		rdata  []byte
		sig    dnsclient.RRSIG
		keyTag uint16
	}
	examples := []example{
		{
			rfc: "RFC 8080 §6.1", zone: "example.com", digest: 2,
			key:   dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 15, Key: b64(t, "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")},
			want:  "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b",
			owner: "example.com", rrType: 15, rdata: append([]byte{0, 10}, wire(t, "mail.example.com")...),
			sig: dnsclient.RRSIG{Covered: 15, Algorithm: 15, Labels: 2, OriginalTTL: 3600,
				Expiration: time.Unix(1440021600, 0), Inception: time.Unix(1438207200, 0), KeyTag: 3613,
				Signature: b64(t, "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==")},
			keyTag: 3613,
		},
		{
			rfc: "RFC 6605 §6.1", zone: "example.net", digest: 2,
			key:   dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, Key: b64(t, "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==")},
			want:  "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17",
			owner: "www.example.net", rrType: 1, rdata: []byte{192, 0, 2, 1},
			sig: dnsclient.RRSIG{Covered: 1, Algorithm: 13, Labels: 3, OriginalTTL: 3600,
				Expiration: stamp("20100909100439"), Inception: stamp("20100812100439"), KeyTag: 55648,
				Signature: b64(t, "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==")},
			keyTag: 55648,
		},
		{
			rfc: "RFC 6605 §6.2", zone: "example.net", digest: 4,
			key:   dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 14, Key: b64(t, "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40")},
			want:  "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6",
			owner: "www.example.net", rrType: 1, rdata: []byte{192, 0, 2, 1},
			sig: dnsclient.RRSIG{Covered: 1, Algorithm: 14, Labels: 3, OriginalTTL: 3600,
				Expiration: stamp("20100909102025"), Inception: stamp("20100812102025"), KeyTag: 10771,
				Signature: b64(t, "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm")},
			keyTag: 10771,
		},
	}

	for _, e := range examples {
		if got := keyTag(e.key); got != e.keyTag {
			t.Errorf("%s: key tag %d, want %d", e.rfc, got, e.keyTag)
		}
		digest := digester(e.digest)
		digest.Write(wire(t, e.zone))
		digest.Write(keyRDATA(e.key))
		if got := hex.EncodeToString(digest.Sum(nil)); got != e.want {
			t.Errorf("%s: digest %s, want %s", e.rfc, got, e.want)
		}

		sig := e.sig
		sig.SignerWire = wire(t, e.zone)
		owner := wire(t, e.owner)
		data, ok := signedData(sig, owner, e.rrType, [][]byte{e.rdata})
		if !ok {
			t.Fatalf("%s: the signed data could not be put together", e.rfc)
		}
		if good, why := verifySignature(e.key, sig, data); !good || why != "" {
			t.Errorf("%s: verified %v, %q", e.rfc, good, why)
		}

		// One bit of the signature, and one of the record, each turn it into
		// a signature that does not verify — not one that was not checked.
		flipped := sig
		flipped.Signature = slices.Clone(sig.Signature)
		flipped.Signature[len(flipped.Signature)-1] ^= 1
		if good, why := verifySignature(e.key, flipped, data); good || why != "" {
			t.Errorf("%s: a changed signature reads %v, %q", e.rfc, good, why)
		}
		changed := slices.Clone(data)
		changed[len(changed)-1] ^= 1
		if good, why := verifySignature(e.key, sig, changed); good || why != "" {
			t.Errorf("%s: a changed record reads %v, %q", e.rfc, good, why)
		}
	}
}

// RSA, in RFC 3110's key format with either length form, with SHA-256 and
// SHA-512, and with a signature missing its leading zero byte.
func TestAnRSASignatureVerifies(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	exponent := big.NewInt(int64(private.E)).Bytes()
	short := append(append([]byte{byte(len(exponent))}, exponent...), private.N.Bytes()...)
	long := append(append([]byte{0, 0, byte(len(exponent))}, exponent...), private.N.Bytes()...)
	data := []byte("the signed data")

	for _, c := range []struct {
		algorithm uint8
		hash      crypto.Hash
	}{{8, crypto.SHA256}, {10, crypto.SHA512}} {
		digest := c.hash.New()
		digest.Write(data)
		signature, err := rsa.SignPKCS1v15(rand.Reader, private, c.hash, digest.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range [][]byte{short, long} {
			k := dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: c.algorithm, Key: key}
			sig := dnsclient.RRSIG{Algorithm: c.algorithm, Signature: signature}
			if good, why := verifySignature(k, sig, data); !good || why != "" {
				t.Errorf("algorithm %d: %v, %q", c.algorithm, good, why)
			}
			if good, why := verifySignature(k, sig, append(slices.Clone(data), '!')); good || why != "" {
				t.Errorf("algorithm %d, changed data: %v, %q", c.algorithm, good, why)
			}
		}
	}

	// A signature whose first byte is zero, sent without it, verifies as the
	// validators in use verify it.
	for i := 0; ; i++ {
		data := []byte("the signed data " + string(rune('a'+i%26)) + strings.Repeat("x", i))
		digest := sha256.Sum256(data)
		signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if signature[0] != 0 {
			if i > 4000 {
				t.Fatal("no signature with a leading zero turned up")
			}
			continue
		}
		k := dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 8, Key: short}
		sig := dnsclient.RRSIG{Algorithm: 8, Signature: bytes.TrimLeft(signature, "\x00")}
		if good, why := verifySignature(k, sig, data); !good || why != "" {
			t.Errorf("a signature without its leading zero: %v, %q", good, why)
		}
		break
	}
}

// What this cannot check is said as a check not made, never as a signature
// that failed (R4): an algorithm it does not implement, a key it cannot read,
// an RSA key outside the sizes it verifies.
func TestWhatThisCannotCheckIsNotAFailure(t *testing.T) {
	sig := func(alg uint8, n int) dnsclient.RRSIG {
		return dnsclient.RRSIG{Algorithm: alg, Signature: bytes.Repeat([]byte{1}, n)}
	}
	// RFC 5702 §6.1's example key, 512 bits.
	small := b64(t, "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=")

	for label, c := range map[string]struct {
		key dnsclient.DNSKEY
		sig dnsclient.RRSIG
	}{
		"Ed448":                  {dnsclient.DNSKEY{Algorithm: 16, Key: make([]byte, 57)}, sig(16, 114)},
		"DSA":                    {dnsclient.DNSKEY{Algorithm: 3, Key: make([]byte, 64)}, sig(3, 41)},
		"a point off the curve":  {dnsclient.DNSKEY{Algorithm: 13, Key: bytes.Repeat([]byte{1}, 64)}, sig(13, 64)},
		"a short P-256 key":      {dnsclient.DNSKEY{Algorithm: 13, Key: make([]byte, 63)}, sig(13, 64)},
		"a short Ed25519 key":    {dnsclient.DNSKEY{Algorithm: 15, Key: make([]byte, 31)}, sig(15, 64)},
		"a 512-bit RSA key":      {dnsclient.DNSKEY{Algorithm: 8, Key: small}, sig(8, 64)},
		"an RSA key cut short":   {dnsclient.DNSKEY{Algorithm: 8, Key: []byte{3, 1, 0, 1}}, sig(8, 64)},
		"an RSA key with no len": {dnsclient.DNSKEY{Algorithm: 8, Key: []byte{0, 0}}, sig(8, 64)},
		"an empty RSA key":       {dnsclient.DNSKEY{Algorithm: 8}, sig(8, 64)},
	} {
		if good, why := verifySignature(c.key, c.sig, []byte("data")); good || why == "" {
			t.Errorf("%s: verified %v, with no reason", label, good)
		}
	}
}

// at scans the zone with the clock set.
func at(t *testing.T, z *zone, now time.Time) *Result {
	t.Helper()
	got, err := (&Scanner{Resolver: z, Now: func() time.Time { return now }}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}

var otherSeed = bytes.Repeat([]byte{3}, 32)

// The signatures are checked with the zone's own keys: the key the parent's
// digest names has to sign the key set, and a key in that set the record at
// the top. Each way of breaking that is graded, and says which.
func TestTheSignaturesAreCheckedWithTheZonesOwnKeys(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ksk, zsk := testKey(kskSeed, 257), testKey(zskSeed, 256)

	for _, c := range []struct {
		label  string
		break_ func(z *zone)
		says   string
	}{
		{"the key set signed only by the zone key", func(z *zone) {
			z.keySignatures = []dnsclient.RRSIG{sign(t, zskSeed, zsk, dnsclient.TypeDNSKEY, keySet(z.keys), signedFrom, signedUntil)}
		}, "the key set is not signed by the key the parent's digest names"},
		{"the key set's signature changed", func(z *zone) {
			z.keySignatures[0].Signature = slices.Clone(z.keySignatures[0].Signature)
			z.keySignatures[0].Signature[0] ^= 1
		}, "the key set's signature by key " + itoa(keyTag(ksk)) + " does not verify"},
		{"a key added after the set was signed", func(z *zone) {
			z.keys = append(z.keys, testKey(otherSeed, 256))
		}, "does not verify"},
		{"the key set's signature ran out", func(z *zone) {
			z.keySignatures = []dnsclient.RRSIG{sign(t, kskSeed, ksk, dnsclient.TypeDNSKEY, keySet(z.keys), signedFrom, now.AddDate(0, 0, -3))}
		}, "ran out on 2026-10-07"},
		{"the key set's signature not yet valid", func(z *zone) {
			z.keySignatures = []dnsclient.RRSIG{sign(t, kskSeed, ksk, dnsclient.TypeDNSKEY, keySet(z.keys), now.AddDate(0, 0, 2), signedUntil)}
		}, "is not valid until 2026-10-12"},
		{"a signature for a name of another length", func(z *zone) {
			z.keySignatures[0].Labels = 3
		}, "the key set is not signed by"},
		{"the anchored key is not a zone key", func(z *zone) {
			// Flag 1 alone: a secure entry point without bit 7, which RFC
			// 4034 §2.1.1 says must not be used to verify anything.
			notZone := testKey(kskSeed, 1)
			z.keys = []dnsclient.DNSKEY{notZone, zsk}
			z.ds = []dnsclient.DS{signerFor(t, "example.com", notZone)}
			z.keySignatures = []dnsclient.RRSIG{sign(t, kskSeed, notZone, dnsclient.TypeDNSKEY, keySet(z.keys), signedFrom, signedUntil)}
		}, "the key set is not signed by the key the parent's digest names"},
		{"the top signed by a key the zone does not publish", func(z *zone) {
			z.signatures = []dnsclient.RRSIG{sign(t, otherSeed, testKey(otherSeed, 256), dnsclient.TypeSOA, [][]byte{z.soa.RDATA}, signedFrom, signedUntil)}
		}, "the record at the top of the zone is not signed by a key the zone publishes"},
		{"the top changed after it was signed", func(z *zone) {
			changed := *z.soa
			changed.Serial++
			changed.RDATA = soaRDATA(t, changed)
			z.soa = &changed
		}, "the record at the top of the zone's signature by key " + itoa(keyTag(zsk)) + " does not verify"},
	} {
		z := served(t)
		c.break_(z)
		got := at(t, z, now)
		if !has(got, "dns.dnssec-signature-invalid") || got.Verdict != policy.Insecure {
			t.Errorf("%s: %q %v", c.label, got.Verdict, ruleIDs(got))
		}
		if !strings.Contains(got.Observed.SignatureFault, c.says) || got.Observed.SignaturesVerified {
			t.Errorf("%s: the fault reads %q", c.label, got.Observed.SignatureFault)
		}
	}

	// The top's signature running out is dns.signature-expired's, and is not
	// counted twice.
	z := served(t)
	z.signatures = []dnsclient.RRSIG{sign(t, zskSeed, zsk, dnsclient.TypeSOA, [][]byte{z.soa.RDATA}, signedFrom, now.AddDate(0, 0, -1))}
	got := at(t, z, now)
	if !has(got, "dns.signature-expired") || has(got, "dns.dnssec-signature-invalid") || !got.Observed.SignaturesVerified {
		t.Errorf("an expired signature at the top reads %v, verified %v", ruleIDs(got), got.Observed.SignaturesVerified)
	}

	// The set is signed in canonical order, whatever order the resolver hands
	// it over in, and a record it repeats is the same record.
	z = served(t)
	z.keys = append([]dnsclient.DNSKEY{z.keys[1], z.keys[0]}, z.keys[1])
	if got := at(t, z, now); !got.Observed.SignaturesVerified || len(got.Findings) != 0 {
		t.Errorf("the key set in another order reads %v, %q", ruleIDs(got), got.Observed.SignatureFault)
	}

	// A rollover in progress: one good signature among several is enough.
	z = served(t)
	z.keySignatures = append([]dnsclient.RRSIG{sign(t, zskSeed, zsk, dnsclient.TypeDNSKEY, keySet(z.keys), signedFrom, signedUntil)}, z.keySignatures...)
	if got := at(t, z, now); !got.Observed.SignaturesVerified || len(got.Findings) != 0 {
		t.Errorf("a key set with one good signature among two reads %v", ruleIDs(got))
	}
}

func itoa(n uint16) string { return big.NewInt(int64(n)).String() }

// Where the signatures could not be checked, that is what is said, and
// nothing is graded.
func TestSignaturesNotCheckedAreNotGraded(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	for label, c := range map[string]struct {
		break_ func(z *zone)
		says   string
	}{
		"none came with the key set": {func(z *zone) { z.keySignatures = nil }, "no signature came with the key set"},
		"none came with the top":     {func(z *zone) { z.signatures = nil }, "no signature came with the record at the top of the zone"},
		"a compressed signer": {func(z *zone) {
			z.keySignatures[0].SignerWire, z.keySignatures[0].Signature = nil, nil
		}, "compressed its signer's name"},
		"an algorithm not verified here": {func(z *zone) {
			ksk := dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 16, Key: make([]byte, 57)}
			z.keys = []dnsclient.DNSKEY{ksk}
			z.ds = []dnsclient.DS{signerFor(t, "example.com", ksk)}
			z.keySignatures = []dnsclient.RRSIG{{Covered: dnsclient.TypeDNSKEY, Algorithm: 16, Labels: 2, KeyTag: keyTag(ksk),
				SignerWire: wire(t, "example.com"), Signature: make([]byte, 114), Inception: signedFrom, Expiration: signedUntil}}
		}, "Ed448, which this check does not verify"},
	} {
		z := served(t)
		c.break_(z)
		got := at(t, z, now)
		if has(got, "dns.dnssec-signature-invalid") || got.Observed.SignatureFault != "" {
			t.Errorf("%s: graded %v", label, ruleIDs(got))
		}
		if !strings.Contains(got.Observed.SignatureCheckReason, c.says) || !noteSaying(got, "The signatures were not checked") {
			t.Errorf("%s: the reason reads %q", label, got.Observed.SignatureCheckReason)
		}
	}

	// KeyTrap: signatures and keys that all claim one another cost a bounded
	// number of checks, and past it nothing is graded.
	z := served(t)
	good := z.keySignatures[0]
	for i := 0; i < 40; i++ {
		bad := good
		bad.Signature = slices.Clone(good.Signature)
		bad.Signature[0] ^= byte(i + 1)
		z.keySignatures = append([]dnsclient.RRSIG{bad}, z.keySignatures...)
	}
	got := at(t, z, now)
	if has(got, "dns.dnssec-signature-invalid") || !strings.Contains(got.Observed.SignatureCheckReason, "CVE-2023-50387") {
		t.Errorf("a flood of signatures reads %v, %q", ruleIDs(got), got.Observed.SignatureCheckReason)
	}

	// A resolver that says it validated, beside a reading here that
	// disagrees, is the disagreement said, not a grade over the resolver.
	z = served(t)
	z.validated = true
	z.keySignatures[0].Signature = slices.Clone(z.keySignatures[0].Signature)
	z.keySignatures[0].Signature[0] ^= 1
	got = at(t, z, now)
	if has(got, "dns.dnssec-signature-invalid") || !strings.Contains(got.Observed.SignatureCheckReason, "disagrees") {
		t.Errorf("a disagreement with the resolver reads %v, %q", ruleIDs(got), got.Observed.SignatureCheckReason)
	}

	// Nothing is checked where the chain itself does not match.
	z = served(t)
	z.ds = []dnsclient.DS{{KeyTag: 1, Algorithm: 15, DigestType: 2, Digest: make([]byte, 32)}}
	got = at(t, z, now)
	if got.Observed.SignaturesVerified || got.Observed.SignatureFault != "" || got.Observed.SignatureCheckReason != "" {
		t.Errorf("a chain that does not match had its signatures read: %+v", got.Observed)
	}
}

// A zone the resolver fails is asked for once more with checking disabled,
// and read as the zone it is rather than as a name inside another.
//
// Before, a validating resolver's SERVFAIL on the top of the zone made the
// report say no zone began at the name: the one outcome this check exists to
// explain came out as a note that explained nothing.
func TestAZoneTheResolverRejectsIsReadUnchecked(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	z := served(t)
	z.keySignatures[0].Signature = slices.Clone(z.keySignatures[0].Signature)
	z.keySignatures[0].Signature[0] ^= 1
	z.fail["soa"] = dnsclient.ErrServerFail
	z.fail["dnskey"] = dnsclient.ErrServerFail
	got := at(t, z, now)
	if !got.Observed.Apex || !got.Observed.ResolverRejected {
		t.Fatalf("a rejected zone reads apex %v, rejected %v", got.Observed.Apex, got.Observed.ResolverRejected)
	}
	if !has(got, "dns.dnssec-signature-invalid") || got.Verdict != policy.Insecure {
		t.Errorf("a rejected zone with a bad signature reads %q %v", got.Verdict, ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.dnssec-signature-invalid" && !strings.Contains(f.Rationale, "answered only when told not to check") {
			t.Errorf("the finding does not say the resolver refused it: %s", f.Rationale)
		}
	}
	if !slices.Contains(z.unchecked, dnsclient.TypeSOA) || !slices.Contains(z.unchecked, dnsclient.TypeDNSKEY) || slices.Contains(z.unchecked, dnsclient.TypeDS) {
		t.Errorf("asked unchecked %v, and only what failed is asked again", z.unchecked)
	}

	// Rejected, and found sound here: the disagreement is said, not graded.
	z = served(t)
	z.fail["dnskey"] = dnsclient.ErrServerFail
	got = at(t, z, now)
	if len(got.Findings) != 0 || !got.Observed.SignaturesVerified || !noteSaying(got, "found them sound") {
		t.Errorf("a rejected zone that verifies reads %v %v", ruleIDs(got), noteTexts(got))
	}

	// A refusal is not a validation failure, and is not asked again.
	z = served(t)
	z.fail["soa"] = dnsclient.ErrRefused
	at(t, z, now)
	if len(z.unchecked) != 0 {
		t.Errorf("a refused question was asked again unchecked: %v", z.unchecked)
	}

	// An unchecked answer that carries nothing changes nothing: a name
	// inside a zone stays one.
	z = served(t)
	z.soa = nil
	z.fail["soa"] = dnsclient.ErrServerFail
	got = at(t, z, now)
	if got.Observed.Apex || got.Observed.ResolverRejected {
		t.Errorf("an empty unchecked answer made a zone: apex %v, rejected %v", got.Observed.Apex, got.Observed.ResolverRejected)
	}
}

// A key and a signature are bytes a zone chose. Whatever they are, checking
// them returns, and never says a signature holds that was not made by the key.
func FuzzVerifySignature(f *testing.F) {
	for _, alg := range []uint8{5, 7, 8, 10, 13, 14, 15, 16} {
		f.Add(alg, []byte{3, 1, 0, 1, 0xC1}, []byte{1, 2, 3})
	}
	f.Add(uint8(15), make([]byte, 32), make([]byte, 64))
	f.Add(uint8(13), make([]byte, 64), make([]byte, 64))
	f.Add(uint8(8), []byte{0, 0, 1, 3}, []byte{})
	f.Fuzz(func(t *testing.T, alg uint8, key, signature []byte) {
		k := dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: alg, Key: key}
		sig := dnsclient.RRSIG{Algorithm: alg, Signature: signature}
		if good, why := verifySignature(k, sig, []byte("data")); good && why != "" {
			t.Errorf("verified and not checked at once: %q", why)
		}
	})
}
