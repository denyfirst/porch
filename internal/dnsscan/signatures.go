package dnsscan

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/policy"
)

// Checking the signatures at the top of a zone with the zone's own keys.
//
// A digest at the parent that matches a key here is half of the link. The
// other half is that the key it names signs the zone's key set, and that a
// key in that set signs the zone's records; a rollover that published the
// new key and never signed with it passes the first test and fails the
// second, and every validating resolver then refuses the zone. Until now the
// second half was the resolver's word (the AD bit). This checks it: two
// record sets, the keys and the record at the top of the zone, each against
// the signatures that came with it, by RFC 4034 §3.1.8.1 and RFC 4035 §5.3.
//
// Nothing is asked for this. The keys and signatures arrive with answers this
// check already reads, because every query sets the DNSSEC OK bit.
//
// What it will not do is call a zone broken because of a limit of its own.
// A signature is found wanting only when the key was read, the algorithm is
// one this verifies, and the arithmetic says no. An algorithm it does not
// implement, a key it cannot read, a signer's name it cannot place: each is
// said as a check not made (R4), never as a signature that failed.

const (
	// zoneKeyFlag is DNSKEY flag bit 7: only a key with it set may verify a
	// signature (RFC 4034 §2.1.1), and protocol is always 3 (§2.1.2).
	zoneKeyFlag   = 0x0100
	protocolDNSEC = 3

	classIN = 1

	// RSA keys outside these sizes are not verified here. RFC 3110 allows up
	// to 4096 bits, and Go refuses fewer than 1024; a key outside that range
	// is a check not made rather than a signature that failed.
	minRSABits = 1024
	maxRSABits = 4096

	// maxAttempts is how many signature checks one record set may cost.
	//
	// Key tags are a checksum anybody can collide, so a zone, or a resolver
	// answering for one, can pair hundreds of signatures with hundreds of
	// keys that all claim each one: KeyTrap (CVE-2023-50387), which made
	// every major validator spend minutes on one answer until they bounded
	// the work. A real zone needs one check, two in a rollover; past this
	// many, the set is said to carry more than this check tries, and nothing
	// is graded.
	maxAttempts = 8
)

// setCheck is what checking one record set's signatures found. Exactly one
// of the three holds.
type setCheck struct {
	verified bool
	fault    string
	reason   string
}

// signedSet is one record set and what checking it needs.
type signedSet struct {
	// what names the set in a sentence: "the key set".
	what string

	rrType uint16
	rdatas [][]byte

	signatures []dnsclient.RRSIG

	// keys are the keys allowed to have signed it.
	keys []dnsclient.DNSKEY

	// keysAre names those keys in a sentence: "the key the parent's digest
	// names".
	keysAre string

	// ownExpiry says the end of a signature's validity period is graded by a
	// rule of its own (dns.signature-expired), and is not counted again here.
	ownExpiry bool
}

// checkSignatures checks the key set against the keys the parent anchors, and
// then the record at the top of the zone against the key set.
func (s *Scanner) checkSignatures(owner []byte, domain string, keys, soa dnsclient.ZoneAnswer, anchored []dnsclient.DNSKEY, facts *policy.DNSFacts) {
	labels := strings.Count(domain, ".") + 1
	now := s.now()

	if len(keys.Alias) > 0 {
		facts.SignatureCheckReason = "the name is an alias, so the keys that came back are another name's"
		return
	}

	keySet := make([][]byte, 0, len(keys.Keys))
	var zoneKeys []dnsclient.DNSKEY
	for _, k := range keys.Keys {
		keySet = append(keySet, keyRDATA(k))
		if usable(k) {
			zoneKeys = append(zoneKeys, k)
		}
	}
	var anchors []dnsclient.DNSKEY
	for _, k := range anchored {
		if usable(k) {
			anchors = append(anchors, k)
		}
	}

	first := checkSet(signedSet{
		what:       "the key set",
		rrType:     dnsclient.TypeDNSKEY,
		rdatas:     keySet,
		signatures: keys.Signatures,
		keys:       anchors,
		keysAre:    "the key the parent's digest names",
	}, owner, labels, now)
	if !first.verified {
		settle(facts, first, keys.Validated)
		return
	}

	// The record at the top of the zone, which every signed zone has and
	// which the zone signing key signs on the same schedule as everything
	// else. Only once the key set holds: a key from a set that does not is
	// not one anybody would verify with.
	var records [][]byte
	for _, r := range soa.SOA {
		records = append(records, r.RDATA)
	}
	if len(records) == 0 {
		facts.SignatureCheckReason = "the record at the top of the zone was not read, so its signature was not checked"
		return
	}
	second := checkSet(signedSet{
		what:       "the record at the top of the zone",
		rrType:     dnsclient.TypeSOA,
		rdatas:     records,
		signatures: soa.Signatures,
		keys:       zoneKeys,
		keysAre:    "a key the zone publishes",
		ownExpiry:  true,
	}, owner, labels, now)
	settle(facts, second, soa.Validated)
}

// settle writes one set's result into the facts.
//
// A fault where the resolver set the AD bit on the same answer is reported
// as the disagreement it is rather than graded: one of the two is wrong, the
// resolver is the one every visitor's lookups go through, and a check that
// overruled it would be grading its own reading against the evidence.
func settle(facts *policy.DNSFacts, c setCheck, resolverValidated bool) {
	switch {
	case c.verified:
		facts.SignaturesVerified = true
	case c.fault != "" && resolverValidated:
		facts.SignatureCheckReason = "the resolver says it validated the zone, and this check's own reading disagrees: " + c.fault
	case c.fault != "":
		facts.SignatureFault = c.fault
	default:
		facts.SignatureCheckReason = c.reason
	}
}

// checkSet checks one record set's signatures. One that verifies with an
// allowed key and is inside its validity period is enough (RFC 4035 §5.3.3);
// otherwise the most specific thing that went wrong is reported.
func checkSet(set signedSet, owner []byte, labels int, now time.Time) setCheck {
	if len(set.signatures) == 0 {
		return setCheck{reason: "no signature came with " + set.what + ", so the resolver may not pass them on"}
	}

	var (
		expired, early       time.Time
		expiredTag, earlyTag uint16
		failed               bool
		failedTag            uint16
		reason               string
		unplaced             bool
		attempts             int
	)
	for _, sig := range set.signatures {
		if sig.SignerWire == nil {
			unplaced = true
			continue
		}
		// Made by this zone, for a name of this many labels. A signature
		// that says otherwise is not one a validator uses for this set.
		if !bytes.Equal(sig.SignerWire, owner) || int(sig.Labels) != labels {
			continue
		}
		for _, k := range set.keys {
			if k.Algorithm != sig.Algorithm || keyTag(k) != sig.KeyTag {
				continue
			}
			if attempts++; attempts > maxAttempts {
				return setCheck{reason: set.what + " carries more signatures by matching keys than this check tries (" +
					strconv.Itoa(maxAttempts) + "), which is how KeyTrap (CVE-2023-50387) exhausts a validator"}
			}
			data, ok := signedData(sig, owner, set.rrType, set.rdatas)
			if !ok {
				reason = "the signed data could not be put together from what came back"
				continue
			}
			good, why := verifySignature(k, sig, data)
			switch {
			case why != "":
				reason = why
			case !good:
				failed, failedTag = true, sig.KeyTag
			case now.Before(sig.Inception):
				early, earlyTag = sig.Inception, sig.KeyTag
			case now.After(sig.Expiration) && !set.ownExpiry:
				expired, expiredTag = sig.Expiration, sig.KeyTag
			default:
				return setCheck{verified: true}
			}
		}
	}

	by := func(tag uint16) string { return set.what + "'s signature by key " + strconv.Itoa(int(tag)) }
	switch {
	case !expired.IsZero():
		return setCheck{fault: by(expiredTag) + " ran out on " + expired.Format("2006-01-02")}
	case !early.IsZero():
		return setCheck{fault: by(earlyTag) + " is not valid until " + early.Format("2006-01-02")}
	case failed:
		return setCheck{fault: by(failedTag) + " does not verify"}
	case reason != "":
		return setCheck{reason: reason}
	case unplaced:
		return setCheck{reason: "a signature over " + set.what + " compressed its signer's name, which RFC 4034 forbids, so where it begins is not known"}
	default:
		return setCheck{fault: set.what + " is not signed by " + set.keysAre}
	}
}

// usable is RFC 4034 §2.1.1 and §2.1.2: a zone key, of the DNSSEC protocol.
func usable(k dnsclient.DNSKEY) bool {
	return k.Flags&zoneKeyFlag != 0 && k.Protocol == protocolDNSEC
}

// signedData is what a signature is over (RFC 4034 §3.1.8.1): the
// signature record's own fields up to the signer's name, then each record of
// the set in canonical form and canonical order (§6.2, §6.3), with the TTL the
// signature names rather than whatever a cache counted down to.
func signedData(sig dnsclient.RRSIG, owner []byte, rrType uint16, rdatas [][]byte) ([]byte, bool) {
	expiration, ok := epoch(sig.Expiration)
	if !ok {
		return nil, false
	}
	inception, ok := epoch(sig.Inception)
	if !ok {
		return nil, false
	}

	sorted := slices.Clone(rdatas)
	slices.SortFunc(sorted, bytes.Compare)
	sorted = slices.CompactFunc(sorted, bytes.Equal)

	out := make([]byte, 0, 18+len(sig.SignerWire)+len(sorted)*(len(owner)+10+64))
	out = binary.BigEndian.AppendUint16(out, sig.Covered)
	out = append(out, sig.Algorithm, sig.Labels)
	out = binary.BigEndian.AppendUint32(out, sig.OriginalTTL)
	out = binary.BigEndian.AppendUint32(out, expiration)
	out = binary.BigEndian.AppendUint32(out, inception)
	out = binary.BigEndian.AppendUint16(out, sig.KeyTag)
	out = append(out, sig.SignerWire...)

	for _, rdata := range sorted {
		if len(rdata) > math.MaxUint16 {
			return nil, false
		}
		out = append(out, owner...)
		out = binary.BigEndian.AppendUint16(out, rrType)
		out = binary.BigEndian.AppendUint16(out, classIN)
		out = binary.BigEndian.AppendUint32(out, sig.OriginalTTL)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata))) // #nosec G115 -- bounded above
		out = append(out, rdata...)
	}
	return out, true
}

// epoch is a time back in the thirty-two bits a signature record carries it
// in. Every time here was read from those bits, so the range check is a guard
// rather than a case.
func epoch(t time.Time) (uint32, bool) {
	u := t.Unix()
	if u < 0 || u > math.MaxUint32 {
		return 0, false
	}
	return uint32(u), true // #nosec G115 -- range checked above
}

// verifySignature checks one signature with one key. A non-empty reason
// means it was not checked; otherwise ok is the answer.
func verifySignature(k dnsclient.DNSKEY, sig dnsclient.RRSIG, data []byte) (ok bool, reason string) {
	name := policy.AlgorithmName(sig.Algorithm)
	switch sig.Algorithm {
	case 5, 7:
		return verifyRSA(k.Key, sig.Signature, crypto.SHA1, data, name)
	case 8:
		return verifyRSA(k.Key, sig.Signature, crypto.SHA256, data, name)
	case 10:
		return verifyRSA(k.Key, sig.Signature, crypto.SHA512, data, name)
	case 13:
		return verifyECDSA(k.Key, sig.Signature, elliptic.P256(), crypto.SHA256, data, name)
	case 14:
		return verifyECDSA(k.Key, sig.Signature, elliptic.P384(), crypto.SHA384, data, name)
	case 15:
		if len(k.Key) != ed25519.PublicKeySize {
			return false, "the " + name + " key is not " + strconv.Itoa(ed25519.PublicKeySize) + " bytes, so it was not used"
		}
		if len(sig.Signature) != ed25519.SignatureSize {
			return false, ""
		}
		return ed25519.Verify(ed25519.PublicKey(k.Key), data, sig.Signature), ""
	default:
		return false, "the key uses " + name + ", which this check does not verify"
	}
}

// verifyRSA is RFC 3110's key format with RFC 5702's hashes.
func verifyRSA(key, signature []byte, h crypto.Hash, data []byte, name string) (bool, string) {
	pub, why := rsaKey(key)
	if why != "" {
		return false, "the " + name + " key " + why
	}
	k := (pub.N.BitLen() + 7) / 8
	if len(signature) > k {
		return false, ""
	}
	// A signature shorter than the modulus is the same number without its
	// leading zeros, which the validators in use accept; Go wants it padded.
	if len(signature) < k {
		signature = append(make([]byte, k-len(signature)), signature...)
	}
	digest := h.New()
	digest.Write(data)
	err := rsa.VerifyPKCS1v15(pub, h, digest.Sum(nil), signature)
	switch {
	case err == nil:
		return true, ""
	case errors.Is(err, rsa.ErrVerification):
		return false, ""
	default:
		return false, "the " + name + " key could not be used"
	}
}

// rsaKey reads RFC 3110 §2: an exponent length, one byte or three, then the
// exponent, then the modulus. A non-empty reason says why it was not used.
func rsaKey(b []byte) (*rsa.PublicKey, string) {
	if len(b) < 1 {
		return nil, "is empty"
	}
	n := int(b[0])
	b = b[1:]
	if n == 0 {
		if len(b) < 2 {
			return nil, "is cut short"
		}
		n = int(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if n == 0 || n >= len(b) {
		return nil, "is cut short"
	}
	e := new(big.Int).SetBytes(b[:n])
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > math.MaxInt32 {
		return nil, "has an exponent this check does not use"
	}
	m := new(big.Int).SetBytes(b[n:])
	if bits := m.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, "is " + strconv.Itoa(bits) + " bits, outside what this check verifies"
	}
	return &rsa.PublicKey{N: m, E: int(e.Int64())}, ""
}

// verifyECDSA is RFC 6605: the key is the point's two coordinates and the
// signature r and s, each the curve's size.
func verifyECDSA(key, signature []byte, curve elliptic.Curve, h crypto.Hash, data []byte, name string) (bool, string) {
	size := (curve.Params().BitSize + 7) / 8
	if len(key) != 2*size {
		return false, "the " + name + " key is not " + strconv.Itoa(2*size) + " bytes, so it was not used"
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, key...))
	if err != nil {
		return false, "the " + name + " key is not a point on its curve, so it was not used"
	}
	if len(signature) != 2*size {
		return false, ""
	}
	digest := h.New()
	digest.Write(data)
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	return ecdsa.Verify(pub, digest.Sum(nil), r, s), ""
}
