package policy

import (
	"strconv"
	"strings"
)

// The zone's own settings, each said in one line of the report.
//
// They were measured all along and reached a reader only in a folded note,
// or not at all: the SOA timers in a sentence under "Observed", the keys by
// algorithm alone, and the digests the parent holds not at all. A report that
// keeps what it measured where nobody opens it has, for most readers, not
// measured it. None of these is graded here; RFC 1912's timer ranges are
// recommendations, and the one digest a document rules out (SHA-1, RFC 8624)
// has a rule of its own.

// DNSTimersLine says the zone's SOA timers, or nothing where no zone begins
// at the name or none was read.
func DNSTimersLine(f DNSFacts) string {
	if !f.SOAFound || f.SOARefresh|f.SOARetry|f.SOAExpire|f.SOAMinimum == 0 {
		return ""
	}
	return "refresh " + duration(f.SOARefresh) + ", retry " + duration(f.SOARetry) +
		", expire " + duration(f.SOAExpire) + ", negative answers kept " + duration(f.SOAMinimum)
}

// DNSKeysLine says each key the zone publishes: its tag, what it signs, and
// its algorithm by the name an operator's own interface uses.
func DNSKeysLine(keys []KeyDigest) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		role := "zone signing"
		if k.KeySigning {
			role = "key signing"
		}
		name := k.Name
		if name == "" {
			name = "algorithm " + strconv.Itoa(int(k.Algorithm))
		}
		parts = append(parts, "key "+strconv.Itoa(int(k.KeyTag))+", "+role+", "+name)
	}
	return strings.Join(parts, "; ")
}

// DNSDigestLine says each digest the parent holds for this zone: which key it
// is of, the hash, and whether a key here matched it.
func DNSDigestLine(signers []DelegationSigner) string {
	parts := make([]string, 0, len(signers))
	for _, ds := range signers {
		line := "key " + strconv.Itoa(int(ds.KeyTag)) + ", " + digestName(ds.DigestType)
		switch {
		case ds.Unsupported:
			line += ", not a hash this check computes"
		case ds.Matched:
			line += ", matches a key here"
		default:
			line += ", matches no key here"
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, "; ")
}

// digestName is the IANA name of a delegation signer digest type.
func digestName(t uint8) string {
	switch t {
	case 1:
		return "SHA-1"
	case 2:
		return "SHA-256"
	case 3:
		return "GOST R 34.11-94"
	case 4:
		return "SHA-384"
	default:
		return "digest type " + strconv.Itoa(int(t))
	}
}
