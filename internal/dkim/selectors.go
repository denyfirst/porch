package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// Documented are selectors that mail providers publish for their own service.
//
// Not a list this project invented. Each entry is the name a provider tells its
// own customers to create, in that provider's own setup instructions, and each
// carries the provider it belongs to so that a reader can go and check rather
// than take this file's word for it. That distinction is the whole reason the
// list is allowed to exist: a set of likely-looking names somebody here made up
// would be a threshold nobody can argue with (R21), and a set of names each
// provider publishes is a citation.
//
// It is a convenience and never a claim. A domain where none of these answer
// has not been shown to lack DKIM — it has been shown that these particular
// names hold nothing — and every report says which were tried and why (R4).
//
// The authoritative source is still the operator. They set the records up.
var Documented = []struct {
	Selector string
	Provider string
}{
	{"google", "Google Workspace"},
	{"selector1", "Microsoft 365"},
	{"selector2", "Microsoft 365"},
	{"k1", "Mailchimp and Mandrill"},
	{"k2", "Mailchimp and Mandrill"},
	{"s1", "SendGrid and several others"},
	{"s2", "SendGrid and several others"},
	{"mail", "a common default in self-hosted setups"},
	{"dkim", "a common default in self-hosted setups"},
	{"default", "a common default in self-hosted setups"},

	// Migadu asks for three CNAMEs, key1 to key3, so that it can rotate keys
	// without its customers touching DNS. Added after a check of this
	// project's own domain, which Migadu serves, found no key under any name
	// above while the zone held all three.
	{"key1", "Migadu"},
	{"key2", "Migadu"},
	{"key3", "Migadu"},
}

// DocumentedSelectors is the list above, ready to look under.
func DocumentedSelectors() []Selector {
	out := make([]Selector, 0, len(Documented))
	for _, d := range Documented {
		out = append(out, Selector{Name: d.Selector, Source: FromProvider})
	}
	return out
}

// ProviderOf names who documents a selector, for a report that lists one.
func ProviderOf(selector string) string {
	for _, d := range Documented {
		if d.Selector == selector {
			return d.Provider
		}
	}
	return ""
}

// maxSelectorLength bounds one selector. The key lives at
// <selector>._domainkey.<domain> and a whole name is at most 253 bytes, so a
// selector longer than this leaves no room for a domain worth asking about.
const maxSelectorLength = 128

// CheckSelector refuses a selector that is not a DNS name.
//
// RFC 6376 §3.1: a selector is one or more labels separated by dots. Letters,
// digits and hyphens are what it allows; an underscore is accepted as well,
// because DNS carries one and some operators use it, and refusing a record
// somebody really published would answer about this parser rather than about
// their domain.
//
// It exists because a selector that arrives in a request is appended to a
// domain and asked of a resolver. A comma in one was a second selector the
// bound had not counted, and a space or a control character is a name no
// zone holds. The message states the rule and never the selector (I3).
func CheckSelector(name string) error {
	name = fold(name)
	if name == "" || len(name) > maxSelectorLength {
		return errBadSelector
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errBadSelector
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return errBadSelector
			}
		}
	}
	return nil
}

var errBadSelector = errors.New("a selector is one or more DNS labels separated by dots: " +
	"letters, digits, hyphens and underscores, each label at most 63 characters")

// Named turns what an operator typed into selectors to look under.
//
// Comma separated, because that is what somebody types. Empty entries are
// dropped rather than refused: a trailing comma is a typing accident and not
// worth an error message.
func Named(list string) []Selector {
	var out []Selector
	for _, name := range strings.Split(list, ",") {
		name = fold(name)
		if name == "" {
			continue
		}
		out = append(out, Selector{Name: name, Source: FromOperator})
	}
	return out
}

// rsaBits reads the size of an RSA key out of a p= value.
//
// Zero for anything it cannot read, which is not a failure worth reporting on
// its own: the record was found either way, and a size nobody could parse is
// said as "published" rather than as a number that might be wrong.
//
// Only RSA has a size worth reporting. Ed25519 keys are all one length, so a
// number beside one would invite a comparison against the RSA floor that means
// nothing.
func rsaBits(p, algorithm string) int {
	if algorithm != "" && !strings.EqualFold(algorithm, "rsa") {
		return 0
	}

	// Whitespace is permitted inside a long TXT value and is common, because a
	// key is longer than one string and gets wrapped by hand.
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, p)

	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return 0
	}

	// A key from somebody else's zone, so it is parsed and never used. The
	// standard library's parser is the same one that reads a certificate's
	// key, and it is given bounded input: a TXT value cannot exceed what the
	// resolver already bounded.
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return 0
	}
	return rsaKey.N.BitLen()
}
