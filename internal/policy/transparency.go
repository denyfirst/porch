package policy

import (
	"fmt"
	"time"
)

// Certificate transparency, described rather than graded.
//
// A publicly trusted certificate has to be recorded in append-only logs, and
// each log answers with a signed receipt. Browsers refuse a certificate that
// arrives without enough of them.
//
// How many, from how many logs, and which logs count are decided by each
// browser, so a grade here would be one browser's rule dressed as a standard.
// What the report does instead is count the receipts the way Chrome's
// published policy counts them, against the log list this build carries, and
// say whether Chrome would accept them; see ctpolicy.go. Since Chrome 148 a
// receipt inside a stapled status response no longer counts, so the two
// channels read here are the two that do.

// TransparencyFacts is what the certificate and the handshake each carried.
type TransparencyFacts struct {
	// Embedded is how many timestamps the leaf carries, and FromLogs how many
	// distinct logs issued them.
	Embedded int
	FromLogs int

	// InHandshake is how many arrived as a TLS extension. Almost always zero,
	// because almost every authority embeds them instead.
	InHandshake int

	// Stapled reports whether a status response accompanied the handshake.
	//
	// It is the third delivery channel, and this is the only thing said about
	// it here: a report claiming a certificate carries no receipts, while
	// holding an unread response that may contain them, would be stating as
	// fact something it declined to look at.
	Stapled bool

	// Trusted reports whether the chain reached a root in the trust store.
	//
	// A certificate outside it — self-signed, or issued by a private
	// authority — is under no obligation to be logged at all, and saying
	// nothing was found would read as a fault where there is none.
	Trusted bool

	// Checked is true when the receipts were checked against a log list
	// whose own signature verified. Without it the counts below are silence
	// rather than receipts that failed (R4).
	Checked bool

	// ListReason says why they were not checked.
	ListReason string

	// ListVersion and ListDate name the list they were checked against, so a
	// reader can see how old the judgement is.
	ListVersion string
	ListDate    string

	// What checking found, one count per receipt: its log signed this
	// certificate; the log's key does not verify it; the list names no such
	// log; or it could not be checked at all.
	Verified     int
	BadSignature int
	UnknownLog   int
	Unreadable   int

	// Receipts are the receipts one by one, as Chrome's policy reads them,
	// and Lifetime the certificate's validity period, which decides how many
	// it needs.
	Receipts []CTReceipt
	Lifetime time.Duration
}

// Chrome is the comparison with Chrome's policy, for a publicly trusted
// certificate whose receipts were checked.
func (f TransparencyFacts) Chrome() ChromeCT {
	if !f.Trusted || !f.Checked {
		return ChromeCT{}
	}
	return JudgeChromeCT(f.Receipts, f.Lifetime, f.ListDate)
}

// DescribeTransparency returns the sentences a report should carry.
//
// Notes rather than findings. Nothing here is graded; see the reasoning above.
func DescribeTransparency(f TransparencyFacts) []Note {
	total := f.Embedded + f.InHandshake

	if total > 0 {
		note := fmt.Sprintf(
			"%s, from %s. The certificate is recorded where anybody, including the domain's "+
				"owner, can find it, which is how a wrongly issued certificate gets caught.",
			plural(total, "transparency timestamp"), plural(f.FromLogs, "log"))

		if f.InHandshake > 0 && f.Embedded > 0 {
			note += fmt.Sprintf(" %d arrived embedded in the certificate and %d in the handshake.",
				f.Embedded, f.InHandshake)
		}

		// Separate sentences, separate claims. How many receipts arrived is a
		// fact about this certificate; what checking them found is another;
		// and which list they can be checked against is true of every scan,
		// so it is the standing limit rather than part of either.
		out := []Note{Observed(note)}
		out = append(out, describeReceipts(f, total)...)
		out = append(out, DescribeChromeCT(f.Chrome())...)
		return append(out, LimitTransparencyReceipts.Note())
	}

	if !f.Trusted {
		// Not a fault. A private authority answers to whoever runs it.
		return []Note{Observed(
			"No transparency timestamps were found, and this chain does not reach a trusted " +
				"root. A certificate outside the public authorities is under no obligation to be " +
				"logged.")}
	}

	if f.Stapled {
		// The one case where silence would be a false accusation.
		return []Note{Unsettled(
			"No transparency timestamps were found in the certificate or the handshake. A " +
				"stapled status response can also carry them, and this service does not read it.")}
	}

	return []Note{Observed(
		"No transparency timestamps were found in the certificate, the handshake or a " +
			"stapled response. A publicly trusted certificate is expected to be logged and " +
			"browsers refuse one that is not, so clients may decline this connection.")}
}

// describeReceipts says what checking the receipts found.
//
// Nothing here is graded, for the reason nothing above is: how many receipts a
// certificate needs, and from which logs, is each browser's policy (R21). What
// checking adds is the difference between a receipt that is present and one that
// is genuine.
//
// The four outcomes are kept apart because they send a reader to different
// places. A receipt that does not verify vouches for nothing. A receipt from a
// log the carried list does not name is not false — a log newer than the list, or
// one another browser trusts, looks exactly like that — and saying otherwise
// would accuse a certificate on the strength of an old list.
func describeReceipts(f TransparencyFacts, total int) []Note {
	if !f.Checked {
		reason := f.ListReason
		if reason == "" {
			reason = "this scan did not check them"
		}
		return []Note{Unsettled("The receipts were not verified: " + reason + ". An unchecked receipt is a " +
			"claim that a log recorded this certificate, not proof of it.")}
	}

	list := "Chrome's log list of " + f.ListDate
	if f.ListVersion != "" {
		list += " (version " + f.ListVersion + ")"
	}

	var out []Note
	switch {
	case f.Verified == total:
		// A receipt is a log's signed promise, and a verified one proves the
		// promise was made. That the log kept it is a separate proof. The
		// sentence said "really did record" until the 2026-09-16 audit (A20).
		out = append(out, Observed("Every receipt was checked against the key "+list+" gives its log, and every "+
			"signature verifies: each log named promised to include this certificate. "+
			"Whether it did needs an inclusion proof, which this scan did not ask for."))
	case f.Verified > 0:
		out = append(out, Observed(fmt.Sprintf("%s of the %d verify against the key %s gives its log.",
			plural(f.Verified, "receipt"), total, list)))
	}

	if f.BadSignature > 0 {
		out = append(out, Observed(fmt.Sprintf("%s did not verify against the key %s gives its log, so it vouches for nothing; "+
			"browsers discount it.",
			plural(f.BadSignature, "receipt"), list)))
	}
	if f.UnknownLog > 0 {
		out = append(out, Unsettled(fmt.Sprintf("%s came from a log %s does not name, so there was no key to check it against. A "+
			"newer log looks the same, so it is not established that the receipt is false.", plural(f.UnknownLog, "receipt"), list)))
	}
	if f.Unreadable > 0 {
		out = append(out, Unsettled(fmt.Sprintf("%s could not be checked: the receipt could not be read, or the "+
			"certificate that issued this one was not in the chain to check against.", plural(f.Unreadable, "receipt"))))
	}
	return out
}

// plural writes a count with its noun, so a report does not say "1 logs".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
