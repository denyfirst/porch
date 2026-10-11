package policy

import (
	"fmt"
	"time"
)

// Chrome's certificate transparency policy, applied to the receipts a
// certificate carried.
//
// This file said for a long time that how many receipts a certificate needs
// is each browser's policy and not ours to enforce, and left the reader to
// compare the count with whichever client they cared about. That was a gap
// dressed as modesty. The policy is published, Chrome is most of the web, and
// the log list it is judged against is the one this build already carries,
// signed by Google and dated in the report. So the comparison is made here,
// and reported as Chrome's — not graded, because it is one browser's rule
// rather than a standard, and the report says which list it used.
//
// What Chrome requires, as of its policy in 2026:
//
//   - Receipts embedded in the certificate: two from distinct logs for a
//     certificate valid 180 days or less, three for a longer one; from at
//     least two distinct log operators; and at least one from an RFC 6962
//     log rather than a static-ct one. A receipt counts if its log is
//     usable, qualified or read-only, or retired after the receipt was
//     issued.
//   - Receipts in the TLS handshake: two from distinct logs and distinct
//     operators, at least one from an RFC 6962 log, each log usable,
//     qualified or read-only.
//   - Receipts in a stapled OCSP response stopped counting in Chrome 148.
//
// Only receipts whose signature verified count. A receipt from a log the
// carried list does not name might be from a newer log Chrome does count, so
// where one is present and the rest fall short, the answer is unsettled rather
// than a failure.

// chromeCTSource is the policy the comparison follows.
var chromeCTSource = Reference{
	"Chrome Certificate Transparency Policy",
	"https://googlechrome.github.io/CertificateTransparency/ct_policy.html",
}

// CTReceipt is one receipt, as Chrome's policy reads it.
type CTReceipt struct {
	// Verified is whether its signature verified against the log's key.
	Verified bool `json:"verified"`

	// UnknownLog is whether the carried list names no such log.
	UnknownLog bool `json:"unknownLog,omitempty"`

	// InHandshake is whether it arrived in the TLS extension rather than
	// embedded in the certificate.
	InHandshake bool `json:"inHandshake,omitempty"`

	LogID    string    `json:"logId"`
	Operator string    `json:"operator,omitempty"`
	State    string    `json:"state,omitempty"`
	Since    time.Time `json:"since,omitzero"`
	Issued   time.Time `json:"issued,omitzero"`
	Tiled    bool      `json:"tiled,omitempty"`
}

// ChromeCT is what the comparison found.
type ChromeCT struct {
	// Judged is false when there was nothing to compare: no receipts were
	// checked, or the certificate is outside the public authorities.
	Judged bool `json:"judged"`

	// Met is whether the receipts satisfy the policy. Settled is false when
	// they fall short but a receipt from a log the list does not name might
	// make up the difference.
	Met     bool `json:"met"`
	Settled bool `json:"settled"`

	// Needed is how many distinct logs the certificate's lifetime calls for,
	// and Logs and Operators how many distinct counting logs and operators
	// the embedded receipts came from.
	Needed    int `json:"needed"`
	Logs      int `json:"logs"`
	Operators int `json:"operators"`

	// ListDate is the date of the log list the comparison used.
	ListDate string `json:"listDate,omitempty"`
}

// maxShortLifetime is the longest a certificate can be valid and need two
// embedded receipts rather than three.
const maxShortLifetime = 180 * 24 * time.Hour

// JudgeChromeCT compares the receipts with Chrome's policy.
//
// lifetime is the certificate's validity period, from notBefore to notAfter.
func JudgeChromeCT(receipts []CTReceipt, lifetime time.Duration, listDate string) ChromeCT {
	out := ChromeCT{ListDate: listDate, Needed: 2}
	if lifetime > maxShortLifetime {
		out.Needed = 3
	}
	if len(receipts) == 0 {
		return out
	}
	out.Judged = true

	var embedded, handshake []CTReceipt
	unknown := false
	for _, r := range receipts {
		if r.UnknownLog {
			unknown = true
		}
		if !r.Verified {
			continue
		}
		if r.InHandshake {
			if current(r.State) {
				handshake = append(handshake, r)
			}
			continue
		}
		if current(r.State) || (r.State == "retired" && !r.Issued.IsZero() && !r.Since.IsZero() && r.Issued.Before(r.Since)) {
			embedded = append(embedded, r)
		}
	}

	logs, operators, rfc6962 := diversity(embedded)
	out.Logs, out.Operators = logs, operators
	embeddedMet := logs >= out.Needed && operators >= 2 && rfc6962

	hLogs, hOperators, hRFC6962 := diversity(handshake)
	handshakeMet := hLogs >= 2 && hOperators >= 2 && hRFC6962

	out.Met = embeddedMet || handshakeMet
	out.Settled = out.Met || !unknown
	if handshakeMet && !embeddedMet {
		out.Logs, out.Operators, out.Needed = hLogs, hOperators, 2
	}
	return out
}

// current is whether a log in this state counts at the time of checking.
func current(state string) bool {
	switch state {
	case "usable", "qualified", "readonly":
		return true
	}
	return false
}

// diversity counts the distinct logs and operators among receipts, and
// whether any came from an RFC 6962 log.
func diversity(rs []CTReceipt) (logs, operators int, rfc6962 bool) {
	seenLog := map[string]bool{}
	seenOp := map[string]bool{}
	for _, r := range rs {
		if !seenLog[r.LogID] {
			seenLog[r.LogID] = true
			logs++
		}
		if r.Operator != "" && !seenOp[r.Operator] {
			seenOp[r.Operator] = true
			operators++
		}
		if !r.Tiled {
			rfc6962 = true
		}
	}
	return logs, operators, rfc6962
}

// ChromeCTLine says what the comparison found, in a few words.
func ChromeCTLine(c ChromeCT) string {
	switch {
	case !c.Judged:
		return ""
	case c.Met:
		return fmt.Sprintf("meets Chrome's policy: %s from %s, %d needed",
			plural(c.Logs, "log"), plural(c.Operators, "operator"), c.Needed)
	case !c.Settled:
		return fmt.Sprintf("short of Chrome's policy by the logs this build knows: %s from %s, %d needed",
			plural(c.Logs, "log"), plural(c.Operators, "operator"), c.Needed)
	default:
		return fmt.Sprintf("does not meet Chrome's policy: %s from %s, %d needed from at least 2 operators",
			plural(c.Logs, "log"), plural(c.Operators, "operator"), c.Needed)
	}
}

// DescribeChromeCT is the note beside the line.
func DescribeChromeCT(c ChromeCT) []Note {
	switch {
	case !c.Judged:
		return nil
	case c.Met:
		return nil
	case !c.Settled:
		return []Note{Unsettled("These receipts fall short of Chrome's certificate transparency policy " +
			"as judged against its log list of " + c.ListDate + ", but one came from a log that list " +
			"does not name, which may be a newer log Chrome counts. " + chromeCTSource.Label + ".")}
	default:
		return []Note{Observed("Chrome refuses a publicly trusted certificate whose receipts do not meet " +
			"its certificate transparency policy, judged here against its log list of " + c.ListDate +
			". Ask the authority that issued it for a certificate logged to more logs. " +
			chromeCTSource.Label + ".")}
	}
}
