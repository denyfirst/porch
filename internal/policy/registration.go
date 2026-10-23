package policy

import (
	"fmt"
	"strings"
	"time"
)

// A domain's registration, described rather than graded.
//
// When a registration runs out, every service under the domain goes with it;
// and a domain its registrar has not locked against transfer is one a stolen
// registrar password is enough to lose. Neither shows in the domain's DNS.
// Both are answered by the registry, which is asked directly (internal/rdap).
//
// Not graded, because no standard sets a line (R21): how long before expiry is
// too close, and whether a lock is wanted, are the owner's choices. The line
// says the facts and the notes say what they mean.

// RegistrationFacts is what the registry holds.
type RegistrationFacts struct {
	// Asked is false when no registry was asked.
	Asked bool `json:"asked"`

	// Domain is the registered domain the registry answered for, and
	// Registry the host that answered.
	Domain   string `json:"domain,omitempty"`
	Registry string `json:"registry,omitempty"`

	Registrar string    `json:"registrar,omitempty"`
	Created   time.Time `json:"created,omitzero"`
	Expires   time.Time `json:"expires,omitzero"`
	Changed   time.Time `json:"changed,omitzero"`

	// Statuses are the registry's status values (RFC 8056), and the two
	// below are read from them.
	Statuses       []string `json:"statuses,omitempty"`
	TransferLocked bool     `json:"transferLocked"`
	RegistryLocked bool     `json:"registryLocked"`

	DelegationSigned bool `json:"delegationSigned"`

	// Reason says why nothing was established.
	Reason string `json:"reason,omitempty"`
}

// renewSoon is how close an expiry is said to be close. Not a grade: the
// sentence that says so is a note.
const renewSoon = 30 * 24 * time.Hour

// RegistrationLine says what the registry holds, in one line.
func RegistrationLine(f RegistrationFacts, now time.Time) string {
	switch {
	case !f.Asked:
		return ""
	case f.Reason != "":
		return "not established: " + f.Reason
	}

	var parts []string
	head := f.Domain
	if f.Registrar != "" {
		head += ", registered through " + f.Registrar
	}
	parts = append(parts, head)

	if !f.Expires.IsZero() {
		parts = append(parts, expiryPhrase(f.Expires, now))
	}

	switch {
	case f.RegistryLocked:
		parts = append(parts, "locked at the registry")
	case f.TransferLocked:
		parts = append(parts, "locked against transfer")
	default:
		parts = append(parts, "not locked against transfer")
	}
	return strings.Join(parts, "; ")
}

func expiryPhrase(expires, now time.Time) string {
	date := expires.UTC().Format("2006-01-02")
	days := int(expires.Sub(now).Hours() / 24)
	switch {
	case expires.Before(now):
		return fmt.Sprintf("ran out %s, %s ago", date, plural(-days, "day"))
	case days == 0:
		return "runs out " + date + ", today"
	default:
		return fmt.Sprintf("runs out %s, in %s", date, plural(days, "day"))
	}
}

// DescribeRegistration is what the facts mean, where they mean something to
// act on.
func DescribeRegistration(f RegistrationFacts, now time.Time) []Note {
	if !f.Asked || f.Reason != "" {
		return nil
	}
	var out []Note
	// A registration that has run out is graded (dns.registration-expired)
	// and said there.
	switch {
	case !f.Expires.IsZero() && f.Expires.Before(now):
	case !f.Expires.IsZero() && f.Expires.Sub(now) < renewSoon:
		out = append(out, Observed("The registration runs out within a month. Every service under the "+
			"domain stops with it; renewing, or turning on automatic renewal, is done at the registrar."))
	}
	if !f.TransferLocked {
		out = append(out, Observed("The domain is not locked against transfer, so whoever holds the "+
			"registrar account can move it to another registrar. Most registrars set the lock "+
			"(clientTransferProhibited, RFC 5731) on request and at no cost."))
	}
	return out
}
