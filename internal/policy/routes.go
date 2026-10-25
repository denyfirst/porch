package policy

import (
	"fmt"
	"strings"
)

// Whether the routes to a domain's addresses are signed, described rather
// than graded.
//
// RPKI lets the holder of an address block sign which network may announce
// it, and networks that validate drop an announcement the signature
// contradicts (RFC 6811). An invalid route is one those networks cannot
// reach; an unsigned one is one any network can announce as convincingly as
// the real one. Neither is the domain owner's configuration — it is the
// hosting provider's — so it is reported and not graded (R21), and the note
// says who can fix it.

// RouteFacts is one address and how its route validated.
type RouteFacts struct {
	Address string   `json:"address"`
	Prefix  string   `json:"prefix,omitempty"`
	Origins []string `json:"origins,omitempty"`

	// State is "valid", "invalid", "not-found" or "no-route"; empty with a
	// Reason where nothing was established.
	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// RoutesLine says how the routes validated, in one line. skipped is how many
// further addresses were not asked about, past the bound on how many are.
func RoutesLine(rs []RouteFacts, skipped int) string {
	if len(rs) == 0 {
		return ""
	}
	return routesCounted(rs) + notAsked(skipped)
}

// notAsked is the tail of the line where the bound left addresses out. Until
// 2026-10-25 the line said "of 8 addresses" of a name with twelve, and a
// reader took the eight for all of them.
func notAsked(skipped int) string {
	if skipped <= 0 {
		return ""
	}
	return fmt.Sprintf(", and %d more not asked", skipped)
}

func routesCounted(rs []RouteFacts) string {
	count := map[string]int{}
	unsettled := 0
	for _, r := range rs {
		if r.State == "" {
			unsettled++
			continue
		}
		count[r.State]++
	}
	if count["valid"] == len(rs) {
		if len(rs) == 1 {
			return "signed and valid for the one address"
		}
		return fmt.Sprintf("signed and valid for all %d addresses", len(rs))
	}
	var parts []string
	add := func(n int, says string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, says))
		}
	}
	add(count["invalid"], "invalid")
	add(count["not-found"], "not signed")
	add(count["valid"], "valid")
	add(count["no-route"], "with no route seen")
	add(unsettled, "not established")
	return strings.Join(parts, ", ") + " of " + addresses(len(rs))
}

// plainAddresses is "the other N were", or "one other was" for one.
func plainAddresses(n int) string {
	if n == 1 {
		return "one other was"
	}
	return fmt.Sprintf("the other %d were", n)
}

// addresses writes a count of addresses; plural would add a bare s.
func addresses(n int) string {
	if n == 1 {
		return "1 address"
	}
	return fmt.Sprintf("%d addresses", n)
}

// DescribeRoutes says what an invalid or unsigned route means, and who can
// change it; why a route was not established, where one was not; and which
// addresses were not asked about at all.
func DescribeRoutes(rs []RouteFacts, skipped int) []Note {
	var invalid, unsigned []string
	unread := map[string][]string{}
	var reasons []string
	for _, r := range rs {
		switch {
		case r.State == "invalid":
			invalid = append(invalid, r.Address)
		case r.State == "not-found":
			unsigned = append(unsigned, r.Address)
		case r.State == "":
			// Said, with the reason. Until 2026-10-25 the line counted these
			// as "not established" and nothing said why, so a service that
			// could not be reached and a route nobody could find looked alike.
			reason := r.Reason
			if reason == "" {
				reason = "no reason was recorded"
			}
			if _, ok := unread[reason]; !ok {
				reasons = append(reasons, reason)
			}
			unread[reason] = append(unread[reason], r.Address)
		}
	}
	var out []Note
	for _, reason := range reasons {
		routeIs := "route to " + list(unread[reason]) + " is"
		if len(unread[reason]) > 1 {
			routeIs = "routes to " + list(unread[reason]) + " are"
		}
		out = append(out, Unsettled("Whether the "+routeIs+" signed was not established: "+reason+"."))
	}
	if skipped > 0 {
		out = append(out, Unsettled(fmt.Sprintf("Routes were asked about for %s, the name's own first and "+
			"then its name servers', and %s not asked about.", addresses(len(rs)), plainAddresses(skipped))))
	}
	if len(invalid) > 0 {
		out = append(out, Observed("The route to "+list(invalid)+" contradicts its RPKI signature (RFC 6811), "+
			"so networks that validate routes drop it and cannot reach "+them(invalid)+". The network "+
			"announcing it, or the holder of the block, has to correct the announcement or the signature."))
	}
	if len(unsigned) > 0 {
		out = append(out, Observed("Nobody has signed the route to "+list(unsigned)+", so any network that "+
			"announces "+them(unsigned)+" is believed as readily as the real one. The holder of the block, "+
			"usually the hosting provider, signs it with a ROA at its registry."))
	}
	return out
}

func them(addresses []string) string {
	if len(addresses) == 1 {
		return "it"
	}
	return "them"
}
