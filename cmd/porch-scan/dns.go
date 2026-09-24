package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/dnsscan"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/results"
)

// dnsResult is one domain, with room for the reason it could not be read.
//
// The same shape as the other checks': a caller reading JSON from this command
// should not have to learn a fourth arrangement because there is a fourth
// check.
type dnsResult struct {
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
	*dnsscan.Result
}

// runDNS reads each domain's own DNS.
//
// No -allow-private here, and its absence is the point rather than an
// omission. The flag exists on the checks that open connections, so that an
// operator can measure a server on their own network; this opens nothing. It
// asks a resolver, and a resolver answers about a private name the same way it
// answers about anything else.
func runDNS(ctx context.Context, domains []string, timeout time.Duration, resolver string, asJSON bool, store *results.Store) int {
	// The command line asks the delegation directly: the scan runs on the
	// operator's own machine, from their own address, under their
	// responsibility — the argument -allow-private rests on for the other
	// checks.
	scanner := &dnsscan.Scanner{AskServers: true}
	if resolver != "" {
		scanner.Resolver = &dnsclient.Client{Server: resolver, Timeout: timeout}
	}

	reports := make([]dnsResult, 0, len(domains))
	for _, domain := range domains {
		r := dnsResult{Domain: domain}

		measured, err := scanner.Scan(ctx, domain)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Result = measured
			r.Domain = measured.Domain
		}
		reports = append(reports, r)

		if r.Result != nil {
			keep(store, checkDNS, r.Domain, r.Verdict, r.Policy, r.Findings)
		}
	}

	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(reports); err != nil {
			fmt.Fprintf(os.Stderr, "writing JSON: %v\n", err)
			return exitError
		}
	} else {
		for i, r := range reports {
			if i > 0 {
				fmt.Println()
			}
			printDNS(os.Stdout, r)
		}
	}

	return exitCode(dnsOutcomes(reports))
}

// printDNS writes one domain's report.
func printDNS(w io.Writer, r dnsResult) {
	fmt.Fprintf(w, "\n%s\n%s\n", r.Domain, strings.Repeat("=", len(r.Domain)))

	if r.Error != "" {
		fmt.Fprintf(w, "\n  scan failed: %s\n", r.Error)
		return
	}

	verdict := string(r.Verdict)
	if verdict == "" {
		verdict = "ungraded (no zone begins at this name, so there was nothing to grade)"
	}
	fmt.Fprintf(w, "\n  Verdict   %s\n", verdict)
	if r.Verdict == policy.Weak || r.Verdict == policy.Insecure {
		fmt.Fprintf(w, "            %s\n", wrap(policy.WorstCase, 66, "            "))
	}
	fmt.Fprintf(w, "  Policy    %s\n", r.Policy)

	if f := r.Observed; f != nil {
		fmt.Fprintf(w, "\n  What the name publishes\n")

		// Two kinds, two lines, and "none" on the line that found nothing:
		// merged, a reader cannot tell a name with no IPv6 from one nobody
		// asked about.
		if f.AddressReason != "" {
			fmt.Fprintf(w, "    Addresses  not read: %s\n", f.AddressReason)
		} else {
			fmt.Fprintf(w, "    IPv4       %s\n", listOrNone(f.IPv4))
			fmt.Fprintf(w, "    IPv6       %s\n", listOrNone(f.IPv6))
		}

		switch {
		case f.AliasReason != "":
			fmt.Fprintf(w, "    Alias      not read: %s\n", f.AliasReason)
		case f.Alias == "":
			fmt.Fprintf(w, "    Alias      none\n")
		case f.AliasTargetExists:
			fmt.Fprintf(w, "    Alias      %s\n", f.Alias)
		default:
			fmt.Fprintf(w, "    Alias      %s, which does not exist\n", f.Alias)
		}

		if f.SOAFound {
			fmt.Fprintf(w, "    Zone       begins here, serial %d, primary %s\n", f.SOASerial, f.SOAPrimary)
		} else {
			fmt.Fprintf(w, "    Zone       begins above this name\n")
		}

		printText(w, f.Text)
		fmt.Fprintf(w, "    DNSSEC     %s\n", dnssecLine(*f))

		// The algorithm by the name an operator's own interface uses, and how
		// absent names are proved: both facts about a signed zone, neither a
		// verdict about it.
		if f.Signed {
			if names := algorithmNames(f.Keys); names != "" {
				fmt.Fprintf(w, "    Signed with %s\n", names)
			}
			if f.NSEC3Read {
				fmt.Fprintf(w, "    Absent     %s\n", absenceLine(*f))
			}
		}

		printDelegation(w, *f)
	}

	printFindings(w, r.Findings)
	printNotes(w, r.Notes, dnsMethodPage)
}

// dnssecLine says what the chain is, in the order a reader asks it: whether the
// zone is signed at all, and then whether the link holds.
func dnssecLine(f policy.DNSFacts) string {
	switch {
	case !f.Apex:
		// The chain is a property of a zone, and no zone begins here. Nothing
		// was asked, so "not signed" would be a claim about a zone this never
		// looked at — and the zone above may well be signed (R4).
		return "not read: the chain belongs to the zone above this name"
	case !f.Signed:
		return "not signed"
	case f.ChainReason != "":
		return "not checked: " + f.ChainReason
	case f.ChainMatched:
		return "signed, and the parent's digest matches a key here"
	case len(f.Keys) == 0:
		return "anchored at the parent, and no key is published here"
	default:
		return "anchored at the parent, and no key here matches its digest"
	}
}

// printDelegation lists the servers the zone is answered by, one line each, so
// that a name resolving to nothing is visible beside the ones that resolve.
func printDelegation(w io.Writer, f policy.DNSFacts) {
	if !f.Apex {
		return
	}

	fmt.Fprintf(w, "\n  Where the zone is answered\n")
	if f.NSReason != "" {
		fmt.Fprintf(w, "    not read: %s\n", f.NSReason)
		return
	}
	if len(f.NameServers) == 0 {
		fmt.Fprintf(w, "    the zone names no server\n")
		return
	}

	for _, ns := range f.NameServers {
		switch {
		case ns.Reason != "":
			fmt.Fprintf(w, "    %-28s not read: %s\n", ns.Name, ns.Reason)
		case ns.Asked && !ns.Authoritative:
			fmt.Fprintf(w, "    %-28s does not answer for this zone\n", ns.Name)
		case ns.Transfer:
			// Ahead of the addresses, because it is the line a reader of this
			// block acts on: everything else here says how the zone is reached,
			// and this says the whole of it can be taken.
			fmt.Fprintf(w, "    %-28s %s — hands out the whole zone to anybody\n",
				ns.Name, strings.Join(ns.Addresses, ", "))
		case ns.Recursion:
			fmt.Fprintf(w, "    %-28s %s — answers for other domains too\n",
				ns.Name, strings.Join(ns.Addresses, ", "))
		case ns.Alias != "":
			fmt.Fprintf(w, "    %-28s an alias for %s\n", ns.Name, ns.Alias)
		case len(ns.Addresses) == 0:
			fmt.Fprintf(w, "    %-28s resolves to nothing\n", ns.Name)
		default:
			fmt.Fprintf(w, "    %-28s %s\n", ns.Name, strings.Join(ns.Addresses, ", "))
		}
	}
	if len(f.NameServers) > 1 && f.Networks == 1 {
		fmt.Fprintf(w, "    every address above is in one network, so they fail together\n")
	}

	fmt.Fprintf(w, "    %-28s %s\n", "the zone above", parentLine(f))
}

// parentLine says what the zone above this one hands out, which is the list a
// resolver starting at the root follows rather than the one above.
func parentLine(f policy.DNSFacts) string {
	switch {
	case f.ParentReason != "":
		return "not read: " + f.ParentReason
	case !f.ParentAsked:
		return "not asked"
	}

	atParent, atZone := f.OnlyAtParent, f.OnlyAtZone
	if len(atParent) == 0 && len(atZone) == 0 {
		return f.Parent + " hands out the same servers"
	}

	var parts []string
	if len(atParent) > 0 {
		parts = append(parts, "hands out "+strings.Join(atParent, ", ")+" as well")
	}
	if len(atZone) > 0 {
		parts = append(parts, "does not hand out "+strings.Join(atZone, ", "))
	}
	return f.Parent + " " + strings.Join(parts, ", and ")
}

// dnsOutcomes collects what each domain was graded, for the exit status.
func dnsOutcomes(reports []dnsResult) []outcome {
	out := make([]outcome, 0, len(reports))
	for _, r := range reports {
		o := outcome{Failed: r.Error != ""}
		if r.Result != nil {
			o.Verdict = r.Verdict
		}
		out = append(out, o)
	}
	return out
}

// listOrNone writes a list, or says there was none. Empty is a fact here: the
// lookup happened and found nothing.
func listOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

// printText writes the text records as published.
//
// As published, and marked as that. Everything else in a report is written by
// this program; these are the only lines in it chosen by whoever is being
// measured, and a reader has to be able to tell the two apart — the difference
// matters most where a record has been made to read like advice.
//
// Bounded twice, because a TXT record is whatever somebody put there: at most
// eight records, and each cut to a length that still shows what it is.
func printText(w io.Writer, records []string) {
	if len(records) == 0 {
		fmt.Fprintf(w, "    Text       none\n")
		return
	}

	shown := records
	if len(shown) > maxTextShown {
		shown = shown[:maxTextShown]
	}
	fmt.Fprintf(w, "    Text       %d records, as published:\n", len(records))
	for _, record := range shown {
		fmt.Fprintf(w, "                 %s\n", cut(record, maxTextLength))
	}
	if len(records) > len(shown) {
		fmt.Fprintf(w, "                 and %d more\n", len(records)-len(shown))
	}
}

// cut shortens a value read out of somebody else's zone, and says it did.
func cut(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

const (
	maxTextShown  = 8
	maxTextLength = 120
)

// algorithmNames lists the algorithms a zone signs with, by name and without
// repeating one, in the words the page uses (R16).
func algorithmNames(keys []policy.KeyDigest) string {
	var names []string
	seen := map[string]bool{}
	for _, k := range keys {
		name := k.Name
		if name == "" {
			name = policy.AlgorithmName(k.Algorithm)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

// absenceLine says how a signed zone proves a name does not exist, in the
// words the page uses (R16).
func absenceLine(f policy.DNSFacts) string {
	if !f.NSEC3 {
		return "named plainly, so the zone can be listed"
	}
	if f.NSEC3Iterations == 0 {
		return "hashed"
	}
	return "hashed, " + strconv.Itoa(int(f.NSEC3Iterations)) + " extra times"
}
