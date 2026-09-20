package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	scanner := &dnsscan.Scanner{}
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

		switch {
		case f.AddressReason != "":
			fmt.Fprintf(w, "    Addresses  not read: %s\n", f.AddressReason)
		case len(f.Addresses) == 0:
			fmt.Fprintf(w, "    Addresses  none\n")
		default:
			fmt.Fprintf(w, "    Addresses  %s\n", strings.Join(f.Addresses, ", "))
		}

		if f.Alias != "" {
			gone := ""
			if !f.AliasTargetExists {
				gone = ", which does not exist"
			}
			fmt.Fprintf(w, "    Alias      %s%s\n", f.Alias, gone)
		}

		if f.SOAFound {
			fmt.Fprintf(w, "    Zone       begins here, serial %d, primary %s\n", f.SOASerial, f.SOAPrimary)
		} else {
			fmt.Fprintf(w, "    Zone       begins above this name\n")
		}

		fmt.Fprintf(w, "    Text       %d records\n", len(f.Text))
		fmt.Fprintf(w, "    DNSSEC     %s\n", dnssecLine(*f))

		printDelegation(w, *f)
	}

	printFindings(w, r.Findings)
	printNotes(w, r.Notes, dnsMethodPage)
}

// dnssecLine says what the chain is, in the order a reader asks it: whether the
// zone is signed at all, and then whether the link holds.
func dnssecLine(f policy.DNSFacts) string {
	switch {
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
		case len(ns.Addresses) == 0:
			fmt.Fprintf(w, "    %-28s resolves to nothing\n", ns.Name)
		default:
			fmt.Fprintf(w, "    %-28s %s\n", ns.Name, strings.Join(ns.Addresses, ", "))
		}
	}
	if len(f.NameServers) > 1 && f.Networks == 1 {
		fmt.Fprintf(w, "    every address above is in one network, so they fail together\n")
	}
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
