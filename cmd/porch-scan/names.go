package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/liveness"
)

// The inventory of names a domain's public certificates reveal.
//
// # Why this is not a check
//
// Every other mode here measures something and grades it against a document.
// This one reads a register and lists what is in it. There is no verdict,
// because no document says how many names an estate may have or which of them
// ought to exist — a grade here would be a threshold this project invented,
// which is what R21 refuses.
//
// So it prints no verdict and returns zero unless the search itself failed, and
// the report says in its own words that nothing was graded. A reader who saw a
// list with no verdict and no sentence explaining the absence would supply the
// missing verdict themselves, and the one they supply is "fine".
//
// # Why it is allowed at all
//
// N7 refuses invented addresses: no wordlist, no guessing, nothing sent to the
// estate. Every name here was published by whoever obtained a certificate for
// it, in a log that exists to be read. Finding them sends not one packet to the
// domain being asked about.
//
// N12 governs the disclosure instead, and it is the real cost: the question
// names the domain to a monitor this project does not run. That is why this is
// never available on a demonstration build, which promises it queries no log,
// and why on the command line it is a mode somebody types rather than anything
// that runs by default.
func runNames(ctx context.Context, domains []string, timeout time.Duration, monitor, monitorURL, resolver string, asJSON bool) int {
	if demo.Enabled {
		fmt.Fprintln(os.Stderr, "this is a demonstration build, and it asks no certificate "+
			"transparency monitor anything")
		return 2
	}

	searcher, err := monitorNamed(monitor, monitorURL, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Which resolver answers decides what this report means, so it is the
	// operator's to choose.
	//
	// It matters more here than anywhere else in this program. A resolver
	// inside an organisation answers that organisation's own names with
	// internal addresses, so an inventory built from a desk reports the inside
	// while reading as though it had measured the outside. That is why an
	// address nothing may dial is a status of its own below rather than a
	// timeout.
	checker := &liveness.Checker{
		Timeout:  timeout,
		Resolver: &dnsclient.Client{Server: resolver, Timeout: timeout},
	}

	worst := 0
	for i, domain := range domains {
		found := searcher.SearchEstate(ctx, domain)

		// And what each of them is doing now, which a list of names cannot
		// answer. Every source of names is a record of the past; an operator
		// is asking about the present.
		live := checker.Check(ctx, hosts(found))

		if asJSON {
			if err := json.NewEncoder(os.Stdout).Encode(found); err != nil {
				fmt.Fprintln(os.Stderr, "the inventory could not be written")
				return 2
			}
		} else {
			if i > 0 {
				fmt.Fprintln(os.Stdout)
			}
			printNames(os.Stdout, found, live)
		}

		if found.Reason != "" {
			worst = 2
		}
	}
	return worst
}

// printNames writes one estate's inventory.
func printNames(w io.Writer, e ctsearch.Estate, live []liveness.Name) {
	fmt.Fprintf(w, "%s\n", e.Domain)
	fmt.Fprintf(w, "  Names in public certificates\n")

	if e.Reason != "" {
		fmt.Fprintf(w, "    Not established: %s\n", e.Reason)
		return
	}

	fmt.Fprintf(w, "    Found        %d distinct %s across %d %s\n",
		e.Distinct, plural(e.Distinct, "name", "names"),
		e.Certificates, plural(e.Certificates, "certificate", "certificates"))

	if e.Wildcards > 0 {
		fmt.Fprintf(w, "    Wildcards    %d, each covering hosts it does not name\n", e.Wildcards)
	}
	if e.Foreign > 0 {
		fmt.Fprintf(w, "    Other names  %d on the same certificates, under other domains, not listed\n", e.Foreign)
	}
	if e.Truncated {
		fmt.Fprintf(w, "    Cut          more names were found than are listed\n")
	}

	printNamesNow(w, e, live)
	printWildcards(w, e)
	printNamesLimits(w, e)
}

// covered says the window the logs show one name in.
//
// The expiry is the useful end. A name whose newest certificate ran out two
// years ago is either gone or is now covered by a wildcard, and an operator
// reading an inventory of their own estate wants to find exactly those. Which
// of the two it is, this does not say: it has not asked the host anything and
// saying would be inventing the answer (R17).
func covered(n ctsearch.Name) string {
	if n.LastSeen.IsZero() {
		return "no dates in the log"
	}
	out := "certificates to " + n.LastSeen.Format("2006-01-02")
	if !n.FirstSeen.IsZero() {
		out = "from " + n.FirstSeen.Format("2006-01-02") + ", " + out
	}
	return out
}

// printNamesLimits says what this method cannot see.
//
// Printed every time, under every inventory, and not shortened when the list is
// long. This is the sentence that decides whether the report is honest: read
// without it, a list of forty names says "your estate has forty hosts", which
// is not what any of this establishes and is not something a certificate log
// can establish for anybody.
//
// It is also the sentence that protects whoever presents the report. A list
// handed to a security team as an estate inventory, which a port scan then adds
// to, costs the person who handed it over their credibility — and the
// difference between the two methods was knowable in advance and written here.
func printNamesLimits(w io.Writer, e ctsearch.Estate) {
	fmt.Fprintf(w, "\n  What this does not show\n")
	fmt.Fprintf(w, "    Nothing here was guessed and nothing was asked of %s: these names\n", e.Domain)
	fmt.Fprintf(w, "    were published by whoever obtained a certificate for them.\n")
	fmt.Fprintf(w, "    A host with no publicly trusted certificate never appears — plain\n")
	fmt.Fprintf(w, "    HTTP, a service that is not HTTPS, or anything behind a private\n")
	fmt.Fprintf(w, "    authority leaves no trace in a public log.\n")

	if e.Wildcards > 0 {
		fmt.Fprintf(w, "    A wildcard covers hosts without naming them, and %d of the names\n"+
			"    above %s.\n", e.Wildcards, plural(e.Wildcards, "is a wildcard", "are wildcards"))
	}

	fmt.Fprintf(w, "    This is an inventory, not a verdict: nothing above is graded, because\n")
	fmt.Fprintf(w, "    no document says which names an estate ought to have.\n")
}

// plural picks the word for a count, so a report does not say "1 names".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// namesTargets refuses anything that is not a bare domain.
//
// A port, a scheme or a path here means somebody is asking a question this mode
// does not answer, and answering the nearest one instead is how a report comes
// to be about something other than what was asked.
func namesTargets(targets []string) error {
	for _, t := range targets {
		if strings.ContainsAny(t, ":/") {
			return fmt.Errorf("%q is not a bare domain: this mode reads a register under a "+
				"domain and takes no port, scheme or path", t)
		}
	}
	return nil
}

// The monitors this can be pointed at, spelled once.
const (
	monitorCRTSh       = "crtsh"
	monitorCertSpotter = "certspotter"
)

// monitorNamed builds the monitor to ask.
//
// Two of them, with different owners and different infrastructure, because a
// dependency described as replaceable and never replaced is a claim nobody has
// checked. crt.sh answered 502 to every request for a day while this was being
// written, which is an ordinary state for a free service indexing billions of
// certificates — and on that day the argument stopped being theoretical.
//
// The address is separate from the choice. An operator running their own index
// of one of these, or a paid one, overrides where it is asked without having to
// say which answer format it speaks.
func monitorNamed(name, address string, timeout time.Duration) (ctsearch.EstateSearcher, error) {
	switch name {
	case "", monitorCRTSh:
		if address != "" && !strings.Contains(address, "%s") {
			// Without it the same address is fetched for every domain, and the
			// answer would be an inventory of whatever that address holds,
			// reported under the name that was asked about.
			return nil, fmt.Errorf("-monitor-url for %s needs %%s where the name goes", monitorCRTSh)
		}
		return &ctsearch.CRTSh{Timeout: timeout, Endpoint: address}, nil

	case monitorCertSpotter:
		// The token is read from the environment rather than a flag: it
		// identifies whoever is running this to the monitor, and a credential
		// on a command line is a credential in a shell history and in every
		// process listing on the machine.
		return &ctsearch.CertSpotter{
			Timeout:  timeout,
			Endpoint: address,
			Token:    os.Getenv("CERTSPOTTER_TOKEN"),
		}, nil
	}
	return nil, fmt.Errorf("unknown monitor %q: it is %s or %s", name, monitorCRTSh, monitorCertSpotter)
}

// printNamesNow draws what each name is doing, which is the column an operator
// reads first.
//
// Status before the name, because the question is "what do I have to deal
// with" rather than "what is this name called". A reader runs an eye down the
// left edge and stops at the ones that are not "live".
func printNamesNow(w io.Writer, e ctsearch.Estate, live []liveness.Name) {
	if len(live) == 0 {
		// Nothing established what they are doing, so the names are still
		// drawn and the heading says which question went unanswered. Dropping
		// them would lose the half of the report that was established, to
		// report the half that was not (R4).
		printNamesFound(w, e)
		return
	}

	fmt.Fprintf(w, "\n  What each name is doing now\n")

	width := 0
	for _, n := range live {
		if len(n.Name) > width {
			width = len(n.Name)
		}
	}

	// The window each name was covered in, from the register that named it.
	//
	// Without it a name is only ever "now", and the finding that matters most
	// in an old estate cannot be seen: a name whose newest certificate expired
	// four years ago and which is still answering on 443 is a service nobody
	// has looked at since, and the two halves of that sentence live in two
	// different columns. A reader who saw only the status would chase it as
	// though it were current, and a reader who saw only the date would not
	// know it was still running.
	covered := map[string]string{}
	for _, n := range e.Names {
		covered[n.Name] = lastCovered(n)
	}

	for _, n := range live {
		line := says(n)
		if when := covered[n.Name]; when != "" {
			line += "; " + when
		}
		fmt.Fprintf(w, "    %-9s %-*s %s\n", n.Status, width, n.Name, line)
	}
}

// lastCovered says when the register last had this name, in the fewest words
// that stay true.
//
// The expiry rather than the issue date: what an operator is looking for is a
// name nobody has renewed, and the issue date of a certificate that ran out
// three years ago says the same thing less directly. Where the log carried no
// dates at all this says nothing rather than guessing at one.
func lastCovered(n ctsearch.Name) string {
	if n.LastSeen.IsZero() {
		return ""
	}
	return "certificates to " + n.LastSeen.Format("2006-01-02")
}

// says is the evidence beside one name: where it points, or why nothing was
// established.
func says(n liveness.Name) string {
	switch {
	case n.Reason != "":
		return n.Reason
	case n.Status == liveness.Dangling:
		return "an alias to " + n.Alias + ", which does not resolve"
	case n.Status == liveness.Gone:
		return "does not resolve"
	case n.Status == liveness.Internal:
		return addressList(n) + " — nothing here may dial it, and a resolver elsewhere may answer differently"
	case n.Status == liveness.Live:
		return addressList(n) + ", answering on " + strings.Join(n.Answered, " and ")
	default:
		return addressList(n) + ", nothing answered"
	}
}

// addressList is where a name points, bounded so that one name with forty
// addresses does not become the report.
func addressList(n liveness.Name) string {
	const show = 3

	var out []string
	for i, a := range n.Addresses {
		if i >= show {
			out = append(out, fmt.Sprintf("and %d more", len(n.Addresses)-show))
			break
		}
		out = append(out, a.String())
	}
	if n.Alias != "" {
		return strings.Join(out, ", ") + " via " + n.Alias
	}
	return strings.Join(out, ", ")
}

// printWildcards draws the names that are not hosts.
//
// Apart from the rest, and without a status, because a wildcard is not a name
// anything resolves: asking what `*.example.com` is doing would be asking a
// question with no answer. What it is doing is hiding however many hosts are
// behind it, which the paragraph below says.
func printWildcards(w io.Writer, e ctsearch.Estate) {
	var wildcards []ctsearch.Name
	for _, n := range e.Names {
		if n.Wildcard {
			wildcards = append(wildcards, n)
		}
	}
	if len(wildcards) == 0 {
		return
	}

	fmt.Fprintf(w, "\n  Wildcards, which name no host\n")
	for _, n := range wildcards {
		fmt.Fprintf(w, "    %-44s %s\n", n.Name, covered(n))
	}
}

// hosts are the names in an inventory that something could resolve.
//
// A wildcard is left out because it is not a name: nothing resolves
// `*.example.com`, and putting it through a resolver would produce a failure
// that reads as a fault in the estate.
func hosts(e ctsearch.Estate) []string {
	var out []string
	for _, n := range e.Names {
		if !n.Wildcard {
			out = append(out, n.Name)
		}
	}
	return out
}

// printNamesFound draws the names with no status beside them.
//
// What a report looks like when the register was read and nothing asked what
// the names are doing: the list, the window each was covered in, and a heading
// that says so. It is the older half of this report and it is kept, because a
// reader who cannot reach a resolver should still get the names.
func printNamesFound(w io.Writer, e ctsearch.Estate) {
	var named []ctsearch.Name
	for _, n := range e.Names {
		if !n.Wildcard {
			named = append(named, n)
		}
	}
	if len(named) == 0 {
		return
	}

	fmt.Fprintf(w, "\n  Names found, none of them asked what it is doing now\n")
	for _, n := range named {
		fmt.Fprintf(w, "    %-44s %s\n", n.Name, covered(n))
	}
}
