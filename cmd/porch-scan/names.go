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
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/liveness"
)

// The inventory of names a domain's own records and its public certificates
// reveal.
//
// # Why this is not a check
//
// Every other mode here measures something and grades it against a document.
// This one reads registers and lists what is in them. There is no verdict,
// because no document says how many names an estate may have or which of them
// ought to exist — a grade here would be a threshold this project invented,
// which is what R21 refuses.
//
// So it prints no verdict and returns zero unless a source failed, and the
// report says in its own words that nothing was graded. A reader who saw a list
// with no verdict and no sentence explaining the absence would supply the
// missing verdict themselves, and the one they supply is "fine".
//
// # Why it is allowed at all
//
// N7 refuses invented addresses: no wordlist, no guessing. Every name here was
// published by whoever obtained a certificate for it, in a log that exists to
// be read, or by the domain itself, in records it publishes to anybody who
// asks.
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
	client := &dnsclient.Client{Server: resolver, Timeout: timeout}
	checker := &liveness.Checker{Timeout: timeout, Resolver: client}

	// And the cheapest source of names there is, which is the domain itself.
	//
	// Three lookups, no third party, and nothing published that was not already
	// published: an MX names the machine that takes the mail, a sender policy
	// names the hosts allowed to send it, a delegation names the servers that
	// answer. A monitor may be down — one was, all day, while this mode was
	// being written — and this half of the inventory still arrives.
	records := &dnsnames.Reader{Resolver: client, Timeout: timeout}

	worst := 0
	for i, domain := range domains {
		found := inventory.Merge(domain,
			searcher.SearchEstate(ctx, domain),
			records.Under(ctx, domain))

		// And what each of them is doing now, which a list of names cannot
		// answer. Every source of names is a record of the past; an operator
		// is asking about the present.
		live := checker.Check(ctx, found.Hosts())

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

		if shortInventory(found) {
			worst = 2
		}
	}
	return worst
}

// shortInventory reports that a source failed.
//
// Which makes this a short inventory whatever the report on the screen looks
// like, so it is the exit status as well as a line in the report. A run that
// exited zero with the certificate half missing is a run somebody scripts, and
// the script would then be taking a list of names from two sources on the days
// both answered and from one on the days they did not, with nothing in the
// status to tell the two apart (R4).
func shortInventory(inv inventory.Inventory) bool {
	return inv.Logs.Reason != "" || inv.Records.Reason != ""
}

// printNames writes one domain's inventory.
func printNames(w io.Writer, inv inventory.Inventory, live []liveness.Name) {
	fmt.Fprintf(w, "%s\n", inv.Domain)
	fmt.Fprintf(w, "  Names under this domain\n")

	if !inv.Established() {
		// Not one source answered, so there is no inventory — and an empty
		// list under the usual heading would be the most comfortable wrong
		// answer available (R4).
		for _, reason := range []string{inv.Logs.Reason, inv.Records.Reason} {
			if reason != "" {
				fmt.Fprintf(w, "    Not established: %s\n", reason)
			}
		}
		return
	}

	fmt.Fprintf(w, "    Found        %d distinct %s\n",
		inv.Distinct, plural(inv.Distinct, "name", "names"))

	// Then one line per source, always, including the one that failed.
	//
	// This is the line that keeps the count above honest. Six names from two
	// sources and six names from one that answered while the other timed out
	// are the same six names, and only these two lines tell a reader which
	// report they are holding.
	fmt.Fprintf(w, "    Certificates %s\n", saysLogs(inv))
	fmt.Fprintf(w, "    Records      %s\n", saysRecords(inv))

	if inv.Wildcards > 0 {
		fmt.Fprintf(w, "    Wildcards    %d, each covering hosts it does not name\n", inv.Wildcards)
	}
	if other := saysForeign(inv); other != "" {
		fmt.Fprintf(w, "    Other names  %s\n", other)
	}
	if inv.Truncated {
		fmt.Fprintf(w, "    Cut          more names were found than are listed\n")
	}

	printNamesNow(w, inv, live)
	printWildcards(w, inv)
	printNamesLimits(w, inv, len(live) > 0)
}

// saysLogs is what the certificate monitor established, in one line.
func saysLogs(inv inventory.Inventory) string {
	switch r := inv.Logs; {
	case !r.Asked:
		return "not read"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0 && inv.Certificates == 0:
		return "named none of them: no publicly logged certificate covers a host here"
	case r.Named == 0:
		return fmt.Sprintf("named none of them, in %d %s read",
			inv.Certificates, plural(inv.Certificates, "certificate", "certificates"))
	default:
		return fmt.Sprintf("named %d of them, across %d %s",
			r.Named, inv.Certificates, plural(inv.Certificates, "certificate", "certificates"))
	}
}

// saysRecords is what the domain's own records established, in one line.
//
// It names the record types that actually carried a name rather than the three
// that were read, because the difference is the finding: a domain whose names
// all came from its delegation publishes no mail and no sender policy, and a
// line saying "from its MX, sender policy and delegation" would have hidden
// that behind a phrase about what was asked.
func saysRecords(inv inventory.Inventory) string {
	switch r := inv.Records; {
	case !r.Asked:
		return "not read"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them: its mail, sender policy and delegation name no host under it"
	default:
		return fmt.Sprintf("named %d of them, from %s", r.Named, wordList(recordSources(inv)))
	}
}

// saysForeign is the names that were returned and are somebody else's.
//
// Counted rather than listed, and kept because it is evidence about the answer:
// a certificate covering two estates, or a sender policy naming a mail
// provider, is the ordinary case, and a reader can see that the question was
// asked and answered rather than skipped.
func saysForeign(inv inventory.Inventory) string {
	logs, records := inv.Logs.Foreign, inv.Records.Foreign
	switch {
	case logs > 0 && records > 0:
		return fmt.Sprintf("%d under other domains, not listed: %d on the same certificates, %d in the records",
			logs+records, logs, records)
	case logs > 0:
		return fmt.Sprintf("%d on the same certificates, under other domains, not listed", logs)
	case records > 0:
		return fmt.Sprintf("%d in the domain's own records, under other domains, not listed", records)
	}
	return ""
}

// recordSources are the record types that named something, in the fixed order.
func recordSources(inv inventory.Inventory) []string {
	var out []string
	for _, want := range []inventory.Source{inventory.FromMX, inventory.FromSPF, inventory.FromNS} {
		for _, n := range inv.Names {
			if hasSource(n, want) {
				out = append(out, string(want))
				break
			}
		}
	}
	return out
}

// hasSource reports whether one source named this host.
func hasSource(n inventory.Name, want inventory.Source) bool {
	for _, s := range n.Sources {
		if s == want {
			return true
		}
	}
	return false
}

// wordList joins names the way a sentence does, so a report reads as English.
func wordList(in []string) string {
	switch len(in) {
	case 0:
		return "nothing"
	case 1:
		return in[0]
	}
	return strings.Join(in[:len(in)-1], ", ") + " and " + in[len(in)-1]
}

// covered says the window the logs show one name in.
//
// The expiry is the useful end. A name whose newest certificate ran out two
// years ago is either gone or is now covered by a wildcard, and an operator
// reading an inventory of their own estate wants to find exactly those. Which
// of the two it is, this does not say: it has not asked the host anything and
// saying would be inventing the answer (R17).
//
// A name no certificate ever covered has no window at all, and says so rather
// than borrowing the phrase a log would have used.
func covered(n inventory.Name) string {
	if n.LastSeen.IsZero() {
		if hasSource(n, inventory.FromCertificate) {
			return "no dates in the log"
		}
		return "in no logged certificate"
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
// is not what any of this establishes and is not something either source can
// establish for anybody.
//
// It is also the sentence that protects whoever presents the report. A list
// handed to a security team as an estate inventory, which a port scan then adds
// to, costs the person who handed it over their credibility — and the
// difference between the methods was knowable in advance and written here.
//
// Each source speaks only for itself. A paragraph about what a certificate log
// misses, printed under a report where the monitor was never reached, would be
// describing the limits of something that did not happen.
func printNamesLimits(w io.Writer, inv inventory.Inventory, probed bool) {
	fmt.Fprintf(w, "\n  What this does not show\n")
	fmt.Fprintf(w, "    Nothing here was guessed: no name was invented and no list of names\n")
	fmt.Fprintf(w, "    was tried.\n")

	if inv.Logs.Established() {
		fmt.Fprintf(w, "    From the public logs, these names were published by whoever obtained\n")
		fmt.Fprintf(w, "    a certificate for them.\n")
		fmt.Fprintf(w, "    A host with no publicly trusted certificate never appears — plain\n")
		fmt.Fprintf(w, "    HTTP, a service that is not HTTPS, or anything behind a private\n")
		fmt.Fprintf(w, "    authority leaves no trace in a public log.\n")
	}

	if inv.Records.Established() {
		fmt.Fprintf(w, "    From the domain's own records, these are the hosts its mail, its\n")
		fmt.Fprintf(w, "    sender policy and its delegation have to name. A host that takes no\n")
		fmt.Fprintf(w, "    mail, sends none and answers for no zone is in none of them.\n")
	}

	if inv.Wildcards > 0 {
		fmt.Fprintf(w, "    A wildcard covers hosts without naming them, and %d of the names\n"+
			"    above %s.\n", inv.Wildcards, plural(inv.Wildcards, "is a wildcard", "are wildcards"))
	}

	if probed {
		// What was sent, said plainly, because the paragraph above this one
		// used to say that nothing was asked of the domain at all — which
		// stopped being true the day each name started being resolved and
		// connected to.
		fmt.Fprintf(w, "    What each name is doing now was established by resolving it and\n")
		fmt.Fprintf(w, "    opening a connection to each address it gave. Nothing was sent over\n")
		fmt.Fprintf(w, "    that connection and no request was made.\n")
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

// printNamesNow draws what each name is doing and what named it, which are the
// two columns an operator reads before the name itself.
//
// Status first, because the question is "what do I have to deal with" rather
// than "what is this name called": a reader runs an eye down the left edge and
// stops at the ones that are not "live". The source next, because it decides
// what the status means. A name that does not resolve and came from a
// certificate is a host somebody once got a certificate for; the same name from
// a sender policy is mail this domain is still telling the world to expect.
func printNamesNow(w io.Writer, inv inventory.Inventory, live []liveness.Name) {
	if len(live) == 0 {
		// Nothing established what they are doing, so the names are still
		// drawn and the heading says which question went unanswered. Dropping
		// them would lose the half of the report that was established, to
		// report the half that was not (R4).
		printNamesFound(w, inv)
		return
	}

	fmt.Fprintf(w, "\n  What each name is doing now, and what named it\n")

	known := map[string]inventory.Name{}
	for _, n := range inv.Names {
		known[n.Name] = n
	}

	nameWidth, sourceWidth := 0, 0
	for _, n := range live {
		if len(n.Name) > nameWidth {
			nameWidth = len(n.Name)
		}
		if width := len(namedBy(known[n.Name])); width > sourceWidth {
			sourceWidth = width
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
	for _, n := range live {
		line := says(n)
		if when := lastCovered(known[n.Name]); when != "" {
			line += "; " + when
		}
		fmt.Fprintf(w, "    %-9s %-*s %-*s %s\n",
			n.Status, nameWidth, n.Name, sourceWidth, namedBy(known[n.Name]), line)
	}
}

// namedBy is the provenance column: everything that named one host.
//
// All of them rather than the first. A name in a certificate and in the
// domain's own records is the well-kept case and reads as one; a name in a
// certificate alone, with nothing in the zone pointing at it, is the one worth
// a reader's time.
func namedBy(n inventory.Name) string {
	var out []string
	for _, s := range n.Sources {
		out = append(out, string(s))
	}
	return strings.Join(out, ", ")
}

// lastCovered says when the register last had this name, in the fewest words
// that stay true.
//
// The expiry rather than the issue date: what an operator is looking for is a
// name nobody has renewed, and the issue date of a certificate that ran out
// three years ago says the same thing less directly. Where no log carried a
// date this says nothing rather than guessing at one — and a name only the
// domain's records carried has no log date to say anything about.
func lastCovered(n inventory.Name) string {
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
// behind it, which the paragraph below says. No source column either: nothing
// but a certificate names a wildcard.
func printWildcards(w io.Writer, inv inventory.Inventory) {
	var wildcards []inventory.Name
	for _, n := range inv.Names {
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

// printNamesFound draws the names with no status beside them.
//
// What a report looks like when the registers were read and nothing asked what
// the names are doing: the list, what named each one, the window it was covered
// in, and a heading that says so. It is the older half of this report and it is
// kept, because a reader who cannot reach a resolver should still get the
// names.
func printNamesFound(w io.Writer, inv inventory.Inventory) {
	var named []inventory.Name
	for _, n := range inv.Names {
		if !n.Wildcard {
			named = append(named, n)
		}
	}
	if len(named) == 0 {
		return
	}

	nameWidth, sourceWidth := 0, 0
	for _, n := range named {
		if len(n.Name) > nameWidth {
			nameWidth = len(n.Name)
		}
		if width := len(namedBy(n)); width > sourceWidth {
			sourceWidth = width
		}
	}

	fmt.Fprintf(w, "\n  Names found, none of them asked what it is doing now\n")
	for _, n := range named {
		fmt.Fprintf(w, "    %-*s %-*s %s\n", nameWidth, n.Name, sourceWidth, namedBy(n), covered(n))
	}
}
