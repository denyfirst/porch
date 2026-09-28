package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/certnames"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/knownnames"
	"github.com/denyfirst/porch/internal/liveness"
	"github.com/denyfirst/porch/internal/nsecnames"
	"github.com/denyfirst/porch/internal/passivedns"
	"github.com/denyfirst/porch/internal/ptrnames"
	"github.com/denyfirst/porch/internal/zonenames"
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
// namesOptions is what the inventory mode was asked for.
//
// A struct rather than eleven parameters. The list has grown with every source
// and a positional call that long is one every reader has to count the commas
// in — and one a test in another build file gets wrong silently, which has
// happened twice.
type namesOptions struct {
	// Timeout bounds each question this mode asks.
	Timeout time.Duration

	// Monitor and MonitorURL choose the certificate transparency monitor.
	Monitor, MonitorURL string

	// Resolver is the resolver every lookup goes to. Which one answers
	// decides what the whole report means.
	Resolver string

	// Register and RegisterURL choose the passive register, where one is
	// wanted. Empty asks none.
	Register, RegisterURL string

	// Ranges are the address ranges the operator says are theirs, walked for
	// the names their reverse records answer to. Empty walks none.
	Ranges []netip.Prefix

	// ReadZone asks the domain's own name servers to hand over the zone.
	//
	// Off unless the operator says so, and the flag is the saying: the check
	// that asks whether a zone transfers to anybody deliberately reads none of
	// it, because a zone belongs to whoever runs it. Reading one is for an
	// estate that is the reader's.
	ReadZone bool

	// WalkZoneProofs follows the zone's own absence proofs to list it.
	//
	// Off unless the operator says so, and the flag is the saying, for the
	// reason ReadZone is: a signed zone that has not moved to NSEC3 hands its
	// names to anybody who follows them, and reading somebody else's that way
	// is enumeration however public each record is. It is for an estate that
	// is the reader's.
	WalkZoneProofs bool

	// ReadCertificates asks each live host for the certificate it presents.
	// Off unless the operator says so: it is the one part of this mode that
	// opens a connection to the estate on purpose.
	ReadCertificates bool

	// Known are names the operator already has, taken as given.
	//
	// The one source that asks nothing and the answer to what none of the
	// others can do: DNS lists nothing, so a host with no public certificate,
	// under a zone that refuses to transfer and is not signed, exists for a
	// reader only because whoever runs it says it does. Bounded, because a
	// list of an estate and a dictionary being tried against a resolver are
	// different instruments (N7).
	Known []string

	// JSON writes the inventory as it stands rather than as a report.
	JSON bool
}

func runNames(ctx context.Context, domains []string, opt namesOptions) int {
	if demo.Enabled {
		fmt.Fprintln(os.Stderr, "this is a demonstration build, and it asks no certificate "+
			"transparency monitor anything")
		return 2
	}

	timeout := opt.Timeout

	searcher, err := monitorNamed(opt.Monitor, opt.MonitorURL, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// The third source, and the only one that sees behind a wildcard. Off
	// unless an operator names one: it wants their own key, the question names
	// their domain to a company they chose, and nothing here picks one for
	// them.
	passive, err := registerNamed(opt.Register, opt.RegisterURL, timeout)
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
	client := &dnsclient.Client{Server: opt.Resolver, Timeout: timeout}
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
		sources := inventory.Sources{
			Logs:    searcher.SearchEstate(ctx, domain),
			Records: records.Under(ctx, domain),
		}
		// The zone itself, where the operator said it is theirs. The only
		// source that is complete when it works, and the one that usually
		// refuses — a zone is handed to the secondaries its operator named.
		if opt.ReadZone {
			zone := &zonenames.Reader{Resolver: client, Timeout: timeout}
			sources.Zone = zone.Under(ctx, domain)
		}

		// And the zone's own absence proofs, where the operator said the zone
		// is theirs. Where a transfer is refused — which is nearly always —
		// this is the other way a zone lists itself, and it works on exactly
		// the zones a transfer does not: signed ones that have not moved to
		// NSEC3. Neither replaces the other and the report says which
		// answered.
		if opt.WalkZoneProofs {
			proofs := &nsecnames.Reader{Resolver: client, Timeout: timeout}
			sources.NSEC = proofs.Under(ctx, domain)
		}

		// The estate from its other half: an address the operator says is
		// theirs, and the name its reverse record answers to. Nothing is sent
		// to the address itself.
		//
		// Called whether or not any range was named, because the reader is
		// where "no range" is answered: it reports that nothing was asked,
		// which is what the report has to say. A condition here as well would
		// be a second place for the two to disagree.
		addresses := &ptrnames.Reader{Resolver: client, Timeout: timeout}
		sources.Reverse = addresses.Under(ctx, domain, opt.Ranges)

		// And the names the operator handed over, which is the only way a host
		// nothing published can be in this report at all. Taken as given and
		// then treated like any other name: resolved, asked what it is doing,
		// and labelled with where it came from — so the row that matters,
		// a host they listed and nothing else named, is readable at a glance.
		if len(opt.Known) > 0 {
			sources.Known = knownnames.From(domain, opt.Known)
		}
		if passive != nil {
			sources.Passive = passive.Under(ctx, domain)
		}
		found := inventory.Merge(domain, sources)

		// And what each of them is doing now, which a list of names cannot
		// answer. Every source of names is a record of the past; an operator
		// is asking about the present. The answers go beside the names rather
		// than in a list of their own, so that a name nothing reached is still
		// a name in the report.
		live := checker.Check(ctx, found.Hosts())

		// Then, where it was asked for, the estate itself: the certificate
		// each answering host presents, and the names written in it.
		//
		// It runs after the registers rather than beside them because it needs
		// somewhere to knock: the hosts to ask are the ones something has just
		// established are answering. What it finds is then merged back in, and
		// a name that arrives this way is asked what it is doing like any
		// other — otherwise the newest half of the inventory would be the half
		// with no state beside it.
		if hosts := certificatesFrom(opt); hosts != nil {
			sources.Presented = hosts.Under(ctx, domain, liveness.Answering(live))

			found = inventory.Merge(domain, sources)
			live = append(live, checker.Check(ctx, found.Unasked(live))...)
		}

		found = found.WithLiveness(live)

		if opt.JSON {
			if err := json.NewEncoder(os.Stdout).Encode(found); err != nil {
				fmt.Fprintln(os.Stderr, "the inventory could not be written")
				return 2
			}
		} else {
			if i > 0 {
				fmt.Fprintln(os.Stdout)
			}
			printNames(os.Stdout, found)
		}

		if shortInventory(found) {
			worst = 2
		}
	}
	return worst
}

// certificatesFrom builds the reader that asks each answering host for its
// certificate, or nil where the operator did not ask for it.
//
// Nil rather than a reader nobody uses, and a function rather than a condition
// inside the loop, because this is the one source that opens a connection to
// the estate: whether it runs at all is a decision worth being able to look at
// on its own, and worth a test of its own.
func certificatesFrom(opt namesOptions) *certnames.Reader {
	if !opt.ReadCertificates {
		return nil
	}
	return &certnames.Reader{Timeout: opt.Timeout}
}

// shortInventory reports that a source failed.
//
// Which makes this a short inventory whatever the report on the screen looks
// like, so it is the exit status as well as a line in the report. A run that
// exited zero with the certificate half missing is a run somebody scripts, and
// the script would then be taking a list of names from two sources on the days
// both answered and from one on the days they did not, with nothing in the
// status to tell the two apart (R4).
//
// Every source, not the two this mode was born with. It read the logs and the
// records while six sources could fail, so a run whose zone transfer or whose
// reverse walk failed exited zero — the exact case this was written to catch,
// missed because the list of sources lived here as well as in the report. It
// is asked of the inventory now, which is the only thing that knows how many
// there are.
func shortInventory(inv inventory.Inventory) bool {
	return len(inv.Failures()) > 0
}

// printNames writes one domain's inventory.
func printNames(w io.Writer, inv inventory.Inventory) {
	fmt.Fprintf(w, "%s\n", inv.Domain)
	fmt.Fprintf(w, "  Names under this domain\n")

	if !inv.Established() {
		// Not one source answered, so there is no inventory — and an empty
		// list under the usual heading would be the most comfortable wrong
		// answer available (R4).
		for _, reason := range inv.Failures() {
			fmt.Fprintf(w, "    Not established: %s\n", reason)
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
	fmt.Fprintf(w, "    The zone     %s\n", saysZone(inv))
	fmt.Fprintf(w, "    Its proofs   %s\n", saysNsec(inv))
	fmt.Fprintf(w, "    Certificates %s\n", saysLogs(inv))
	fmt.Fprintf(w, "    Records      %s\n", saysRecords(inv))
	fmt.Fprintf(w, "    Passive DNS  %s\n", saysPassive(inv))
	fmt.Fprintf(w, "    The hosts    %s\n", saysPresented(inv))
	fmt.Fprintf(w, "    Reverse DNS  %s\n", saysReverse(inv))
	fmt.Fprintf(w, "    Your list    %s\n", saysKnown(inv))

	if inv.Wildcards > 0 {
		fmt.Fprintf(w, "    Wildcards    %d, each covering hosts it does not name\n", inv.Wildcards)
	}
	if other := saysForeign(inv); other != "" {
		fmt.Fprintf(w, "    Other names  %s\n", other)
	}
	if inv.Truncated {
		fmt.Fprintf(w, "    Cut          more names were found than are listed\n")
	}

	printNamesNow(w, inv)
	printWildcards(w, inv)
	printNamesLimits(w, inv, inv.Probed)
}

// saysKnown is what the operator's own list contributed, in one line.
//
// It carries the number nobody else can give them: how many of the names they
// handed over nothing else found. That is the whole reason to hand a list
// over — a host in it that no log, register, zone or record named is a host
// the outside cannot see, and it is the row somebody reading their own estate
// came here for.
func saysKnown(inv inventory.Inventory) string {
	switch r := inv.Known; {
	case !r.Asked:
		return "not given: -names or -names-file was not used"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them"
	default:
		line := fmt.Sprintf("%d given", r.Named)
		if alone := onlyGiven(inv); alone > 0 {
			line += fmt.Sprintf(", %d of them named by nothing else", alone)
		} else {
			line += ", every one of them named by something else as well"
		}
		return line
	}
}

// onlyGiven counts the hosts nothing but the list itself carried.
func onlyGiven(inv inventory.Inventory) int {
	alone := 0
	for _, n := range inv.Names {
		if len(n.Sources) == 1 && n.Sources[0] == inventory.FromOperator {
			alone++
		}
	}
	return alone
}

// saysNsec is what the zone's own absence proofs listed, in one line.
//
// The reason it usually says nothing is the reason it exists: a zone using
// NSEC3, or not signed at all, has no plain chain to follow — and that is a
// fact about the zone's own configuration rather than a failure of this walk.
func saysNsec(inv inventory.Inventory) string {
	switch r := inv.NSEC; {
	case !r.Asked:
		return "not walked: -walk-proofs was not given"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them"
	default:
		return fmt.Sprintf("named %d of them, out of the zone's own absence proofs", r.Named)
	}
}

// saysZone is what the zone handed over, in one line.
//
// The refusal is a first-class answer here rather than a failure: a zone is
// handed to the secondaries its operator named and to nobody else, and a
// reader seeing "every server refused" is reading their own DNS working as it
// should.
func saysZone(inv inventory.Inventory) string {
	switch r := inv.Zone; {
	case !r.Asked:
		return "not asked: -read-zone was not given"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them: every server refused the transfer, which is the ordinary answer"
	default:
		return fmt.Sprintf("named %d of them, handed over by the zone itself", r.Named)
	}
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

// saysPassive is what a passive register observed, in one line.
//
// "Not read" where none was configured, because that is the ordinary state and
// a reader has to be able to tell it from a register that answered with
// nothing. This is the source that sees behind a wildcard, so an estate
// covered by one and a report with this line reading "not read" is a reader
// being told exactly how much they are not seeing.
func saysPassive(inv inventory.Inventory) string {
	switch r := inv.Passive; {
	case !r.Asked:
		return "not read: no register was named"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them: the register has observed no host under this domain"
	default:
		return fmt.Sprintf("named %d of them, observed by the register", r.Named)
	}
}

// saysPresented is what the hosts themselves said, in one line.
//
// It carries how many were asked and how many answered, because the difference
// is the measure of how much this could not see: an estate where two hosts in
// twenty presented a certificate has eighteen nobody here read.
func saysPresented(inv inventory.Inventory) string {
	switch r := inv.Presented; {
	case !r.Asked:
		return "not asked: -read-certificates was not given"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them"
	default:
		return fmt.Sprintf("named %d of them, off the certificates they presented", r.Named)
	}
}

// saysReverse is what the addresses in the named ranges answered to.
//
// It carries the addresses asked and the ones that answered, because the
// difference is the shape of the range: a /24 with four answers is four
// machines and two hundred and fifty-two addresses nobody has named.
func saysReverse(inv inventory.Inventory) string {
	switch r := inv.Reverse; {
	case !r.Asked:
		return "not walked: no address range was named"
	case r.Reason != "":
		return "Not established: " + r.Reason
	case r.Named == 0:
		return "named none of them"
	default:
		return fmt.Sprintf("named %d of them, off the reverse records in the ranges named", r.Named)
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

	if inv.Zone.Established() && inv.Zone.Named > 0 {
		fmt.Fprintf(w, "    The zone handed itself over, so the names above are every name in\n")
		fmt.Fprintf(w, "    it rather than a sample. What is not in a zone is still not here: a\n")
		fmt.Fprintf(w, "    host reached by address alone, and anything in a zone delegated away\n")
		fmt.Fprintf(w, "    from this one.\n")
	}

	if inv.Reverse.Established() {
		fmt.Fprintf(w, "    The addresses in the ranges named were asked what they answer to,\n")
		fmt.Fprintf(w, "    and nothing was sent to any of them. A range this program was not\n")
		fmt.Fprintf(w, "    given is a range nothing looked at, and an address with no reverse\n")
		fmt.Fprintf(w, "    record is a machine this cannot name.\n")
	}

	if inv.Presented.Established() {
		fmt.Fprintf(w, "    The hosts that answered were asked for their certificates, which is\n")
		fmt.Fprintf(w, "    how a name a private authority issued is found: no public log holds\n")
		fmt.Fprintf(w, "    one. A handshake was made and closed, nothing was requested over it,\n")
		fmt.Fprintf(w, "    and the certificates were read rather than judged.\n")
	}

	if inv.Passive.Established() {
		fmt.Fprintf(w, "    A passive register holds what somebody's resolver saw, not what this\n")
		fmt.Fprintf(w, "    domain published. A name in it may never have existed — a typo, or a\n")
		fmt.Fprintf(w, "    name that resolved for an hour years ago — and a host nobody outside\n")
		fmt.Fprintf(w, "    ever looked up is not in it at all.\n")
	}

	if inv.Wildcards > 0 {
		fmt.Fprintf(w, "    A wildcard covers hosts without naming them, and %d of the names\n"+
			"    above %s.\n", inv.Wildcards, plural(inv.Wildcards, "is a wildcard", "are wildcards"))
		if !inv.Passive.Established() {
			// The one source that sees behind one, and it was not read. A
			// reader who is told a wildcard hides hosts, and not told that
			// nothing looked for them, has been given half the sentence.
			fmt.Fprintf(w, "    Nothing here looked behind them: a passive register is the source\n")
			fmt.Fprintf(w, "    that can, and none was named.\n")
		}
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

// The passive registers this can be pointed at, spelled once.
const (
	registerSecurityTrails = "securitytrails"
	registerVirusTotal     = "virustotal"
)

// registerNamed builds the passive register to ask, or nil where none was
// named.
//
// Nil rather than an empty implementation, because "no register" is a state
// the report has to be able to say: a register that was never asked and a
// register that found nothing are the same empty list and only one of them is
// an answer (R4).
//
// The key comes from the environment and never from a flag. It identifies
// whoever is running this to the register, it is billed to them, and a
// credential on a command line is a credential in a shell history and in every
// process listing on the machine. A register named with no key in the
// environment is refused here rather than asked and rejected: naming somebody's
// domain to a company that will not answer buys nothing and discloses the same
// thing a successful search would.
func registerNamed(name, address string, timeout time.Duration) (passivedns.Register, error) {
	switch name {
	case "":
		return nil, nil

	case registerSecurityTrails:
		token := os.Getenv("SECURITYTRAILS_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("-passive %s needs a key in SECURITYTRAILS_TOKEN", registerSecurityTrails)
		}
		return &passivedns.SecurityTrails{Endpoint: address, Token: token, Timeout: timeout}, nil

	case registerVirusTotal:
		token := os.Getenv("VIRUSTOTAL_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("-passive %s needs a key in VIRUSTOTAL_TOKEN", registerVirusTotal)
		}
		return &passivedns.VirusTotal{Endpoint: address, Token: token, Timeout: timeout}, nil
	}
	return nil, fmt.Errorf("unknown passive register %q: it is %s or %s",
		name, registerSecurityTrails, registerVirusTotal)
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
func printNamesNow(w io.Writer, inv inventory.Inventory) {
	if !inv.Probed {
		// Nothing established what they are doing, so the names are still
		// drawn and the heading says which question went unanswered. Dropping
		// them would lose the half of the report that was established, to
		// report the half that was not (R4).
		printNamesFound(w, inv)
		return
	}

	var hosts []inventory.Name
	for _, n := range inv.Names {
		if !n.Wildcard {
			hosts = append(hosts, n)
		}
	}
	if len(hosts) == 0 {
		return
	}

	fmt.Fprintf(w, "\n  What each name is doing now, and what named it\n")

	nameWidth, sourceWidth := 0, 0
	for _, n := range hosts {
		if len(n.Name) > nameWidth {
			nameWidth = len(n.Name)
		}
		if width := len(namedBy(n)); width > sourceWidth {
			sourceWidth = width
		}
	}

	// Every name in the inventory, and not only the ones an answer came back
	// for. A row is drawn from the name rather than from the status, because
	// the other way round is how a name leaves a report without being
	// mentioned: the check bounds how many names it will reach, and the ones
	// past that bound had no row at all.
	//
	// The window each name was covered in goes on the same line. Without it a
	// name is only ever "now", and the finding that matters most in an old
	// estate cannot be seen: a name whose newest certificate expired four
	// years ago and which is still answering on 443 is a service nobody has
	// looked at since, and the two halves of that sentence come from two
	// different places.
	for _, n := range hosts {
		status, line := liveness.Unchecked, "nothing asked what this name is doing"
		if n.Now != nil {
			status, line = n.Now.Status, says(*n.Now)
		}
		if when := lastCovered(n); when != "" {
			line += "; " + when
		}
		fmt.Fprintf(w, "    %-9s %-*s %-*s %s\n",
			status, nameWidth, n.Name, sourceWidth, namedBy(n), line)
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

// rangesNamed reads the address ranges an operator typed.
//
// Every one of them is parsed and the whole set is measured before anything is
// asked, because the refusal is the point: a range too wide to read is refused
// when the flag is read rather than after tens of thousands of questions have
// gone to somebody's resolver. Empty names none, which is the ordinary case.
// namesGiven gathers the names the operator handed over, from the flag and
// from the file, in that order.
//
// Two ways in because an estate arrives two ways. A handful of hosts somebody
// remembers is faster typed than filed; a list exported out of an inventory or
// a configuration repository is a file, and asking somebody to paste four
// hundred lines onto a command line is asking them not to bother.
//
// Neither invents a name. Both are refused here, before the run, rather than
// part way through it: a list too long for an estate is a wordlist, and
// finding that out after four hundred lookups have gone to somebody's resolver
// is finding out too late (N7).
func namesGiven(list, path string) ([]string, error) {
	var out []string

	for _, raw := range strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if raw = strings.TrimSpace(raw); raw != "" {
			out = append(out, raw)
		}
	}

	if path != "" {
		fromFile, err := knownnames.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("-names-file: %w", err)
		}
		out = append(out, fromFile...)
	}

	if len(out) > knownnames.MaxNames {
		return nil, fmt.Errorf("a list may name up to %d hosts; a longer one is a wordlist "+
			"rather than an estate, and this mode does not try wordlists", knownnames.MaxNames)
	}
	return out, nil
}

func rangesNamed(list string) ([]netip.Prefix, error) {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil, nil
	}

	var out []netip.Prefix
	for _, raw := range strings.Split(list, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			// The rule rather than what was typed (I6). A range with a typo in
			// it is a range, and echoing it back adds nothing a reader of the
			// flag does not already have.
			return nil, fmt.Errorf("-ranges takes address ranges such as 203.0.113.0/24, comma separated")
		}
		out = append(out, prefix)
	}

	if _, err := ptrnames.Addresses(out); err != nil {
		return nil, fmt.Errorf("-ranges: %w", err)
	}
	return out, nil
}
