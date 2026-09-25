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
func runNames(ctx context.Context, domains []string, timeout time.Duration, monitor, monitorURL string, asJSON bool) int {
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

	worst := 0
	for i, domain := range domains {
		found := searcher.SearchEstate(ctx, domain)

		if asJSON {
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

		if found.Reason != "" {
			worst = 2
		}
	}
	return worst
}

// printNames writes one estate's inventory.
func printNames(w io.Writer, e ctsearch.Estate) {
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

	if len(e.Names) > 0 {
		fmt.Fprintf(w, "\n")
	}
	for _, n := range e.Names {
		fmt.Fprintf(w, "    %-44s %s\n", n.Name, covered(n))
	}

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
			"    above %s one.\n", e.Wildcards, plural(e.Wildcards, "is", "are"))
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
