package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/denyfirst/porch/internal/budget"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/knownnames"
	"github.com/denyfirst/porch/internal/liveness"
	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/nsecnames"
	"github.com/denyfirst/porch/internal/passivedns"
	"github.com/denyfirst/porch/internal/ptrnames"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
	"github.com/denyfirst/porch/internal/zonenames"
)

// The inventory endpoint: which names under a domain appear in publicly logged
// certificates.
//
// # Why this one is refused where the checks are not
//
// On an installation with a scope, this and every check ask for the same
// proof, and there is nothing to add. The difference is on a copy without one.
// A check there measures how one host answers, which the host can see
// happening; this produces a list of somebody's names — the shape of an estate
// rather than the state of one host — and nobody on the other end sees it
// happen, because nothing is asked of them. A copy that answered it for
// whoever could reach it would be an anonymous reconnaissance endpoint, and the
// fact that the data is public does not change what it would be doing:
// assembling it, on request, for people who will not say who they are.
//
// So where there is no scope it is answered only by a copy nobody else can
// reach, and refused everywhere else. "Nobody has proven anything" must not
// mean "everybody may ask".
//
// # And on the demonstration, only this project's own estate
//
// That deployment refused this entirely until 2026-09-27, on the ground that it
// promises it queries no transparency log. The promise was written when the
// demonstration scanned whatever it was given, and then it protected somebody:
// a visitor's domain would have been named to a monitor. It protects nobody
// now. The hosts a demonstration build may touch are compiled in (N6), so a
// visitor cannot name a domain, and the only thing a monitor can learn from it
// is that somebody is looking at *this project's* domain — which is this
// project's own information to give.
//
// What the refusal cost was the demonstration itself. A visitor could not see
// the one mode that reads several sources and says which named what, so the
// strongest thing the tool does was a claim in a repository rather than
// something on the screen. A demonstration that shows less than the product is
// a demonstration that misrepresents it downwards.
//
// So it runs here, for the hosts this project owns and nothing else, and the
// privacy page says exactly that rather than the older, shorter sentence. The
// answer is kept for an interval and handed to everyone, so a visit causes no
// request at all — see keptInventories.
func (s *Server) handleNames(w http.ResponseWriter, r *http.Request) {
	t, ok := s.admit(w, r, parseNamesTarget, s.proofs, s.limits.MaxInventoryBytes,
		"Too many inventories from this address. Try again shortly.")
	if !ok {
		return
	}

	// The compiled-in boundary is the whole of what makes this safe to offer
	// on a demonstration, and it has already been applied: admit refuses a
	// host outside the list, in the same words and with the same counter as
	// every other endpoint here. A second copy of that check would be a second
	// thing to keep in step with the first.

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.RequestTimeout)
	defer cancel()

	// What decides this is whether anybody else can reach this installation,
	// not whether verification happens to be configured.
	//
	// The first version asked the second question and refused wherever the
	// answer was no, which put the same operator in two places at once: the
	// command line produced an inventory of their own estate immediately, and
	// a copy of porchd on the same laptop, reachable by nobody, refused until
	// they published a DNS record to prove to themselves that they owned their
	// own domain. That is friction bought with no safety, and friction bought
	// with no safety is how a rule gets turned off entirely.
	//
	// So a service nobody else can reach was the command line with a browser in
	// front of it, and the command line did not ask for proof (A30, N12). Since
	// 2026-09-29 both do: porchd does not start without a scope, and the
	// command line proves every target before it checks one, so the last case
	// below is reached only by a Server built with no Verify — a test, or a
	// program that embeds this package — and it still refuses a stranger.
	// A service anybody else can reach is the case the rule is for: what this
	// produces is the shape of an estate, the scanned party cannot see it
	// happen, and answering it for strangers would make this an anonymous
	// reconnaissance endpoint with the project's name on it.
	scope := s.scanner.Verify
	switch {
	case demo.Enabled:
		// A boundary compiled into the binary is a stronger answer to the same
		// question than proof of control is, and it has already been applied
		// above: the target is a host this project owns, whoever asked. Asking
		// a visitor to prove control of our domain would be asking them to
		// prove something that is not theirs and is not in question.

	case scope != nil:
		// Verification configured is an operator opting into enforcement, and
		// it is then enforced wherever the service listens — exactly as it is
		// for every check.
		switch _, err := scope.CoversSigned(ctx, t.host, verify.AnyPort); {
		case err == nil:
		case errors.Is(err, verify.ErrNotVerified):
			s.refuse(w, http.StatusForbidden, "proof_required",
				"Publish the proof record for this domain first. An inventory is only "+
					"produced for domains this installation has been shown control of.")
			return
		default:
			// The lookup failed, which is not the domain being unverified.
			// Telling somebody to publish a record they have already published
			// would send them to the wrong place.
			s.refuse(w, http.StatusBadGateway, "scan_failed",
				"The proof record could not be looked up. Try again shortly.")
			return
		}

	case s.exposed:
		s.refuse(w, http.StatusForbidden, "proof_required",
			"An inventory of a domain's names is only produced for domains this "+
				"installation has been shown control of, and this installation has no "+
				"verification configured. Add -verification-secret-file, or reach it "+
				"from the machine it runs on.")
		return
	}

	// Only now, after proof. Whether this installation has a monitor is a fact
	// about the installation, and telling somebody who has not proven anything
	// is answering a question they were not entitled to ask.
	//
	// Refused rather than answered with an empty inventory, which would report
	// an estate as publishing nothing (R4).
	if s.names == nil {
		s.refuse(w, http.StatusNotFound, "not_offered",
			"This installation was not started with a certificate transparency monitor.")
		return
	}
	// A slot of its own. One inventory is several requests to a monitor, and a
	// queue of them must not hold the slots a scan needs.
	if err := s.proofSem.acquire(ctx); err != nil {
		w.Header().Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable, "too_busy",
			"Too many inventories are in flight. Try again shortly.")
		return
	}
	defer s.proofSem.release()

	// Produced here, or handed over from the last time somebody asked.
	//
	// Where a copy is kept — a deployment that demonstrates the tool on one
	// estate, where every visitor asks the same question — this whole closure
	// runs at most once an interval and everybody else is served what it
	// made. Where none is kept, which is every installation an operator runs
	// for themselves, it runs for each caller as it always did.
	// The address ranges the caller says are theirs, where the caller is the
	// person who runs this installation.
	//
	// This is the one capability proof of control cannot grant. A domain is
	// proven with a record in its zone; an address range cannot be proven by
	// anything this project can check, so a service that walked one for
	// whoever asked would be a reverse-scanner for whoever asked. Where
	// nobody else can reach the installation, or a password the operator set
	// stands in front of it, the caller is the operator — which is the same
	// reasoning that decided proof for the inventory itself (A30, N12), and
	// refusing them here would be friction bought with no safety.
	//
	// Bounded before anything is asked, by the same reader the command line
	// uses: nothing wider than /20, four thousand addresses across all of
	// them, and refused rather than cut short.
	var walk []netip.Prefix
	if len(t.ranges) > 0 {
		if !s.operatorOnly() {
			s.refuse(w, http.StatusForbidden, "not_your_range",
				"An address range cannot be proven the way a domain can, so this "+
					"installation reads one only for whoever runs it. Reach it from the "+
					"machine it runs on, or put a password in front of it.")
			return
		}
		if s.reverse == nil {
			s.refuse(w, http.StatusNotFound, "not_offered",
				"This installation has no resolver, so it cannot read a reverse record.")
			return
		}

		var err error
		if walk, err = parseRanges(t.ranges); err != nil {
			s.refuse(w, http.StatusBadRequest, "invalid_range", err.Error())
			return
		}
	}

	// The names the caller says they already have.
	//
	// No gate of its own, unlike a range. A range cannot be proven and this
	// can: every name in the list is held to the domain the caller has already
	// been shown to control, so a list is a statement about an estate they own
	// and the worst it can cause is this installation resolving their own
	// hosts. Bounded and cleaned by the same package the command line uses,
	// before one of them is looked up.
	//
	// Refused rather than silently dropped where nothing here could report it,
	// because a field accepted and ignored is a caller believing something
	// happened.
	if len(t.names) > knownnames.MaxNames {
		s.refuse(w, http.StatusBadRequest, "list_too_long",
			"A list may name up to "+strconv.Itoa(knownnames.MaxNames)+" hosts. A longer one "+
				"is a wordlist rather than an estate, and this mode does not try wordlists.")
		return
	}

	// A kept copy is for the question everybody asks. Ranges and a list of
	// somebody's own names both make it somebody else's question, so it is
	// produced for them and kept for nobody.
	produce := func() inventory.Inventory { return s.inventory(ctx, t.host, walk, t.names) }

	var found inventory.Inventory
	if len(walk) > 0 || len(t.names) > 0 {
		found = produce()
	} else {
		found = s.kept.serve(t.host, produce)
	}

	if !found.Established() && ctx.Err() != nil {
		s.refuse(w, http.StatusGatewayTimeout, "timeout",
			"The inventory did not finish within the time allowed.")
		return
	}

	writeJSON(w, http.StatusOK, found)
}

// inventory reads every source this installation has and merges them.
//
// Split out of the handler because it is also what a kept copy is made from,
// and because the handler above it is a list of refusals: what is produced and
// what is allowed are two different subjects and were one function.
func (s *Server) inventory(ctx context.Context, domain string, walk []netip.Prefix, given []string) inventory.Inventory {
	// Two registers and the domain's own records.
	//
	// The records cost three lookups to the resolver this installation already
	// asks about every other target, and disclose nothing to anybody the
	// monitor has not already been told. What they add is part of the half of
	// an estate a certificate log cannot see — a host on plain HTTP, one
	// behind a private authority, and anything hidden by a wildcard, where the
	// domain's own mail, sender policy or delegation names it.
	//
	// Where this installation has no resolver, the records are not read and
	// the inventory says so rather than reporting an estate that publishes
	// nothing (R4).
	//
	// The records first, and each third party with half of what is left. Until
	// 2026-10-05 the monitor came first with the request's whole deadline, so
	// one that never answered took all of it: the records were then asked with
	// no time left, the probe and the certificates had no names to start from,
	// and the demonstration's inventory came back empty (audit F12). Three
	// lookups to this installation's own resolver cost a fraction of a second
	// and cannot be starved now; the monitor and the register are somebody
	// else's service, and the estate's own hosts keep the other half.
	var records dnsnames.Found
	if s.records != nil {
		records = s.records.Under(ctx, domain)
	}

	var estate ctsearch.Estate
	if s.names != nil {
		asked, cancel := budget.Half(ctx)
		estate = s.names.SearchEstate(asked, domain)
		cancel()
	}

	// The register, where an operator configured one. It is the only source
	// that sees behind a wildcard certificate, and the only one whose names
	// were observed rather than published — which is why the report keeps them
	// apart rather than adding them to a total.
	var observed passivedns.Found
	if s.passive != nil {
		asked, cancel := budget.Half(ctx)
		observed = s.passive.Under(asked, domain)
		cancel()
	}

	// The zone itself, where this installation was told to ask for one. The
	// only source that is complete when it works — and it runs here only for a
	// domain this installation has been shown control of, which every source
	// above it has already been held to.
	var handed zonenames.Found
	if s.zone != nil {
		handed = s.zone.Under(ctx, domain)
	}

	// And the zone's own absence proofs, where this installation was told to
	// follow them. The other way a zone lists itself, on the zones a transfer
	// is refused by — behind the same proof of control, for the same reason.
	var walked nsecnames.Found
	if s.absence != nil {
		walked = s.absence.Under(ctx, domain)
	}

	// And the addresses, where the caller named a range. Nothing is sent to
	// them: the questions are reverse lookups to this installation's own
	// resolver, and a name that comes back is one somebody published for that
	// address.
	var answered ptrnames.Found
	if s.reverse != nil && len(walk) > 0 {
		answered = s.reverse.Under(ctx, domain, walk)
	}

	// And the list the caller already had, which no source can produce for
	// them. It is held to the domain they proved, so the worst it can name is
	// their own estate.
	var already knownnames.Found
	if len(given) > 0 {
		already = knownnames.From(domain, given)
	}

	sources := inventory.Sources{
		Logs:    estate,
		Records: records,
		Passive: observed,
		Reverse: answered,
		Zone:    handed,
		NSEC:    walked,
		Known:   already,
	}
	found := inventory.Merge(domain, sources)

	// And what each name is doing now, which no register can answer. Every
	// source of names is a record of the past, and an operator reading their
	// own estate is asking about the present: a name from five years ago, for
	// a service shut down four years ago, is noise in a list somebody has to
	// act on.
	//
	// Nothing here refuses when the time runs out. The probe runs until the
	// request's budget is spent and the names it did not reach come back
	// unchecked, saying so beside themselves. Throwing the answer away at that
	// point would lose an inventory that was established, to report the part
	// that was not (R4).
	if s.live == nil {
		return found
	}
	live := s.live.Check(ctx, found.Hosts())

	// Then, where the operator asked for it, the estate itself: the
	// certificate each answering host presents, and the names written in it.
	//
	// After the probe rather than beside it, because it needs somewhere to
	// knock — the hosts worth asking are the ones something has just
	// established are answering. What it finds is merged back in and asked
	// what it is doing like any other name, so the newest half of the
	// inventory is not the half with nothing beside it (R4).
	if s.presented != nil {
		sources.Presented = s.presented.Under(ctx, domain, withDomain(live, domain))

		found = inventory.Merge(domain, sources)
		live = append(live, s.live.Check(ctx, found.Unasked(live))...)
	}

	return found.WithLiveness(live)
}

// withDomain is the hosts whose certificates are read: the ones that answered,
// and the domain itself where nothing has asked it yet.
//
// The domain is the one name known to belong to the estate before any source
// has spoken, and its certificate is where its other names most often are.
// Reading only the hosts other sources had named made this source silent
// exactly when it was the only one left: on 2026-10-09 the monitor did not
// answer, the records named only a mail provider's hosts, and the
// demonstration's inventory of denyfirst.dev came back empty — while the
// certificate denyfirst.dev presents names porch.denyfirst.dev and
// mta-sts.denyfirst.dev.
//
// Where the domain was named and probed already, the probe's answer stands: it
// is read if it answered and not knocked on again if it did not.
func withDomain(live []liveness.Name, domain string) []string {
	hosts := liveness.Answering(live)
	for _, n := range live {
		if n.Name == domain {
			return hosts
		}
	}
	return append([]string{domain}, hosts...)
}

// parseNamesTarget takes a bare domain.
//
// A port or a path means somebody is asking a question this endpoint does not
// answer, and answering the nearest one instead is how a report comes to be
// about something other than what was asked. A mail address has its local part
// dropped first, as everywhere else, so that pasting one here discloses no more
// than pasting it into a check.
func parseNamesTarget(raw string) (target, *refusal) {
	raw, _ = mailscan.DropLocalPart(raw)

	host, port, _, err := scan.SplitTargetPort(raw)
	if err != nil {
		return target{}, &refusal{
			status:  http.StatusBadRequest,
			code:    "invalid_target",
			message: "That is not a domain name. Give a name such as example.com.",
		}
	}
	if port != "" && port != "443" {
		return target{}, &refusal{
			status:  http.StatusBadRequest,
			code:    "invalid_target",
			message: "An inventory is of a domain rather than of a port. Give a name such as example.com.",
		}
	}

	// An address is not a domain, and every other endpoint here says so in the
	// same words. This one did not: an address went on to the proof walk, which
	// asked a resolver about _porch-challenge under the address's last octets,
	// and — on a copy nobody else can reach — to the monitor, named as though
	// it were a domain. Refused here, where the other parsers refuse it.
	if refused := refuseAnAddress(host); refused != nil {
		return target{}, refused
	}
	return target{host: strings.ToLower(host), scope: scan.DefaultPort}, nil
}

// parseRanges reads the address ranges a caller sent and bounds them before
// anything is asked.
//
// The refusal names the rule and never the range: a message that echoed back
// what was typed would put a caller's input into a log somewhere downstream
// (I6). The bounds themselves belong to internal/ptrnames, so the service and
// the command line refuse the same range for the same reason rather than
// drifting into two answers.
func parseRanges(raw []string) ([]netip.Prefix, error) {
	if len(raw) > maxRangesPerRequest {
		return nil, errors.New("that is more address ranges than this reads in one request")
	}

	var out []netip.Prefix
	for _, r := range raw {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil {
			return nil, errors.New("an address range looks like 203.0.113.0/24")
		}
		out = append(out, prefix)
	}

	if _, err := ptrnames.Addresses(out); err != nil {
		return nil, err
	}
	return out, nil
}

// maxRangesPerRequest bounds the list itself, before the addresses in it are
// counted. A thousand /32s is four thousand addresses and a thousand parses,
// and the second bound is the cheaper one to hit first.
const maxRangesPerRequest = 32
