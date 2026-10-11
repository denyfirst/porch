package policy

import (
	"fmt"
	"strings"
)

// Certificate authority authorisation, described rather than graded.
//
// A CAA record names the authorities allowed to issue for a domain. Without
// one, any publicly trusted authority may — and there are around a hundred, so
// the weakest of them sets the standard for everyone. Checking the record is
// mandatory for authorities under CA/Browser Forum rules, which makes it one
// of the few controls a domain owner can apply to authorities they have no
// relationship with.
//
// It is not graded, and the reason is where it comes from rather than what it
// says.
//
// Everything else this policy grades arrives in the handshake: a cipher suite,
// a protocol version, a certificate. CAA arrives from a resolver, over a path
// nothing here authenticates, describing a system the person who configured
// the server often does not administer. A verdict on the transport that moved
// because of a DNS record would be a verdict about somebody else's zone.
//
// So it is reported on a line of its own rather than folded into a note. That
// distinction matters more than it sounds: the notes fold shut under every
// verdict but ungraded, and for a name with no CAA this is likely the most
// useful sentence in the report — one DNS record, no risk in adding it, and a
// hundred authorities that stop being able to issue.
//
// # Prevention and detection
//
// CAA and certificate transparency answer two halves of one question: can
// somebody else obtain a certificate for this name, and would anybody find
// out. CAA acts before issuance and transparency after, and neither replaces
// the other. An authority checks CAA at the moment it issues, so a resolver
// poisoned at that moment lets the request through; and an authority that is
// itself compromised permits whatever it likes. The logs record the result
// either way.
//
// The two lines sit next to each other in the report for that reason.

// IssuanceFacts is what a resolver answered about a name.
type IssuanceFacts struct {
	// Checked is false when no lookup happened at all — no resolver
	// configured, or the scan's budget spent before it got here. Reported
	// rather than presented as an absence of records, which is a different
	// fact entirely.
	Checked bool `json:"checked"`

	// Authorities are the values of issue properties: the authorities allowed
	// to issue for this name.
	Authorities []string `json:"authorities,omitempty"`

	// Wildcards are the values of issuewild properties. Separate because they
	// govern separately: a name with issue but no issuewild allows wildcard
	// issuance by the same authorities, and one with both may allow different
	// sets.
	Wildcards []string `json:"wildcards,omitempty"`

	// Other counts properties that are neither, such as iodef or
	// contactemail. They matter for one reason: a record set containing them
	// and no issue property restricts nothing, and reporting that name as
	// having CAA would be true and useless.
	Other int `json:"otherProperties"`

	// FoundAt is the name the records were found at, which may be a parent:
	// CAA is inherited, so a policy on example.com governs www.example.com.
	// Empty when nothing was found anywhere up the tree.
	FoundAt string `json:"foundAt,omitempty"`

	// SearchedTo is the highest name the walk reached.
	SearchedTo string `json:"searchedTo,omitempty"`

	// SearchComplete is false when the walk ran out of budget before reaching
	// the top of the name, so the names above SearchedTo were never asked.
	//
	// Without it the empty answer has two readings and this package publishes
	// the wrong one: "no CAA record was found for this name or for any parent"
	// is a claim about every parent, and a walk cut short did not visit them.
	SearchComplete bool `json:"searchComplete"`

	// Validated is the AD bit from the answer the records came from.
	//
	// It is the resolver's claim that it verified the DNSSEC chain, not this
	// service's. False is ambiguous by construction: an unsigned zone and an
	// answer nobody validated are the same bit from here, and most zones are
	// unsigned.
	Validated bool `json:"validated"`

	// Exists is false when the resolver said the name itself does not exist.
	Exists bool `json:"exists"`
}

// Issuance is what a report should show and say.
type Issuance struct {
	// Facts is what the resolver answered, structured.
	//
	// Carried alongside the prose because the prose is English and a caller
	// reading this over the API should not have to parse a sentence to learn
	// which authorities are named.
	Facts IssuanceFacts `json:"facts"`

	// Line is the one-sentence summary for the report, phrased as what was
	// found rather than as a judgement.
	Line string `json:"line"`

	// Notes carries the detail: where the answer came from, how far the walk
	// went, and what the answer does and does not establish.
	Notes []Note `json:"notes,omitempty"`

	// Bindings is each authority the record set allows, and how far it binds
	// that authority (RFC 8657): to which accounts, and to which ways of
	// proving control. Empty where nothing restricts issuance.
	Bindings []Binding `json:"bindings,omitempty"`
}

// Binding is what the record set allows one authority.
//
// RFC 8657 adds two parameters to an issue property. accounturi names the
// account at the authority that may ask for a certificate, and
// validationmethods the ways that account may prove control of the name. An
// authority named by several properties may issue under any of them, so it is
// bound to accounts only if every property naming it names one, and to methods
// only if every one names those.
type Binding struct {
	Authority string `json:"authority"`

	// Wildcard is true for a binding read from issuewild properties, which
	// govern wildcard certificates where any are present.
	Wildcard bool `json:"wildcard,omitempty"`

	// Accounts are the accounts named; empty when any account may ask.
	Accounts []string `json:"accounts,omitempty"`

	// Methods are the validation methods named; empty when any may be used.
	Methods []string `json:"methods,omitempty"`
}

// Bound is whether only named accounts at this authority may ask.
func (b Binding) Bound() bool { return len(b.Accounts) > 0 }

// bindings reads each authority's limits from the values of one property.
func bindings(values []string, wildcard bool) []Binding {
	type limits struct {
		accounts, methods  []string
		unbound, anyMethod bool
	}
	order := []string{}
	by := map[string]*limits{}
	for _, value := range values {
		domain, params, _ := strings.Cut(value, ";")
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			// ";" alone permits nobody: no authority to bind.
			continue
		}
		l, ok := by[domain]
		if !ok {
			l = &limits{}
			by[domain] = l
			order = append(order, domain)
		}
		var accounts, methods []string
		for _, p := range strings.Split(params, ";") {
			key, val, found := strings.Cut(strings.TrimSpace(p), "=")
			if !found {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "accounturi":
				if v := strings.TrimSpace(val); v != "" {
					accounts = append(accounts, v)
				}
			case "validationmethods":
				for _, m := range strings.Split(val, ",") {
					if m = strings.TrimSpace(m); m != "" {
						methods = append(methods, m)
					}
				}
			}
		}
		if len(accounts) == 0 {
			l.unbound = true
		}
		if len(methods) == 0 {
			l.anyMethod = true
		}
		l.accounts = append(l.accounts, accounts...)
		l.methods = append(l.methods, methods...)
	}

	out := make([]Binding, 0, len(order))
	for _, domain := range order {
		l := by[domain]
		b := Binding{Authority: domain, Wildcard: wildcard}
		if !l.unbound {
			b.Accounts = unique(l.accounts)
		}
		if !l.anyMethod {
			b.Methods = unique(l.methods)
		}
		out = append(out, b)
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// describeBindings says, in one sentence, whether the authorities allowed are
// held to the domain owner's own accounts.
//
// Not graded: RFC 8657 is an option an authority may support, and a record
// set without it restricts issuance exactly as RFC 8659 says. But it is the
// difference between "Let's Encrypt may issue" and "your Let's Encrypt account
// may issue", which is the difference between any of its millions of
// customers who can answer a challenge for this name and only you.
func describeBindings(bs []Binding) []Note {
	var unbound, bound []string
	for _, b := range bs {
		name := b.Authority
		if b.Wildcard {
			name += " (wildcards)"
		}
		if b.Bound() {
			bound = append(bound, name)
		} else {
			unbound = append(unbound, name)
		}
	}
	switch {
	case len(bs) == 0:
		return nil
	case len(unbound) == 0:
		return []Note{Observed("Only the accounts the record names may ask " + list(bound) +
			" for a certificate for this name (RFC 8657 accounturi)." + namedAccounts(bs))}
	default:
		return []Note{Observed("Any account at " + list(unbound) + " may ask for a certificate for " +
			"this name. An accounturi parameter (RFC 8657) limits that to your own account, and " +
			"validationmethods to the way you prove control.")}
	}
}

// namedAccounts lists the accounts each bound authority is held to, for the
// note that says it is held: the summary line counts them, and a reader
// checking that the accounts are their own needs to see which they are.
func namedAccounts(bs []Binding) string {
	var parts []string
	for _, b := range bs {
		if !b.Bound() {
			continue
		}
		name := b.Authority
		if b.Wildcard {
			name += " for wildcards"
		}
		parts = append(parts, " At "+name+": "+list(b.Accounts)+".")
	}
	return strings.Join(parts, "")
}

// DescribeIssuance turns a resolver's answer into what a reader should see.
func DescribeIssuance(f IssuanceFacts) Issuance {
	if !f.Checked {
		return Issuance{
			Facts: f,
			Line:  "not checked",
			Notes: []Note{Unsettled(
				"Whether any authority is restricted from issuing certificates for this name was " +
					"not checked: no DNS lookup was made. That is not a finding about the name.")},
		}
	}

	if !f.Exists {
		return Issuance{
			Facts: f,
			Line:  "the name does not resolve",
			Notes: []Note{Observed(
				"The resolver said this name does not exist, so there is nothing for an authority to " +
					"issue a certificate for and nothing to restrict.")},
		}
	}

	// Where the answer came from, and what about it was taken on trust. This
	// qualifies the line above it rather than adding to it, so it is not an
	// observation: the resolver's word is what stands in for a check here.
	provenanceText := "This came from the resolver this machine is configured to use, over a path nothing " +
		"here authenticates. "
	if f.Validated {
		provenanceText += "The resolver reported the answer as DNSSEC-validated, which is its claim rather " +
			"than a check this service performed."
	} else {
		provenanceText += "The answer was not marked DNSSEC-validated: either the zone is not signed, as " +
			"most are not, or it was not verified, and the two look the same from here."
	}
	provenance := Unsettled(provenanceText)

	// The pairing with certificate transparency, which sits on the next line
	// of the report. Stated on every branch, because a reader who has just
	// been told issuance is restricted is exactly the reader most likely to
	// stop reading.
	const pairing = "An authority checks CAA when it issues, so it does not help against a resolver " +
		"poisoned at that moment or a compromised authority; certificate transparency, " +
		"below, records the result either way. The format is RFC 8659."

	switch {
	case len(f.Authorities) == 0 && len(f.Wildcards) == 0 && f.Other > 0:
		// The case that reads as protection and is not. microsoft.com
		// publishes contactemail and nothing else: a record set exists, and
		// no authority is restricted by it.
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("CAA present at %s, and none of it restricts issuance", f.FoundAt),
			Notes: []Note{
				Observed(fmt.Sprintf("A CAA record set exists at %s but has no issue property, so it restricts "+
					"nobody: any public authority may still issue for this name. Probably an "+
					"unfinished step. %s", f.FoundAt, pairing)),
				provenance,
			},
		}

	case len(f.Authorities) == 0 && len(f.Wildcards) == 0 && !f.SearchComplete:
		// The walk stopped before the top, so the names above it were never
		// asked, and one of them is where a policy for the whole tree would
		// live. Saying nothing restricts issuance here would be reporting an
		// absence that was not looked for.
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("no CAA found, but the search stopped at %s before reaching the top", f.SearchedTo),
			Notes: []Note{
				Unsettled("No CAA record was found between this name and " + f.SearchedTo + ", and the search " +
					"stopped there. CAA is inherited, so a record on a shorter name could govern " +
					"this one; whether any authority is restricted was not established. " + pairing),
				provenance,
			},
		}

	case len(f.Authorities) == 0 && len(f.Wildcards) == 0:
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("no CAA at this name or above it, searched to %s", f.SearchedTo),
			Notes: []Note{
				Observed("No CAA record was found for this name or any parent up to " + f.SearchedTo + ". Any " +
					"publicly trusted certificate authority may therefore issue for it, of around a " +
					"hundred. One record naming the authorities you use tells the rest to refuse; " +
					"checking it has been mandatory for authorities since 2017. " + pairing),
				provenance,
			},
		}
	}

	bound := append(bindings(f.Authorities, false), bindings(f.Wildcards, true)...)
	notes := []Note{
		Observed(fmt.Sprintf("Issuance for this name is restricted by the CAA record set at %s. %s",
			f.FoundAt, pairing)),
	}
	notes = append(notes, describeBindings(bound)...)
	return Issuance{
		Facts:    f,
		Line:     describeAuthorities(f),
		Notes:    append(notes, provenance),
		Bindings: bound,
	}
}

// describeAuthorities writes the summary line for a name that restricts.
//
// The authorities are named rather than counted. They are the point: an
// operator reading their own report wants to see the authority they use, and
// somebody reading a report about a third party learns which authorities that
// party trusts, which is public information the moment a certificate is
// issued.
//
// The values are taken from the zone, so a hostile target chooses them.
// dnsclient refuses anything not printable before they reach here, and they
// go to the page as text rather than to a parser.
func describeAuthorities(f IssuanceFacts) string {
	var parts []string

	switch {
	case len(f.Authorities) == 1 && f.Authorities[0] == ";":
		// A single semicolon is the way a zone says nobody may issue.
		parts = append(parts, "no authority is permitted to issue")
	case len(f.Authorities) > 0:
		parts = append(parts, "issuance limited to "+list(readable(f.Authorities)))
	default:
		// issuewild without issue. RFC 8659 leaves ordinary issuance
		// unrestricted here, which is worth saying rather than implying.
		parts = append(parts, "ordinary issuance is not restricted")
	}

	switch {
	case len(f.Wildcards) == 1 && f.Wildcards[0] == ";":
		parts = append(parts, "wildcards refused")
	case len(f.Wildcards) > 0:
		parts = append(parts, "wildcards limited to "+list(readable(f.Wildcards)))
	}

	if f.FoundAt != "" {
		return strings.Join(parts, "; ") + " (from " + f.FoundAt + ")"
	}
	return strings.Join(parts, "; ")
}

// readable separates each CAA value into the authority it names and the
// parameters that follow it.
//
// RFC 8659 §4.2 puts parameters after the domain, separated by semicolons:
// `pki.goog; cansignhttpexchanges=yes` is one value naming one authority. The
// whole string used to go into the list unchanged, and the list is joined with
// commas while the clauses around it are joined with semicolons — so a real
// record set came out as
//
//	issuance limited to comodoca.com, digicert.com; cansignhttpexchanges=yes,
//	letsencrypt.org, pki.goog; cansignhttpexchanges=yes and ssl.com
//
// which a reader cannot parse and might read as naming an authority called
// cansignhttpexchanges=yes. Measured on kapitalbank.az, 2026-08-23.
//
// The parameter is worth showing rather than dropping. cansignhttpexchanges
// authorises that authority to sign Signed HTTP Exchanges, which is a wider
// power than issuing an ordinary certificate, and a reader deciding whether a
// zone's restrictions are tight enough needs to see it.
//
// Each authority is written once, however many values name it, and RFC 8657's
// two parameters are summed up rather than printed: how many accounts it is
// held to, and by which ways of proving control. Printed, this project's own
// record set — one authority, two accounts, DNS only — came out on 2026-10-11
// as the authority twice, each followed by an account URL and a method, and
// read as noise on the line that matters. The URLs are in the note that says
// the authority is held to them, and in the report's bindings. As bindings
// does, an authority is held to accounts or methods only if every value naming
// it says so.
func readable(values []string) []string {
	type entry struct {
		domain                    string
		accounts, methods, others []string
		unbound, anyMethod        bool
	}
	var order []*entry
	by := map[string]*entry{}
	for _, value := range values {
		domain, params, _ := strings.Cut(value, ";")
		domain = strings.TrimSpace(domain)

		if domain == "" {
			// An empty value permits nobody, which is meaningful on its own
			// and must not silently vanish from a list.
			order = append(order, &entry{})
			continue
		}

		key := strings.ToLower(domain)
		e, ok := by[key]
		if !ok {
			e = &entry{domain: domain}
			by[key] = e
			order = append(order, e)
		}
		var accounts, methods []string
		for _, p := range strings.Split(params, ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			name, val, _ := strings.Cut(p, "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "accounturi":
				if v := strings.TrimSpace(val); v != "" {
					accounts = append(accounts, v)
				}
			case "validationmethods":
				for _, m := range strings.Split(val, ",") {
					if m = strings.TrimSpace(m); m != "" {
						methods = append(methods, m)
					}
				}
			default:
				e.others = append(e.others, p)
			}
		}
		if len(accounts) == 0 {
			e.unbound = true
		}
		if len(methods) == 0 {
			e.anyMethod = true
		}
		e.accounts = append(e.accounts, accounts...)
		e.methods = append(e.methods, methods...)
	}

	out := make([]string, 0, len(order))
	for _, e := range order {
		if e.domain == "" {
			out = append(out, "an empty value, which names no authority")
			continue
		}
		var settings []string
		if !e.unbound {
			if n := len(unique(e.accounts)); n == 1 {
				settings = append(settings, "1 account")
			} else {
				settings = append(settings, fmt.Sprintf("%d accounts", n))
			}
		}
		if !e.anyMethod {
			settings = append(settings, strings.Join(unique(e.methods), " or ")+" only")
		}
		settings = append(settings, unique(e.others)...)
		if len(settings) == 0 {
			out = append(out, e.domain)
			continue
		}
		out = append(out, e.domain+" ("+strings.Join(settings, ", ")+")")
	}
	return out
}

// list writes names as prose, so a report does not read like a data structure.
func list(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}
