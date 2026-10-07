package policy

import (
	"strconv"
	"strings"
	"time"
)

// The rules for what a domain's own DNS says about itself.
//
// The line is the one the mail rules draw, and it matters more here than
// anywhere else in this project, because DNS is the part of the internet with
// the most advice and the fewest requirements. A serial number in a particular
// format, a refresh timer inside a particular range, a primary named at the
// parent: scanners report these as faults and none of them is one. RFC 1912
// calls its ranges recommendations, and a zone outside them is a choice its
// operator made — often a correct one, since a zone whose records are written
// by an API needs no serial a human can read.
//
// So what is graded here is what breaks resolution, or what a standard
// requires: fewer name servers than a zone is required to have, a delegation
// nobody can follow, and a DNSSEC chain that does not check out — which takes
// a domain off the internet for everybody behind a validating resolver, and
// leaves it working for whoever set it up. Everything else is reported.

// DNSVersion identifies this rule set, which moves independently of the
// others.
const DNSVersion = "porch-dns-v2"

var (
	rfc1034 = Reference{
		"RFC 1034 — Domain Names: Concepts and Facilities",
		"https://www.rfc-editor.org/rfc/rfc1034",
	}
	rfc1912 = Reference{
		"RFC 1912 — Common DNS Operational and Configuration Errors",
		"https://www.rfc-editor.org/rfc/rfc1912",
	}
	rfc2181 = Reference{
		"RFC 2181 — Clarifications to the DNS Specification",
		"https://www.rfc-editor.org/rfc/rfc2181",
	}
	rfc2182 = Reference{
		"RFC 2182 — Selection and Operation of Secondary DNS Servers (BCP 16)",
		"https://www.rfc-editor.org/rfc/rfc2182",
	}
	rfc4035 = Reference{
		"RFC 4035 — Protocol Modifications for the DNS Security Extensions",
		"https://www.rfc-editor.org/rfc/rfc4035",
	}
	rfc5358 = Reference{
		"RFC 5358 — Preventing Use of Recursive Nameservers in Reflector Attacks (BCP 140)",
		"https://www.rfc-editor.org/rfc/rfc5358",
	}
	rfc9276 = Reference{
		"RFC 9276 — Guidance for NSEC3 Parameter Settings (BCP 236)",
		"https://www.rfc-editor.org/rfc/rfc9276",
	}
	rfc8624 = Reference{
		"RFC 8624 — Algorithm Implementation Requirements and Usage Guidance for DNSSEC",
		"https://www.rfc-editor.org/rfc/rfc8624",
	}
)

// NameServer is one server a zone is delegated to, and what resolving its name
// found.
type NameServer struct {
	Name string `json:"name"`

	// Addresses are what the name resolves to, as text. Empty with no reason
	// means the name resolves to nothing at all, which is a delegation to a
	// server no resolver can reach.
	Addresses []string `json:"addresses,omitempty"`

	// Reason says why the addresses could not be read, where that is what
	// happened. A lookup that failed is not a server without an address (R4).
	Reason string `json:"reason,omitempty"`

	// Alias is what this server's name points at, where the name is an alias.
	// RFC 2181 forbids that: a resolver following a delegation expects an
	// address at the name it was given.
	Alias string `json:"alias,omitempty"`

	// Asked is whether this server was put the question directly, and
	// Authoritative whether it answered for the zone as its own. Without Asked,
	// Authoritative false is silence rather than a server that does not answer
	// for the zone (R4).
	Asked         bool `json:"asked,omitempty"`
	Authoritative bool `json:"authoritative,omitempty"`

	// AskedReason says why asking established nothing: the server refused, or
	// nothing answered on port 53 from here.
	AskedReason string `json:"askedReason,omitempty"`

	// Serial is the zone's serial as this server answered it, and SerialRead
	// says whether it answered with one at all. Two servers holding different
	// serials hold different copies of the zone: the lower one is behind, and
	// whoever a resolver happens to ask gets that copy.
	//
	// SerialRead rather than a zero serial, because zero is a serial somebody
	// can publish (R4).
	Serial     uint32 `json:"serial,omitempty"`
	SerialRead bool   `json:"serialRead,omitempty"`

	// Glue is what the zone above hands out as this server's address, where it
	// hands out anything, and GlueRead says whether the question was put.
	//
	// Only ever filled for a server inside the zone it serves: a resolver
	// starting at the root cannot look that name up without being told, so the
	// parent's copy is what it dials. The zone publishes the same addresses
	// itself, in Addresses above, and the two can disagree.
	Glue     []string `json:"glue,omitempty"`
	GlueRead bool     `json:"glueRead,omitempty"`

	// TransferAsked is whether this server was asked for the whole zone, and
	// Transfer whether it began handing it over. TransferReason says why the
	// question established nothing, where that is what happened.
	//
	// What was read of the answer is its header. The zone itself is not taken:
	// what this reports is that the zone is readable, never what is in it.
	TransferAsked  bool   `json:"transferAsked,omitempty"`
	Transfer       bool   `json:"transfer,omitempty"`
	TransferReason string `json:"transferReason,omitempty"`

	// RecursionAsked is whether this server was asked about a domain it has
	// nothing to do with, and Recursion whether it went and found the answer.
	// Only a server inside the domain being checked is asked that: a provider's
	// server is somebody else's, and the question is about its behaviour rather
	// than about this zone.
	RecursionAsked bool `json:"recursionAsked,omitempty"`
	Recursion      bool `json:"recursion,omitempty"`
}

// KeyDigest is one key a zone publishes.
type KeyDigest struct {
	KeyTag    uint16 `json:"keyTag"`
	Algorithm uint8  `json:"algorithm"`

	// Name is what RFC 8624 calls the algorithm, filled in beside the number so
	// that a report shows what an operator's own interface shows.
	Name string `json:"name,omitempty"`

	// KeySigning is true for a key with the secure entry point bit set, which
	// is the key a delegation signer is normally a digest of.
	KeySigning bool `json:"keySigning"`
}

// DelegationSigner is one digest the parent holds, and whether a key here
// matched it.
type DelegationSigner struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`

	// Matched is true when a key this zone publishes hashes to this digest.
	Matched bool `json:"matched"`

	// Unsupported is true for a digest type this does not compute, which is
	// not the same as one that did not match and must never be read as it.
	Unsupported bool `json:"unsupported,omitempty"`
}

// DNSFacts is what asking a domain's own DNS established.
type DNSFacts struct {
	// Apex is false when no zone begins at the name asked about — a name
	// inside a zone rather than the top of one. Nothing below is graded then:
	// the answers belong to whichever zone contains it.
	Apex bool `json:"apex"`

	// IPv4 and IPv6 are what the name itself resolves to, kept apart because
	// they are two questions: a name with an address of one kind and none of
	// the other is ordinary, and a report that merged them could not say which
	// of the two was asked and found nothing.
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`

	// AddressReason says why they could not be read.
	AddressReason string `json:"addressReason,omitempty"`

	// NameServers are the servers the zone names, with what each resolves to.
	NameServers []NameServer `json:"nameServers,omitempty"`

	// NSReason says why the delegation could not be read at all.
	NSReason string `json:"nsReason,omitempty"`

	// Networks is how many distinct networks the name servers' addresses fall
	// in, counting an IPv4 /24 and an IPv6 /48 as one each.
	Networks int `json:"networks"`

	// What the zone above this one says serves it, which is a second claim
	// about the same delegation and the one a resolver starting at the root
	// actually follows.
	//
	// Parent is that zone's name and is filled whether or not it was asked;
	// ParentServer is the server of it that answered. ParentAsked is the
	// difference between a list that is empty and a question that was never
	// put, and ParentReason says which (R4).
	Parent            string   `json:"parent,omitempty"`
	ParentServer      string   `json:"parentServer,omitempty"`
	ParentAsked       bool     `json:"parentAsked"`
	ParentReason      string   `json:"parentReason,omitempty"`
	ParentNameServers []string `json:"parentNameServers,omitempty"`

	// What comparing the two lists found: names the parent hands out and the
	// zone does not, and names the zone lists and the parent does not. Filled
	// by the scan through DelegationDiff, so that the grade, the printed
	// report and the page all read one comparison.
	OnlyAtParent []string `json:"onlyAtParent,omitempty"`
	OnlyAtZone   []string `json:"onlyAtZone,omitempty"`

	// When the signature over the record at the top of the zone stops being
	// accepted, and when it started.
	//
	// SignatureRead is the difference between a zone that publishes no
	// signature and an answer that carried none — an unsigned zone, a resolver
	// that stripped them, a record this could not read (R4). The key tag says
	// which key made it, so that an operator rolling keys can tell which one
	// the date belongs to.
	SignatureRead      bool      `json:"signatureRead"`
	SignatureExpires   time.Time `json:"signatureExpires,omitempty"`
	SignatureInception time.Time `json:"signatureInception,omitempty"`
	SignatureKeyTag    uint16    `json:"signatureKeyTag,omitempty"`

	// The record at the top of the zone, as published.
	SOAFound   bool   `json:"soaFound"`
	SOAPrimary string `json:"soaPrimary,omitempty"`
	SOAMailbox string `json:"soaMailbox,omitempty"`
	SOASerial  uint32 `json:"soaSerial,omitempty"`
	SOARefresh uint32 `json:"soaRefresh,omitempty"`
	SOARetry   uint32 `json:"soaRetry,omitempty"`
	SOAExpire  uint32 `json:"soaExpire,omitempty"`
	SOAMinimum uint32 `json:"soaMinimum,omitempty"`

	// Alias is what a CNAME at this name points to, empty where the name is not
	// an alias. AliasTargetExists says whether that target exists at all, which
	// is the difference between an alias that works and a name that resolves to
	// nothing.
	Alias             string `json:"alias,omitempty"`
	AliasTargetExists bool   `json:"aliasTargetExists,omitempty"`
	AliasReason       string `json:"aliasReason,omitempty"`

	// Text is what the name publishes as TXT, which is where a domain's sender
	// policy and most of its proofs of ownership live. Reported and never
	// graded: the mail check grades the sender policy, and the rest belongs to
	// whoever put it there.
	Text []string `json:"text,omitempty"`

	// Signed is whether the parent holds a delegation signer for this zone,
	// which is what anchors the chain. A zone without one is unsigned, and that
	// is a choice rather than a fault.
	Signed bool `json:"signed"`

	// Signers and Keys are the two ends of the link.
	Signers []DelegationSigner `json:"signers,omitempty"`
	Keys    []KeyDigest        `json:"keys,omitempty"`

	// NSEC3Read is whether the record saying how absent names are proved was
	// read at all. Without it, NSEC3 false is silence rather than a zone using
	// the plain kind (R4).
	NSEC3Read       bool   `json:"nsec3Read"`
	NSEC3           bool   `json:"nsec3"`
	NSEC3Iterations uint16 `json:"nsec3Iterations,omitempty"`
	NSEC3SaltLength int    `json:"nsec3SaltLength,omitempty"`

	// ChainMatched is true when at least one digest the parent holds covers a
	// key this zone publishes.
	ChainMatched bool `json:"chainMatched"`

	// ChainReason says why the two ends could not be compared.
	ChainReason string `json:"chainReason,omitempty"`

	// ResolverValidated is the AD bit on the answers: the resolver's claim that
	// it checked the signatures, and not this program's work.
	ResolverValidated bool `json:"resolverValidated"`

	// Policy names the rule set, carried beside the facts for the reason every
	// other check carries it.
	Policy string `json:"policy"`
}

// DNSFinding is the graded result.
type DNSFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
	Notes    []Note    `json:"notes,omitempty"`
}

// GradeDNS applies the rules above.
//
// The clock is passed in rather than read here, as GradeLeaf takes it: one
// rule turns on a date — a signature outside its validity period, which every
// validator refuses — and a rule that read the machine's clock could not be
// tested against a fixed one.
func GradeDNS(f DNSFacts, now time.Time) DNSFinding {
	out := DNSFinding{Verdict: Strong}

	add := func(id string, v Verdict, title, rationale string, refs ...Reference) {
		out.Findings = append(out.Findings, Finding{
			RuleID:     id,
			Verdict:    v,
			Title:      title,
			Rationale:  rationale,
			References: refs,
			Policy:     DNSVersion,
		})
		out.Verdict = Worst(out.Verdict, v)
	}
	// Two kinds, and the difference is R18: a fact this scan established, and a
	// question it could not settle. A note without a kind is neither, and the
	// renderers sort by kind.
	note := func(text string) { out.Notes = append(out.Notes, Observed(text)) }
	unsettled := func(text string) { out.Notes = append(out.Notes, Unsettled(text)) }

	// ── The alias, which is read wherever the name is one ────────────

	switch {
	case f.AliasReason != "":
		unsettled("The alias could not be read: " + f.AliasReason)
	case f.Alias == "":
	case f.AliasTargetExists:
		note("This name is an alias for " + f.Alias + ", so everything it answers comes from there.")
	default:
		// Not graded, and the reason is R21: no document sets a rule about an
		// alias whose target is gone. What can be said is what was measured,
		// and what it leads to — which is the more useful half anyway.
		note("This name is an alias for " + f.Alias + ", and " + f.Alias + " does not exist, so the " +
			"name resolves to nothing. If the target is at a provider that hands out " +
			"unclaimed names, whoever claims it next answers for this name.")
	}

	if f.Apex && f.Alias != "" {
		add("dns.alias-at-zone-apex", Insecure,
			"The top of the zone is an alias",
			"RFC 1034 and RFC 2181 let a name be an alias or carry records, never both. At "+
				"the top of a zone an alias contradicts the zone's own records, so resolvers "+
				"that follow it lose the zone's mail and name servers.",
			rfc1034, rfc2181)
	}

	// A name inside a zone is not a zone. Nothing here describes it, and
	// grading the containing zone's delegation as though it were this name's
	// would report a fact about example.com under the name www.example.com.
	if !f.Apex {
		out.Verdict = ""
		note("No zone begins at this name: it is a name inside one. Ask about the domain itself to read its delegation.")
		return withLimits(out)
	}

	// ── Graded: the delegation ───────────────────────────────────────

	var unreachable []string
	for _, ns := range f.NameServers {
		if len(ns.Addresses) == 0 && ns.Reason == "" {
			unreachable = append(unreachable, ns.Name)
		}
	}

	switch {
	case f.NSReason != "":
		unsettled("The delegation could not be read: " + f.NSReason)
	case len(f.NameServers) < 2:
		add("dns.one-name-server", Weak,
			"The zone is served by fewer than two name servers",
			"RFC 1034 requires at least two name servers, and RFC 2182 explains why: one "+
				"server is a single point of failure. This zone names "+
				strconv.Itoa(len(f.NameServers))+".",
			rfc1034, rfc2182)
	case f.Networks == 1:
		add("dns.name-servers-one-network", Weak,
			"Every name server answers from the same network",
			"RFC 2182 asks for name servers that do not fail together. These "+
				strconv.Itoa(len(f.NameServers))+" answer from one network, so whatever takes it "+
				"out takes the domain with it.",
			rfc2182)
	}

	var aliased []string
	for _, ns := range f.NameServers {
		if ns.Alias != "" {
			aliased = append(aliased, ns.Name)
		}
	}
	var lame, recursing []string
	for _, ns := range f.NameServers {
		if ns.Asked && !ns.Authoritative && ns.AskedReason == "" {
			lame = append(lame, ns.Name)
		}
		if ns.Recursion {
			recursing = append(recursing, ns.Name)
		}
	}
	if len(lame) > 0 {
		add("dns.name-server-not-authoritative", Weak,
			"A name server this zone names does not answer for it",
			"Asked for this zone directly, "+strings.Join(lame, ", ")+" answered without "+
				"claiming it. RFC 1912 calls that a lame delegation: lookups that land there are "+
				"slower, and enough of them stop the zone resolving.",
			rfc1912)
	}
	if len(recursing) > 0 {
		add("dns.name-server-offers-recursion", Weak,
			"A name server this zone names answers questions about other domains",
			"Asked about a domain it has nothing to do with, "+strings.Join(recursing, ", ")+
				" went and found the answer. RFC 5358 says an authoritative server should not: "+
				"anyone can use it to aim large answers at somebody else.",
			rfc5358)
	}

	// The parent's list against the zone's own. Only where the parent was
	// actually asked: an unasked question is not agreement (R4), and the two
	// lists being equal is what the report says when it is.
	if f.ParentAsked && f.NSReason == "" {
		if atParent, atZone := f.OnlyAtParent, f.OnlyAtZone; len(atParent)+len(atZone) > 0 {
			detail := "RFC 1912 asks that the zone above this one hand out the same servers the zone " +
				"itself names. " + f.ParentServer + ", a server of " + f.Parent + ", does not: "
			switch {
			case len(atParent) > 0 && len(atZone) > 0:
				detail += "it delegates to " + strings.Join(atParent, ", ") + ", which this zone does not " +
					"name, and this zone names " + strings.Join(atZone, ", ") + ", which it does not delegate to."
			case len(atParent) > 0:
				detail += "it delegates to " + strings.Join(atParent, ", ") + ", which this zone does not name."
			default:
				detail += "this zone names " + strings.Join(atZone, ", ") + ", which it does not delegate to."
			}
			add("dns.parent-and-zone-disagree", Weak,
				"The zone above this one delegates to a different set of servers",
				detail+" Resolvers follow the parent's list, so which servers answer depends on "+
					"which one a resolver tried first, and a name only the parent hands out may "+
					"point somewhere that no longer holds this zone.",
				rfc1912)
		}
	}

	// The address the zone above hands out for a server, against the one the
	// zone publishes for the same name.
	//
	// A server inside the zone it serves cannot be looked up without being
	// told where it is, so what a resolver starting at the root dials is the
	// parent's copy — and nothing in the zone's own records shows what that
	// copy says. RFC 1912 §2.3 describes both halves of getting it wrong: an
	// address left behind at the parent, where "random people still see the
	// old IP address", and a multi-homed server whose addresses are not all
	// listed, which it states as a requirement.
	if stale, missing := glueDiff(f.NameServers); len(stale)+len(missing) > 0 {
		detail := "A server inside this zone is reached only through the address its parent hands " +
			"out. "
		switch {
		case len(stale) > 0 && len(missing) > 0:
			detail += "The parent hands out " + strings.Join(stale, ", ") + ", which this zone does not " +
				"publish, and this zone publishes " + strings.Join(missing, ", ") + ", which the parent " +
				"does not hand out."
		case len(stale) > 0:
			detail += "The parent hands out " + strings.Join(stale, ", ") + ", which this zone does not publish."
		default:
			detail += "This zone publishes " + strings.Join(missing, ", ") + ", which the parent does not " +
				"hand out — and RFC 1912 asks that every address of a server appear in the glue."
		}
		add("dns.glue-does-not-match", Weak,
			"The address the parent hands out is not the one this zone publishes",
			detail+" Some resolvers reach the old address, which may no longer serve this "+
				"zone, and others reach the new one. It is fixed at the registrar, not in the "+
				"zone file.",
			rfc1912)
	}

	if len(aliased) > 0 {
		add("dns.name-server-is-an-alias", Weak,
			"A name server this zone names is an alias",
			"RFC 2181 says a name in a delegation must have an address and must not be an "+
				"alias: "+strings.Join(aliased, ", ")+" is one. Resolvers handle that "+
				"differently, so some reach this zone and others do not.",
			rfc2181)
	}

	if len(unreachable) > 0 {
		add("dns.name-server-without-address", Weak,
			"A name server this zone names resolves to nothing",
			"RFC 1912 calls this a lame delegation: "+strings.Join(unreachable, ", ")+" is "+
				"named as a server for this zone and has no address. Every lookup that tries it "+
				"waits; usually a server was retired without updating the delegation.",
			rfc1912)
	}

	// ── Graded: the chain ────────────────────────────────────────────

	switch {
	case !f.Signed:
		note("The zone is not signed: the parent holds no delegation signer for it. That is a " +
			"choice rather than a fault.")
	case f.ChainReason != "":
		unsettled("The DNSSEC chain could not be checked: " + f.ChainReason)
	case len(f.Keys) == 0:
		add("dns.dnssec-no-keys", Insecure,
			"The parent anchors DNSSEC for this zone and the zone publishes no key",
			"The parent's delegation signer says this zone is signed, but no key is "+
				"published here. Validating resolvers, including the large public ones, return a "+
				"failure instead of the records, while it keeps working for whoever set it up.",
			rfc4035)
	case !f.ChainMatched && !computable(f.Signers):
		// Every digest the parent holds is of a type this does not compute, so
		// the chain was not checked rather than found wanting. Reported below,
		// with the sentence R4 exists for.
	case !f.ChainMatched:
		add("dns.dnssec-chain-broken", Insecure,
			"No key this zone publishes matches the digest its parent holds",
			"None of the keys published here matches the parent's delegation signer, which "+
				"is what a key rotation that never reached the registrar looks like. Validating "+
				"resolvers treat the whole zone as bogus and return nothing.",
			rfc4035)
	}

	for _, ds := range f.Signers {
		if ds.DigestType == 1 && ds.Matched {
			add("dns.dnssec-sha1-digest", Weak,
				"The digest the parent holds for this zone is SHA-1",
				"RFC 8624 says SHA-1 is not to be used for new delegation signers. The chain "+
					"works today, but its weakest link is a hash nobody would choose now; replacing "+
					"it is done at the registrar.",
				rfc8624)
			break
		}
	}

	// ── Graded: the algorithms, and how absent names are proved ──────

	// RFC 8624 sorts the signing algorithms into what must not be used and
	// what is no longer recommended, and the difference is the difference
	// between a zone validators are dropping and one they still accept while
	// the advice moves. Both are read off the keys the zone publishes: an
	// algorithm is a fact in the record, not an opinion about it.
	retired, weak := algorithmsOf(f.Keys)
	if len(retired) > 0 {
		add("dns.dnssec-retired-algorithm", Insecure,
			"The zone signs with an algorithm RFC 8624 says must not be used",
			"The keys published here use "+strings.Join(retired, ", ")+". Resolvers that "+
				"follow RFC 8624 treat a zone signed only with these as unsigned or bogus. "+
				"Replacing them needs a key rollover and a new digest at the registrar.",
			rfc8624)
	}
	if len(weak) > 0 {
		add("dns.dnssec-weak-algorithm", Weak,
			"The zone signs with an algorithm RFC 8624 no longer recommends",
			"The keys published here use "+strings.Join(weak, ", ")+", which RFC 8624 does "+
				"not recommend for signing. Validators accept it today; moving to ECDSA or "+
				"Ed25519 is a rollover that has to happen eventually.",
			rfc8624)
	}

	// How a signed zone proves a name does not exist. NSEC3 with anything but
	// zero iterations is what RFC 9276 — a best current practice — closed:
	// every iteration is work every resolver does on every negative answer,
	// and the secrecy it was meant to buy was measured and found absent.
	if f.NSEC3 && f.NSEC3Iterations > 0 {
		add("dns.nsec3-iterations", Weak,
			"The zone hashes absent names more than once",
			"RFC 9276 says the NSEC3 iteration count must be zero: extra iterations cost "+
				"every resolver and this zone's own servers work, and keep no names secret. This "+
				"zone publishes "+strconv.Itoa(int(f.NSEC3Iterations))+".",
			rfc9276)
	}

	for _, ds := range f.Signers {
		if ds.Unsupported {
			unsettled("The parent holds a digest of a type this check does not compute (type " +
				strconv.Itoa(int(ds.DigestType)) + "), so that one was neither matched nor ruled " +
				"out.")
			break
		}
	}

	// ── Reported ─────────────────────────────────────────────────────

	switch {
	case f.AddressReason != "":
		unsettled("The addresses could not be read: " + f.AddressReason)
	case len(f.IPv4)+len(f.IPv6) == 0:
		note("The name itself resolves to no address. That is ordinary for a domain used only " +
			"for mail or for the names beneath it.")
	}

	if f.SOAFound {
		note("The zone's serial is " + strconv.FormatUint(uint64(f.SOASerial), 10) + ", it names " +
			f.SOAPrimary + " as primary, and its timers are refresh " + duration(f.SOARefresh) +
			", retry " + duration(f.SOARetry) + ", expire " + duration(f.SOAExpire) + ", minimum " +
			duration(f.SOAMinimum) + ". RFC 1912's ranges are recommendations, so these are " +
			"reported and not graded.")
	}

	// When the signatures run out, which nothing else in a report carries.
	//
	// Reported on every signed zone rather than only when it is close, because
	// close is a number this project would have invented. What a reader does
	// with "in four days" and "in three weeks" is their own judgement about
	// their own signing schedule, and the date is the thing they can check
	// against it.
	if f.Signed && f.SignatureRead && !f.SignatureExpires.IsZero() && !f.SignatureExpires.Before(now) {
		left := int(f.SignatureExpires.Sub(now).Hours() / 24)
		note("The signature over the top of this zone runs out on " +
			f.SignatureExpires.Format("2006-01-02") + ", in " + strconv.Itoa(left) + " days, and " +
			"was made by key " + strconv.Itoa(int(f.SignatureKeyTag)) + ". If re-signing stops, " +
			"the zone disappears for validating resolvers on that date. No document says how " +
			"much room to leave, so this is not graded.")
	}

	// A signature that has run out, which is the one thing here a document
	// settles outright.
	//
	// RFC 4035 §5.3.1 has a validator refuse a signature whose validity period
	// does not contain the current time, so a zone whose signatures have
	// expired is already gone for everybody behind one — the same outcome as a
	// broken chain and graded the same way. How long is left before that
	// happens is not graded: no document names a number of days, and a zone
	// re-signed hourly with a two-day window is as correct as one re-signed
	// weekly with a month (R21).
	if f.Signed && f.SignatureRead && !f.SignatureExpires.IsZero() && f.SignatureExpires.Before(now) {
		add("dns.signature-expired", Insecure,
			"The signature over this zone has run out",
			"This zone's signature ran out on "+f.SignatureExpires.Format("2006-01-02")+" at "+
				f.SignatureExpires.Format("15:04")+" UTC, and RFC 4035 requires validating "+
				"resolvers to refuse it. Behind the large public resolvers the domain now fails "+
				"to resolve; usually the signing job stopped.",
			rfc4035)
	}

	// Whether the zone can be read whole, by anybody.
	//
	// Reported and not graded, and that is RFC 5936 rather than caution.
	// Section 5 says an implementation ought to let an operator open transfers
	// to everyone — "a general-purpose implementation SHOULD allow access to be
	// open to all AXFR requests" — while saying it must not be the default, and
	// it says in as many words that the arguments for concealing a zone have
	// been argued to be questionable. So no document calls this a fault, R21
	// applies, and the sentence says what it costs instead of inventing a
	// grade: it is the same fact the note about plain absence proofs carries,
	// reached by a different route.
	if open, unread := transfersOf(f.NameServers); len(open) > 0 {
		began := "that server began"
		if len(open) > 1 {
			began = "those servers began"
		}
		note("The zone can be read whole from " + strings.Join(open, ", ") + ": asked for a " +
			"transfer, " + began + " handing it to an unknown address. That gives away every " +
			"name in the zone at once. RFC 5936 does not call it a fault, and some operators " +
			"allow it on purpose. This check closed the connection after the first reply's " +
			"header, so nothing was taken. To see what it hands over, run porch-scan -check " +
			"names -read-zone on your own zone.")
	} else if len(unread) > 0 {
		note("Whether the zone can be read whole was not established for " + strings.Join(unread, ", ") +
			": the question did not complete. That is not a zone that refused one (R4).")
	}

	// Whether the servers hold the same copy of the zone.
	//
	// Reported and not graded, and that is R21 rather than caution. A zone
	// changed a moment ago legitimately has servers at two serials until the
	// transfer finishes, no document says how long that may take, and a scan
	// sees one instant. What can be said is what was measured: these servers
	// answered with these numbers.
	if agreed, serials := serialsOf(f.NameServers); len(serials) > 1 {
		if agreed {
			note("All " + strconv.Itoa(len(serials)) + " servers that answered hold the same copy of the " +
				"zone: every one of them is at serial " + strconv.FormatUint(uint64(serials[0].serial), 10) + ".")
		} else {
			var said []string
			for _, s := range serials {
				said = append(said, s.name+" at "+strconv.FormatUint(uint64(s.serial), 10))
			}
			note("The servers do not hold the same copy of the zone: " + strings.Join(said, ", ") +
				". Right after a change that is ordinary; if it lasts, a server has stopped " +
				"receiving the zone, and the same name resolves differently depending on who " +
				"asks.")
		}
	}

	switch {
	case !f.Signed || !f.NSEC3Read:
		// An unsigned zone proves nothing absent, and an unread record is not
		// a zone using one kind or the other.
	case f.NSEC3:
		note("Names that do not exist are proved absent with hashed names, and the hash is applied " +
			strconv.Itoa(int(f.NSEC3Iterations)) + " extra times with a salt of " +
			strconv.Itoa(f.NSEC3SaltLength) + " bytes.")
	default:
		note("Names that do not exist are proved absent by naming the next name that does, so " +
			"anyone can list every name in this zone. Nothing requires the hashed kind (RFC " +
			"5155), so this is not graded.")
	}

	if f.ResolverValidated {
		note("The resolver reported these answers DNSSEC-validated. That is its word for work it did, " +
			"not a check this program made.")
	}

	return withLimits(out)
}

// withLimits adds the limits of the method, from the one place that declares
// them. A report that wrote its own would drift from the page explaining them,
// and the sentence a reader is asked to trust would exist in two versions.
func withLimits(out DNSFinding) DNSFinding {
	for _, l := range DNSStandingLimits() {
		out.Notes = append(out.Notes, l.Note())
	}
	return out
}

// duration says a number of seconds the way an operator reads one.
func duration(seconds uint32) string {
	switch {
	case seconds == 0:
		return "0"
	case seconds%86400 == 0:
		return strconv.FormatUint(uint64(seconds/86400), 10) + "d"
	case seconds%3600 == 0:
		return strconv.FormatUint(uint64(seconds/3600), 10) + "h"
	case seconds%60 == 0:
		return strconv.FormatUint(uint64(seconds/60), 10) + "m"
	default:
		return strconv.FormatUint(uint64(seconds), 10) + "s"
	}
}

// computable is whether any digest the parent holds is of a type this check
// computes. Where none is, a chain that did not match was never checked, and
// saying otherwise would report an unread record as a fault (R4).
func computable(signers []DelegationSigner) bool {
	for _, ds := range signers {
		if !ds.Unsupported {
			return true
		}
	}
	return false
}

// LimitDNSAsksTheResolver is what every DNS check here cannot see, and it is
// true of all of them.
//
// Stated as a limit rather than left out, for the reason R4 gives about every
// other silence: a report listing what a zone publishes and saying nothing
// about the rest reads as a complete picture of its DNS.
var LimitDNSAsksTheResolver = StandingLimit{
	ID:    "dns-asks-the-resolver",
	Title: "Everything here came from one resolver",

	Text: "Most answers came from this installation's resolver. Four questions go directly " +
		"to name servers over TCP port 53: whether each answers for the zone, whether " +
		"each allows a zone transfer, whether a server inside the domain (never a " +
		"provider's) answers for other domains, and which servers a parent server hands " +
		"out. The transfer is closed before any record is read. The DNSSEC chain is " +
		"checked by comparing key digests with the parent's; whether every signature " +
		"verifies is the resolver's word.",
}

// DNSStandingLimits are true of every DNS check this program runs.
func DNSStandingLimits() []StandingLimit {
	return []StandingLimit{LimitDNSAsksTheResolver}
}

// algorithmsOf sorts the algorithms a zone signs with into what RFC 8624 says
// must not be used and what it no longer recommends.
//
// Named rather than numbered in the finding, because an operator reading
// "algorithm 5" has to go and look it up, and the name is the thing they will
// type into their provider's interface.
func algorithmsOf(keys []KeyDigest) (retired, weak []string) {
	seen := map[uint8]bool{}
	for _, k := range keys {
		if seen[k.Algorithm] {
			continue
		}
		seen[k.Algorithm] = true

		switch k.Algorithm {
		case 1, 3, 6, 12:
			retired = append(retired, AlgorithmName(k.Algorithm))
		case 5, 7:
			weak = append(weak, AlgorithmName(k.Algorithm))
		}
	}
	return retired, weak
}

// AlgorithmName is the name RFC 8624 lists an algorithm under, or its number
// where this does not know it — which is honest rather than a guess, and is
// what an unknown number should read as.
//
// Exported because a report shows it beside the key: an operator reading
// "algorithm 13" has to go and look it up, and the name is what their
// provider's interface calls it.
func AlgorithmName(algorithm uint8) string {
	names := map[uint8]string{
		1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1",
		7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
		12: "ECC-GOST", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
		15: "Ed25519", 16: "Ed448",
	}
	if name, known := names[algorithm]; known {
		return name
	}
	return "algorithm " + strconv.Itoa(int(algorithm))
}

// DelegationDiff compares the two lists of servers by name, and returns what
// each holds that the other does not.
//
// Exported because the scan runs it and the grade reads what it found: the
// comparison rule belongs beside the rule that grades it, and a scanner, a
// printer and a page each folding names their own way is three chances for one
// report to say "the same servers" beside a finding that says otherwise.
//
// By name and not by address, because the delegation is a list of names: two
// names pointing at one address are two entries a resolver treats separately,
// and one name whose address changed is still the same delegation. The
// comparison folds case and a trailing dot, which are spellings of a name
// rather than different names.
func DelegationDiff(zone []NameServer, parent []string) (onlyAtParent, onlyAtZone []string) {
	named := map[string]bool{}
	for _, ns := range zone {
		named[normalName(ns.Name)] = true
	}
	delegated := map[string]bool{}
	for _, host := range parent {
		delegated[normalName(host)] = true
	}

	for _, host := range parent {
		if !named[normalName(host)] {
			onlyAtParent = append(onlyAtParent, host)
		}
	}
	for _, ns := range zone {
		if !delegated[normalName(ns.Name)] {
			onlyAtZone = append(onlyAtZone, ns.Name)
		}
	}
	return onlyAtParent, onlyAtZone
}

// normalName is a host name in the one spelling this compares by.
func normalName(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// serverSerial is one server's answer about which copy of the zone it holds.
type serverSerial struct {
	name   string
	serial uint32
}

// serialsOf collects the serials the servers answered with, and says whether
// they are all the same.
//
// Only the servers that answered are in it. A server nobody could ask holds no
// opinion about the zone, and counting it as agreeing would turn a silence into
// a measurement (R4).
func serialsOf(servers []NameServer) (agreed bool, serials []serverSerial) {
	for _, ns := range servers {
		if ns.SerialRead {
			serials = append(serials, serverSerial{ns.Name, ns.Serial})
		}
	}

	agreed = true
	for _, s := range serials {
		if s.serial != serials[0].serial {
			agreed = false
			break
		}
	}
	return agreed, serials
}

// transfersOf sorts the servers by what asking them for the zone established:
// the ones that began handing it over, and the ones where the question did not
// complete.
//
// A server nobody could ask is kept apart from one that refused, because a
// question that failed is not a zone that is closed (R4). A server that
// refused is in neither list: that is the ordinary answer and the report says
// nothing about it.
func transfersOf(servers []NameServer) (open, unread []string) {
	for _, ns := range servers {
		switch {
		case ns.TransferAsked && ns.Transfer:
			open = append(open, ns.Name)
		case !ns.TransferAsked && ns.TransferReason != "":
			unread = append(unread, ns.Name)
		}
	}
	return open, unread
}

// glueDiff compares what the zone above hands out as each server's address
// with what the zone itself publishes for the same name.
//
// Two lists and not one count, because the two directions are different
// faults. An address only the parent hands out is one a resolver dials and the
// zone no longer claims — the one that sends visitors to whatever is there
// now. An address only the zone publishes is one no resolver starting at the
// root will ever use, which is the multi-homed case RFC 1912 §2.3 states as a
// requirement.
//
// Only servers whose glue was actually read are compared, and only where the
// zone's own addresses were read too: a lookup that failed is not an address
// that disagrees (R4). Each entry names the server, so a reader knows where to
// go and change it.
func glueDiff(servers []NameServer) (stale, missing []string) {
	for _, ns := range servers {
		if !ns.GlueRead || ns.Reason != "" {
			continue
		}

		published := map[string]bool{}
		for _, addr := range ns.Addresses {
			published[addr] = true
		}
		handed := map[string]bool{}
		for _, addr := range ns.Glue {
			handed[addr] = true
		}

		for _, addr := range ns.Glue {
			if !published[addr] {
				stale = append(stale, addr+" for "+ns.Name)
			}
		}
		for _, addr := range ns.Addresses {
			if !handed[addr] {
				missing = append(missing, addr+" for "+ns.Name)
			}
		}
	}
	return stale, missing
}
