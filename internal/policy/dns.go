package policy

import (
	"strconv"
	"strings"
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
const DNSVersion = "porch-dns-v1"

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
func GradeDNS(f DNSFacts) DNSFinding {
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
		note("This name is an alias for " + f.Alias + ", and " + f.Alias + " does not exist. " +
			"The name resolves to nothing at all. Where the target is a name at a provider that " +
			"hands out unclaimed names — a bucket, an app, a page host — whoever claims it next " +
			"answers for this name, with a certificate they can obtain for it.")
	}

	if f.Apex && f.Alias != "" {
		add("dns.alias-at-zone-apex", Insecure,
			"The top of the zone is an alias",
			"RFC 1034 lets a name be an alias or carry records, never both, and RFC 2181 says the "+
				"same in one line. The top of a zone carries its start of authority and its "+
				"delegation, so an alias here contradicts them: resolvers disagree about which "+
				"answer wins, and the ones that follow the alias lose the zone's mail and its "+
				"name servers with it.",
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
			"RFC 1034 requires a zone to be served by at least two, and RFC 2182 — a best current "+
				"practice — says why: one server is one power supply, one network and one maintenance "+
				"window between a domain and everybody trying to reach it. This zone names "+
				strconv.Itoa(len(f.NameServers))+".",
			rfc1034, rfc2182)
	case f.Networks == 1:
		add("dns.name-servers-one-network", Weak,
			"Every name server answers from the same network",
			"RFC 2182 asks for servers that do not fail together: separate networks, and ideally "+
				"separate places. These "+strconv.Itoa(len(f.NameServers))+" answer from one, so whatever "+
				"takes that network out takes the domain with it — and a domain nobody can resolve is "+
				"one nobody can reach by any other route either.",
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
			"Asked for this zone directly, "+strings.Join(lame, ", ")+" answered without claiming the "+
				"zone as its own. RFC 1912 calls that a lame delegation: a resolver that tries it waits "+
				"and then tries another, so every lookup that lands there is slower, and if enough of "+
				"them are like this the zone stops resolving. A resolver reaching one working server "+
				"hides this, which is why it is asked of each server rather than of a resolver.",
			rfc1912)
	}
	if len(recursing) > 0 {
		add("dns.name-server-offers-recursion", Weak,
			"A name server this zone names answers questions about other domains",
			"Asked about a domain it has nothing to do with, "+strings.Join(recursing, ", ")+" went and "+
				"found the answer. RFC 5358 — a best current practice — says an authoritative server "+
				"should not do that: a server anybody can ask anything is one anybody can use to point "+
				"traffic at somebody else, because a small question produces a large answer sent to "+
				"whichever address asked. What it costs the operator is their own bandwidth and, once "+
				"it has been used that way, their address's reputation.",
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
				detail+" A resolver starting at the root follows the parent's list and never sees the "+
					"zone's, so a name only the parent hands out is where some lookups go — and whatever "+
					"is at that address answers them, whether or not it still holds this zone. A name "+
					"only the zone lists carries none of the traffic it was added to carry. Either way "+
					"the answer a visitor gets depends on which server their resolver tried first.",
				rfc1912)
		}
	}

	if len(aliased) > 0 {
		add("dns.name-server-is-an-alias", Weak,
			"A name server this zone names is an alias",
			"RFC 2181 says the name in a delegation must have an address record and must not be an "+
				"alias: "+strings.Join(aliased, ", ")+" is one. A resolver that follows the delegation "+
				"asks for the address at the name it was given, and what it does with the alias it finds "+
				"instead differs between implementations — which is why some resolvers reach this zone "+
				"and others do not.",
			rfc2181)
	}

	if len(unreachable) > 0 {
		add("dns.name-server-without-address", Weak,
			"A name server this zone names resolves to nothing",
			"RFC 1912 calls this a lame delegation: "+strings.Join(unreachable, ", ")+" is named as "+
				"serving this zone and has no address, so a resolver that tries it waits and then tries "+
				"another. What it costs is time on every lookup that lands there, and what it usually "+
				"means is a server decommissioned without the delegation being changed.",
			rfc1912)
	}

	// ── Graded: the chain ────────────────────────────────────────────

	switch {
	case !f.Signed:
		note("The zone is not signed: the parent holds no delegation signer for it, so DNSSEC is not in " +
			"use here. That is a choice rather than a fault, and where it is in use this check says " +
			"whether the chain holds.")
	case f.ChainReason != "":
		unsettled("The DNSSEC chain could not be checked: " + f.ChainReason)
	case len(f.Keys) == 0:
		add("dns.dnssec-no-keys", Insecure,
			"The parent anchors DNSSEC for this zone and the zone publishes no key",
			"A delegation signer at the parent tells every validating resolver that answers from this "+
				"zone are signed. With no key here nothing can be verified against it, and a validating "+
				"resolver — which is what the large public resolvers are — answers with a failure rather "+
				"than with the records. The domain is then unreachable for a large share of the internet "+
				"and fine for whoever set it up, which is why this goes unnoticed.",
			rfc4035)
	case !f.ChainMatched && !computable(f.Signers):
		// Every digest the parent holds is of a type this does not compute, so
		// the chain was not checked rather than found wanting. Reported below,
		// with the sentence R4 exists for.
	case !f.ChainMatched:
		add("dns.dnssec-chain-broken", Insecure,
			"No key this zone publishes matches the digest its parent holds",
			"The parent's delegation signer is a hash of the key this zone is supposed to sign with. "+
				"None of the keys published here hashes to it, which is what a key rotation that never "+
				"reached the registrar looks like. Every validating resolver treats the whole zone as "+
				"bogus and returns nothing at all.",
			rfc4035)
	}

	for _, ds := range f.Signers {
		if ds.DigestType == 1 && ds.Matched {
			add("dns.dnssec-sha1-digest", Weak,
				"The digest the parent holds for this zone is SHA-1",
				"RFC 8624 says SHA-1 is not to be used for new delegation signers. The chain works "+
					"today; what it costs is that its weakest link is a hash nobody would choose now, "+
					"and replacing it is a change at the registrar rather than in the zone.",
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
			"The keys published here use "+strings.Join(retired, ", ")+". A resolver that follows "+
				"RFC 8624 treats a zone signed only with one of these as unsigned or as bogus "+
				"depending on where it is, so the signatures buy nothing and may cost the zone the "+
				"answers. Replacing the key means a rollover and a new digest at the registrar.",
			rfc8624)
	}
	if len(weak) > 0 {
		add("dns.dnssec-weak-algorithm", Weak,
			"The zone signs with an algorithm RFC 8624 no longer recommends",
			"The keys published here use "+strings.Join(weak, ", ")+", which RFC 8624 marks as not "+
				"recommended for signing. Validators still accept it today; what it costs is that "+
				"the zone rests on a hash and a construction nobody would choose now, and the move "+
				"to ECDSA or Ed25519 is a rollover that has to happen eventually anyway.",
			rfc8624)
	}

	// How a signed zone proves a name does not exist. NSEC3 with anything but
	// zero iterations is what RFC 9276 — a best current practice — closed:
	// every iteration is work every resolver does on every negative answer,
	// and the secrecy it was meant to buy was measured and found absent.
	if f.NSEC3 && f.NSEC3Iterations > 0 {
		add("dns.nsec3-iterations", Weak,
			"The zone hashes absent names more than once",
			"RFC 9276 says the iteration count must be zero: additional iterations cost every "+
				"resolver that asks for a name which does not exist, they cost this zone's own "+
				"servers the same work, and they do not keep the zone's names secret — a listing "+
				"can be recovered from the hashes either way. This zone publishes "+
				strconv.Itoa(int(f.NSEC3Iterations))+".",
			rfc9276)
	}

	for _, ds := range f.Signers {
		if ds.Unsupported {
			unsettled("The parent holds a digest of a type this check does not compute (type " +
				strconv.Itoa(int(ds.DigestType)) + "), so that one was neither matched nor ruled out. " +
				"Nothing measured is not the same as nothing wrong.")
			break
		}
	}

	// ── Reported ─────────────────────────────────────────────────────

	switch {
	case f.AddressReason != "":
		unsettled("The addresses could not be read: " + f.AddressReason)
	case len(f.IPv4)+len(f.IPv6) == 0:
		note("The name itself resolves to no address. A domain used only for mail, or only for names " +
			"beneath it, is ordinary; what this says is that nothing answers at the domain on its own.")
	}

	if f.SOAFound {
		note("The zone's serial is " + strconv.FormatUint(uint64(f.SOASerial), 10) + ", it names " +
			f.SOAPrimary + " as primary, and its timers are refresh " + duration(f.SOARefresh) +
			", retry " + duration(f.SOARetry) + ", expire " + duration(f.SOAExpire) +
			", minimum " + duration(f.SOAMinimum) + ". RFC 1912 gives ranges for these and calls them " +
			"recommendations, so they are reported here and not graded.")
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
				". Immediately after a change that is ordinary and lasts as long as the transfer takes. " +
				"A difference that stays means a server is no longer receiving the zone, and a resolver " +
				"that happens to ask that one answers from the older copy — so the same name resolves " +
				"differently depending on who is asking.")
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
		note("Names that do not exist are proved absent by naming the next name that does, which " +
			"is what lets anybody list every name in this zone by asking for one that is not there " +
			"and following the answers. That is how DNSSEC worked before RFC 5155, and a zone whose " +
			"names are not secret loses nothing by it. It is not graded, because nothing requires " +
			"the hashed kind.")
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

	Text: "Almost every answer here came from the resolver this installation uses, so what is " +
		"reported is what that resolver returns today, which may be an answer it still holds from " +
		"earlier. Three questions cannot be answered that way and are put to servers directly, over " +
		"TCP on port 53, where this installation is allowed to ask them: whether each server the " +
		"zone names answers for the zone as its own; whether a server inside the domain being " +
		"checked — never one belonging to a provider — also answers questions about domains it has " +
		"nothing to do with; and, of one server of the zone above this one, which servers it hands " +
		"out for this domain. Nothing else is sent to them, and no zone transfer is attempted. That " +
		"last answer is one server's, so a zone above whose own servers disagree would be read from " +
		"whichever of them answered first. The DNSSEC chain is checked here by taking the digest " +
		"of the keys this zone publishes and comparing it with what the parent holds; whether the " +
		"signatures over every record verify is the resolver's work, and where it says it did " +
		"that, the report says so as its word rather than as this program's.",
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
