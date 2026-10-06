package policy

// The limits of the instrument, in one place.
//
// A standing limit is true of every scan this program runs. It says nothing
// about the host in front of it, which is exactly why repeating it on every
// report is how it stops being read — and why, when it sat under the same
// heading as everything else a report could not settle, it made each scan
// look as though it had failed at something.
//
// They are declared here rather than at the places that mention them so
// that the page explaining them and the reports referring to them cannot say
// different things. That is R16's argument applied to a third renderer: one
// set of facts, however many faces read it.
//
// The identifiers are stable. They are the anchors on the page, so a report
// that points at one is pointing somewhere that will still exist.

// StandingLimit is one property of this program that no host can change.
type StandingLimit struct {
	// ID is the anchor on the page that explains it. Stable across releases.
	ID string

	// Title is the heading it appears under.
	Title string

	// Text is the sentence itself, in the words a report used to carry.
	Text string
}

// Note renders the limit as a note, so that a caller cannot write a standing
// sentence that is not one of these.
func (l StandingLimit) Note() Note { return Note{Kind: KindStanding, Text: l.Text} }

// The set. Adding one means adding it here and nowhere else; the page picks
// it up, and a test fails if a report carries a standing sentence this list
// does not contain.
//
// Nothing here names how many there are. The count is read from the list at
// render time on both faces, because a sentence saying "four" is a sentence
// that goes stale the day a fifth is written — the same defect as a change
// log section that still says "Unreleased" five releases after it shipped.
var (
	LimitFirstHop = StandingLimit{
		ID:    "first-hop-only",
		Title: "Only the first hop was measured",
		Text: "The endpoint that answered was measured. Behind a CDN, proxy or load balancer, the link " +
			"to the server behind it is not visible and may differ. A name with several addresses was " +
			"measured at one of them; each other address gets one handshake.",
	}

	LimitCipherSuitesOffered = StandingLimit{
		ID:    "cipher-suites-offered",
		Title: "Only the suites this client can offer were offered",
		// This said "Suites outside it, and SSLv2 or SSLv3, are not covered"
		// until SSL 3.0 and the export and NULL suites were asked about by
		// hand. The sentence is attached on exactly the reports where those
		// questions are put — both hang on suiteCoverageApplies — so the
		// rewritten one is true wherever it appears.
		Text: "Suites were enumerated among those Go's TLS stack implements. SSL 3.0 and the " +
			"export-grade, NULL, finite-field DHE and anonymous families were asked with a " +
			"hand-written hello, which shows whether any suite of a family is accepted, not every " +
			"one. SSLv2 and other suites are not covered. A version refused here may only share no " +
			"suite with this client.",
	}

	LimitTLS13Suites = StandingLimit{
		ID:    "tls13-suites",
		Title: "TLS 1.3 suites are asked from the registry",
		Text: "Each TLS 1.3 suite in the IANA registry is asked with a hand-written hello, because Go " +
			"cannot choose among them. Suites outside the registry are not asked. Where that hello is " +
			"not answered like the scan's own handshake, only the negotiated suite is listed and the " +
			"report says so.",
	}

	// Rewritten when the stores of four clients began to be carried. The
	// verdict still rests on one store, and that half is unchanged; what
	// changed is that the others are no longer only a warning.
	LimitOneTrustStore = StandingLimit{
		ID:    "one-trust-store",
		Title: "The verdict rests on one root store",
		Text: "Trust is checked against one root store, and the verdict rests on that store: on Linux " +
			"and other unix systems, the store of the machine that ran this scan; on Windows and " +
			"macOS, the copy of Microsoft's or Apple's store this build carries. What Mozilla, " +
			"Chrome, Microsoft and Apple make of the chain comes from copies of their stores dated in " +
			"the report. Only which roots they include, and Mozilla's distrust dates, are applied; " +
			"other conditions are named, not applied.",
	}

	// What this says was true of every build until one of them started
	// fetching revocation lists, and then it was true of one.
	//
	// It read "No certificate authority is ever asked ... revocation is read
	// only from a response the server stapled", while the same report said two
	// inches higher that the scan had fetched the authority's list and verified
	// it. A standing limit is the sentence a reader is told holds on every
	// scan, so a stale one is worse than a wrong finding: the finding is about
	// a server and this is about us.
	//
	// One text true of both builds, rather than a version each. The difference
	// between them belongs in it, because a reader arriving from a log line
	// cannot tell which installation reached them.
	LimitNoAuthorityAsked = StandingLimit{
		ID:    "no-authority-asked",
		Title: "No authority is asked about this certificate",
		Text: "No certificate authority is asked about this certificate, because the question carries " +
			"its serial number and tells the authority which certificate is being looked at. " +
			"-ask-responder turns that on, only for a domain a service has been shown control of, and " +
			"the report then says so. A response the server stapled is read, and a revocation list " +
			"the certificate names is fetched, because one list names no single certificate. Without " +
			"either, a trusted, in-date chain may still have been withdrawn.",
	}

	// "Transparency receipts are counted and not verified ... this service
	// carries no copy of that list" until a copy was carried. It is now
	// Google's signed file, verified against a key in the source, and the
	// report names its date; see internal/ctlogs for why that answers the old
	// objection rather than ignoring it.
	LimitTransparencyReceipts = StandingLimit{
		ID:    "transparency-receipts",
		Title: "Transparency receipts are checked against one browser's log list",
		Text: "Receipts are checked against Chrome's log list as it stood on the date in the report. A " +
			"receipt from a log the list does not name cannot be checked, and nothing here decides " +
			"how many receipts a browser requires.",
	}
)

// StandingLimits is the whole set, in the order the page shows them.
func StandingLimits() []StandingLimit {
	return []StandingLimit{
		// First because it bounds every other measurement on the page: what
		// answered, rather than what was asked of it.
		LimitFirstHop,
		LimitCipherSuitesOffered,
		LimitTLS13Suites,
		LimitOneTrustStore,
		LimitNoAuthorityAsked,
		LimitTransparencyReceipts,
	}
}

// IsStandingLimit reports whether a sentence is one of them.
//
// Used by the test that runs a whole scan and checks that every standing note
// it produced came from this list, which is what stops a fifth limit being
// written inline and never reaching the page that is supposed to explain it.
func IsStandingLimit(text string) bool {
	for _, l := range StandingLimits() {
		if l.Text == text {
			return true
		}
	}
	return false
}
