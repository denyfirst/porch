// Package promises holds what denyfirst undertakes as an organisation, and
// what each of its products adds on top.
//
// # Why the two are separate
//
// A privacy page that covers an organisation and a product at once cannot be
// read by either audience. Somebody deciding whether to run a tool wants to
// know what the tool does to the machine it runs on; somebody deciding whether
// to trust the people who wrote it wants to know what those people receive.
// Answering both in one page means every sentence has to be read twice to work
// out which question it belongs to, and the sentences that matter most — the
// ones about what the organisation gets — end up buried among details of a
// single check.
//
// Worse, it does not survive a second product. The organisation's undertakings
// would then exist as prose in two places, and two places drift: the day one
// is improved and the other is not, a reader has two documents from the same
// people that do not agree, which is worse evidence than one vague document.
//
// So the organisation says its part once, here, and a product inherits that
// text unchanged and adds its own restrictions below it. A product may promise
// to keep less than the organisation requires. It may never promise more, and
// it may not restate an organisation undertaking in its own words — the test
// beside this refuses an addition that reuses an organisation identifier,
// because an addition that redefines one is how a weaker promise arrives
// wearing a stronger promise's name.
//
// # What belongs here and what does not
//
// Only the organisation's own conduct: what it receives, what it holds, what it
// publishes, how what it publishes can be checked. Nothing about what any
// particular product measures.
//
// That line is not tidiness. This organisation has more than one product and
// they are built by different hands; an undertaking here that described a
// product's features would be this repository making a promise on behalf of
// code it cannot see, which is how a policy becomes untrue without anybody
// lying.
package promises

// Promise is one undertaking, and how somebody can check it rather than believe
// it.
type Promise struct {
	// ID is a stable identifier, used to say which undertaking is meant
	// without quoting it. It outlives rewording: the sentence may be improved,
	// and anything referring to it still refers to the same undertaking.
	ID string

	// Says is the undertaking, in the words it is made in.
	Says string

	// Checked is how somebody establishes it for themselves.
	//
	// Required, and the reason it is required is the whole argument of this
	// package: an undertaking nobody can check is a request to be trusted, and
	// a request to be trusted is what this organisation is trying not to make.
	Checked string
}

// Organisation is what denyfirst undertakes, whatever you run.
var Organisation = []Promise{
	{
		ID:   "nothing-reaches-us",
		Says: "Nothing published by denyfirst reports back to denyfirst. There is no telemetry, no update check, no crash report and no licence check in any of it.",
		Checked: "Every connection a copy makes is to something the person running it asked about. " +
			"The source is public, and there is no address belonging to this organisation in it that a program connects to.",
	},
	{
		ID:   "no-register-of-users",
		Says: "Using what denyfirst publishes needs no account with denyfirst, and this organisation keeps no register of who runs its tools.",
		Checked: "There is nothing to register with. A release is a set of files and a signature; " +
			"nothing is issued to a person and nothing is revoked.",
	},
	{
		ID:   "nothing-from-third-parties",
		Says: "Nothing denyfirst publishes carries third-party code. No dependency is fetched to build it, and no page loads anything from anywhere else — no analytics, no fonts, no content delivery network, no tag of any kind.",
		Checked: "go.mod carries no require block, so a build fetches nothing. " +
			"A browser's network panel on any page here shows one stylesheet and at most two scripts, all from the server you are reading.",
	},
	{
		ID:   "checkable-rather-than-believed",
		Says: "What denyfirst publishes is meant to be checked rather than believed. The source is public; a release is built on a machine that cannot sign it and signed on a machine that does not build it; and a workflow rebuilds the tag to the same bytes.",
		Checked: "docs/releasing.md is the procedure, and every step in it is there because it has gone wrong once. " +
			"The rebuild runs in public and its output is a list of hashes anybody can compare with the files they downloaded.",
	},
	{
		ID:   "a-product-may-only-promise-less",
		Says: "Where denyfirst runs a service, that service says exactly what it keeps. A product may undertake to keep less than this list requires. It may never undertake more, and it may not restate any of these in its own words.",
		Checked: "Each product's page carries this list unchanged, from one place in the source, and adds its own restrictions underneath. " +
			"A product that reworded one of these would fail its own tests.",
	},
	{
		ID:      "faults-have-an-address",
		Says:    "A fault in anything denyfirst publishes has a published address to report it to, and that address says when it stops being current.",
		Checked: "/.well-known/security.txt on this site, which RFC 9116 defines, names the contact and carries an expiry date.",
	},
}

// Product is one thing denyfirst publishes, and what it adds to the list above.
type Product struct {
	// Name is what the product is called.
	Name string

	// What is one line saying what it is for, so that a reader of the
	// organisation's page knows which product a restriction belongs to.
	What string

	// Adds are the restrictions this product takes on beyond the
	// organisation's. Each is narrower than the organisation's list, never
	// wider, and none of them may carry an organisation identifier.
	Adds []Promise
}

// Porch is what this product adds.
//
// Every one of these is narrower than an organisation undertaking rather than a
// restatement of it: they are about what a scanner does to the machine it runs
// on and to the hosts it is pointed at, which is a question the organisation's
// list does not reach.
var Porch = Product{
	Name: "Porch",
	What: "Measures how a host is reached — its TLS handshake, its web reach, its mail policy and its DNS — and grades what it finds.",
	Adds: []Promise{
		{
			ID:   "porch-keeps-no-record-of-a-scan",
			Says: "An installation keeps no record of what was scanned, by whom, or when. Not the hostname, not the address that asked, not a timestamp beyond a date.",
			Checked: "There is no code that could write one, and a test fails if any appears. " +
				"The published counter is a number with nothing behind it, which is why it can be published at all.",
		},
		{
			ID:   "porch-reads-and-does-not-touch",
			Says: "A scan reads what a server volunteers and sends nothing that could change anything. No authentication is attempted, no address is invented, no exploit or malformed packet is sent, and no mail is ever composed.",
			Checked: "The method pages list every connection a scan makes and every address it asks for, " +
				"each beside the document that defines it.",
		},
		{
			ID:      "porch-says-what-it-did-not-measure",
			Says:    "A report says which of its questions went unanswered, rather than leaving silence to read as a pass.",
			Checked: "Every row is drawn whether or not there was an answer, and each says which kind of nothing it found.",
		},
		{
			ID:      "porch-refuses-to-be-pointed-inward",
			Says:    "An installation refuses private, loopback, link-local and reserved destinations, including ones reached by following a redirect a scanned server chose.",
			Checked: "internal/safedial decides it where the connection is made, so an added entry point cannot walk around it.",
		},
	},
}

// Products is every product this page knows of.
//
// One entry, for now, and the list exists rather than the single value because
// the argument for splitting these apart was that a second product is coming.
// A list of one is the shape that survives the second.
var Products = []Product{Porch}
