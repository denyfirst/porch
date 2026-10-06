// Package promises holds what denyfirst undertakes as an organisation, and
// what each product adds.
//
// The organisation's list is about its own conduct and names no product. A
// product adds narrower undertakings of its own and never rewords the
// organisation's. Each text is written once, here, and the pages render it.
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
		ID:      "nothing-reaches-us",
		Says:    "Nothing we publish reports back to us: no telemetry, no update checks, no crash reports, no licence checks.",
		Checked: "The source is public. It contains no address of ours that a program connects to.",
	},
	{
		ID:      "no-register-of-users",
		Says:    "You need no account with us, and we keep no list of who runs our tools.",
		Checked: "There is nothing to sign up for. A release is a set of files and a signature.",
	},
	{
		ID:      "nothing-from-third-parties",
		Says:    "Our pages load nothing from anywhere else: no analytics, no external fonts, no CDN, no tags.",
		Checked: "Your browser's network panel shows every request going only to the server you are reading.",
	},
	{
		ID:      "checkable-rather-than-believed",
		Says:    "You can check what we publish instead of trusting it. The source is public, releases are signed, and anyone can rebuild a release to the same bytes.",
		Checked: "Each product publishes its release steps with its source. A public workflow rebuilds every release and compares the hashes.",
	},
	{
		ID:      "a-product-may-only-promise-less",
		Says:    "Where we run a service, it says exactly what it keeps. A product may keep less than this list allows, never more, and may not reword these.",
		Checked: "Each product lists its additions on its own page. The texts are written once in the source, and a test fails if a product rewords one of these.",
	},
	{
		ID:      "faults-have-an-address",
		Says:    "Security problems can be reported to a published address that says when it expires.",
		Checked: "https://denyfirst.dev/.well-known/security.txt (RFC 9116) names the contact and the expiry date.",
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
var Porch = Product{
	Name: "Porch",
	What: "Checks TLS, websites, mail and DNS, and grades what it finds.",
	Adds: []Promise{
		{
			ID: "porch-keeps-no-record-of-a-scan",
			Says: "Porch never records who asked for a scan. What was scanned is kept only where the person running it chooses: " +
				"on their own disk, or sealed under their password. The demonstration keeps only the latest report " +
				"of each check of its own hosts, in memory, for fifteen minutes.",
			Checked: "No code can write down who asked, and a test fails if any appears. The public counter is only a number.",
		},
		{
			ID:      "porch-reads-and-does-not-touch",
			Says:    "A scan only reads what a server already offers. It sends no login attempts, no exploits, no malformed packets and no mail.",
			Checked: "The method pages list every connection a scan makes.",
		},
		{
			ID:      "porch-builds-from-its-own-source-alone",
			Says:    "Porch has no third-party code: only its own source and Go's standard library.",
			Checked: "go.mod has no require block, so a build fetches nothing but the Go toolchain. docs/releasing.md is the release procedure.",
		},
		{
			ID:      "porch-says-what-it-did-not-measure",
			Says:    "A report says which questions got no answer, so silence never reads as a pass.",
			Checked: "Every row is shown, answered or not, and says why it is empty.",
		},
		{
			ID:      "porch-refuses-to-be-pointed-inward",
			Says:    "Porch refuses private, loopback, link-local and reserved addresses, including ones reached through a redirect.",
			Checked: "internal/safedial checks the address of every connection where it is made.",
		},
	},
}

// Products is every product this page knows of.
//
// One entry, for now, and the list exists rather than the single value because
// the argument for splitting these apart was that a second product is coming.
// A list of one is the shape that survives the second.
var Products = []Product{Porch}
