// Package wellknown names every address under /.well-known this project asks
// for, every address it serves, and the document that defines each one.
//
// # Why a list exists at all
//
// N7 draws one line: no address this program invents, and no request that
// could change state. `/admin` is on the wrong side of it because this program
// would have invented it — nobody said it was there, a GET of it can change
// something on a real application, and a stream of such requests is the
// signature of an attack in the scanned party's logs.
//
// A well-known URI is on the other side. RFC 8615 created the space as the
// register of addresses a server offers to anyone who asks; IANA keeps the
// list; each entry is defined by its own document. Fetching one is using the
// door the standard built.
//
// That distinction only holds while the list is short and every entry has a
// document behind it. Kept here rather than in the packages that fetch them,
// because three constants in three packages is not a list — it is three
// decisions nobody made together, and the fourth is the one that arrives
// without being noticed.
package wellknown

// Path is one address under /.well-known, and what this project does with it.
//
// The two directions are fields rather than two lists. They were two lists for
// one day, on 2026-09-24, and stopped being two the moment the next change
// landed: security.txt is published by this project *and* asked of the sites it
// scans, and a shape that cannot say both would have made somebody choose the
// half that fit. An address can be both. What it cannot be is neither.
type Path struct {
	// Path is the address as it is written, with its leading slash.
	Path string

	// Document is the standard that defines it, or this project where the
	// address is its own.
	Document string

	// Asked says why this project requests it of somebody else's server.
	// Empty where it never does, and N7 is about the entries where it is not.
	Asked string

	// Serves says why this project answers at it on its own site. Empty where
	// it does not. Nothing here is a request made of anybody.
	Serves string
}

// Paths is every address under /.well-known this project touches, in either
// direction.
//
// Adding one is a decision, and the test beside this refuses any address in
// the source that is not here.
var Paths = []Path{
	{
		Path:     "/.well-known/mta-sts.txt",
		Document: "RFC 8461",
		Asked: "The policy a zone announces for its mail. It is fetched because the zone published a " +
			"record saying it is there, so the zone asked for it to be read.",
	},
	{
		Path:     "/.well-known/porch-challenge",
		Document: "this project, docs/scope.md",
		Asked: "The file half of proof of control. Whoever publishes it is asking this installation to " +
			"read it, which is the whole of what it is for.",
	},
	{
		Path:     "/.well-known/security.txt",
		Document: "RFC 9116",
		Asked: "Whether a site publishes a way to report a fault in it, and whether that way has " +
			"expired. The file exists in order to be read by strangers — that is what it is for — " +
			"which makes it the clearest case N7 allows.",
		Serves: "Where to report a security problem in this project, published so that somebody who " +
			"finds one does not have to guess.",
	},
}

// Requested is the addresses this project asks other people's servers for.
func Requested() []Path {
	var out []Path
	for _, p := range Paths {
		if p.Asked != "" {
			out = append(out, p)
		}
	}
	return out
}

// Served is the addresses this project answers at on its own site.
func Served() []Path {
	var out []Path
	for _, p := range Paths {
		if p.Serves != "" {
			out = append(out, p)
		}
	}
	return out
}

// Covers says whether an address is one this project decided on, in either
// direction.
func Covers(path string) bool {
	for _, p := range Paths {
		if p.Path == path {
			return true
		}
	}
	return false
}
