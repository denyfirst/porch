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

// Path is one address under /.well-known, and why it is here.
type Path struct {
	// Path is the address as it is requested, with its leading slash.
	Path string

	// Document is the standard that defines it, or this project where the
	// address is its own.
	Document string

	// Why says what asking for it establishes.
	Why string
}

// Requested is every address under /.well-known this project asks of somebody
// else's server. N7 is about this list and no other.
//
// Adding one is a decision, and the test beside this refuses any address in the
// source that is in neither list.
var Requested = []Path{
	{
		Path:     "/.well-known/mta-sts.txt",
		Document: "RFC 8461",
		Why: "The policy a zone announces for its mail. It is fetched because the zone published a " +
			"record saying it is there, so the zone asked for it to be read.",
	},
	{
		Path:     "/.well-known/porch-challenge",
		Document: "this project, docs/scope.md",
		Why: "The file half of proof of control. Whoever publishes it is asking this installation to " +
			"read it, which is the whole of what it is for.",
	},
}

// Served is every address under /.well-known this project's own site answers
// at.
//
// The other direction, and kept beside the first because the two are easy to
// confuse in a search of the source and impossible to confuse in what they
// mean. Nothing here is a request made of anybody: it is what this project
// publishes about itself, to be read by whoever wants it.
var Served = []Path{
	{
		Path:     "/.well-known/security.txt",
		Document: "RFC 9116",
		Why: "Where to report a security problem in this project, published so that somebody who " +
			"finds one does not have to guess. This is served rather than asked for.",
	},
}

// Covers says whether an address is one this project asks for, or one it
// serves.
func Covers(path string) bool {
	for _, list := range [][]Path{Requested, Served} {
		for _, p := range list {
			if p.Path == path {
				return true
			}
		}
	}
	return false
}
