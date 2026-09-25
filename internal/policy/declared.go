package policy

import (
	"strconv"
	"strings"
	"time"
)

// Declaration is one thing the site said about itself, and what it said.
//
// Label and Value rather than a sentence, because these are rows: a reader runs
// an eye down them looking for the one they came for, and a paragraph cannot be
// scanned that way.
type Declaration struct {
	Label string `json:"label"`

	// Says is what it said. Not "value": internal/webscan guards the serialised
	// report against that field name, because a cookie's value must never reach
	// it, and a second meaning for the word would make the guard read as a false
	// alarm on the day it fires for the right reason.
	Says string `json:"says"`
}

// declaredHeaders are the headers a report lists, in the order a reader asks
// about them: what protects the transport, then the page, then who may read it
// from elsewhere.
//
// The probe records thirteen and the rules grade three. The other ten were
// measured on every scan and shown on none, so a report of a site that declares
// a content policy looked exactly like a report of a site that declares
// nothing — and the second is the one an operator needs to be told about.
var declaredHeaders = []struct{ label, header string }{
	{"Strict-Transport-Security", "Strict-Transport-Security"},
	{"X-Content-Type-Options", "X-Content-Type-Options"},
	{"X-Frame-Options", "X-Frame-Options"},
	{"Referrer-Policy", "Referrer-Policy"},
	{"Permissions-Policy", "Permissions-Policy"},
	{"Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy"},
	{"Cross-Origin-Embedder-Policy", "Cross-Origin-Embedder-Policy"},
	{"Cross-Origin-Resource-Policy", "Cross-Origin-Resource-Policy"},
	{"Access-Control-Allow-Origin", "Access-Control-Allow-Origin"},
}

// maxDeclared bounds a value read out of somebody else's response.
//
// A content policy runs to thousands of characters and a report is not the
// place to reproduce one. Long enough to recognise what is set, cut where it
// is not, and said to be cut — the same bound the published text records get,
// for the same reason: this is the one text in a report chosen by whoever is
// being measured.
const maxDeclared = 120

// Declarations is what the response a visitor lands on said about itself.
//
// Every row is drawn whether or not there is an answer, because a row that is
// not there reads as a question nobody asked (R4). "none" here is a
// measurement: the response was read and carried no such header.
//
// Nothing is graded. No document requires a content policy or a referrer
// policy, and R21 leaves what a site declares as something to report. What the
// rules grade is the handful of cases where a declaration contradicts itself
// or the transport it arrives on.
func Declarations(f HeaderFacts, content ContentFacts, cookies []CookieFacts, sec SecurityTxtFacts, v6 IPv6Facts, other CounterpartFacts, now time.Time) []Declaration {
	if !f.Answered {
		return nil
	}

	out := make([]Declaration, 0, len(declaredHeaders)+4)

	// What carried it, first, and reported rather than graded.
	//
	// It costs no request: the transport settled it over ALPN during the
	// handshake the scan already made, and nothing was reading it. What it is
	// worth is that a reader can see it at all — a client offering HTTP/2 and
	// being answered in HTTP/1.1 has met a decision, and the decision may be
	// anybody's: a proxy nobody remembers configuring, or an operator who
	// turned the protocol off on purpose. This project's own deployment is the
	// second — see the note beside TLSNextProto in cmd/porchd — which is why
	// this is a row and not a rule. No document requires a version of HTTP.
	out = append(out, Declaration{Label: "Served over", Says: cut(f.Protocol, maxDeclared)})

	for _, h := range declaredHeaders {
		out = append(out, Declaration{Label: h.label, Says: cut(f.Values[h.header], maxDeclared)})
	}

	// The content policy is where it is declared rather than what it says: a
	// browser applies a header and a meta element alike, the two are different
	// places to look when changing it, and the value itself is longer than a
	// row.
	out = append(out, Declaration{Label: "Content-Security-Policy", Says: contentPolicyLine(f)})
	out = append(out, Declaration{Label: "Cookies", Says: cookieLine(cookies)})
	out = append(out, Declaration{Label: "The page", Says: pageLine(content)})

	// Last, the three rows that are not about the response a visitor landed on:
	// the other form of the name, the other protocol, and the file that says how
	// to report a fault. Each cost this check its own connection, which is why
	// they are kept together and counted in one place.
	out = append(out, Declaration{Label: "The other form", Says: counterpartLine(other)})
	out = append(out, Declaration{Label: "Over IPv6", Says: ipv6Line(v6)})
	out = append(out, Declaration{Label: "Security contact", Says: securityTxtLine(sec, now)})
	return out
}

// contentPolicyLine says where a content policy was declared, and whether it
// only reports.
func contentPolicyLine(f HeaderFacts) string {
	var places []string
	if f.Present["Content-Security-Policy"] {
		places = append(places, "in a header")
	}
	if f.MetaCSP {
		places = append(places, "in the page")
	}

	switch {
	case len(places) > 0:
		return "declared " + strings.Join(places, " and ")
	case f.Present["Content-Security-Policy-Report-Only"] || f.MetaCSPReportOnly:
		return "report-only: declared, and nothing is blocked by it"
	case !f.MarkupRead:
		// The header was absent and the page was not read, so half the places
		// a policy can be declared were never looked at (R4).
		return "none in the headers, and the page was not read"
	default:
		return "none"
	}
}

// cookieLine counts the cookies the response set and how many carry each of the
// attributes a browser acts on.
func cookieLine(cookies []CookieFacts) string {
	if len(cookies) == 0 {
		return "none set"
	}

	var secure, httpOnly, sameSite int
	for _, c := range cookies {
		if c.Secure {
			secure++
		}
		if c.HTTPOnly {
			httpOnly++
		}
		if c.SameSite != "" {
			sameSite++
		}
	}

	n := strconv.Itoa(len(cookies))
	return n + " set; " + strconv.Itoa(secure) + " Secure, " +
		strconv.Itoa(httpOnly) + " HttpOnly, " + strconv.Itoa(sameSite) + " with SameSite"
}

// pageLine says whether the page was read and what it pulls in.
//
// What it pulls in is the half of a site's security nobody configures: a page
// served perfectly can still carry a script from somewhere else, and a report
// that showed only headers would call that site finished.
func pageLine(f ContentFacts) string {
	if !f.Read {
		return "not read"
	}

	plaintext := len(f.Blocking) + len(f.Passive) + len(f.Forms)
	parts := []string{"read"}
	switch {
	case plaintext == 0:
		parts = append(parts, "nothing on it arrives in the clear")
	default:
		parts = append(parts, strconv.Itoa(plaintext)+" things on it arrive in the clear")
	}
	if n := len(f.Unverified); n > 0 {
		parts = append(parts, strconv.Itoa(n)+" origins it runs code from unchecked")
	}
	if f.Truncated || f.Incomplete {
		parts = append(parts, "and only the start of it was seen")
	}
	return strings.Join(parts, ", ")
}

// cut shortens a value read out of somebody else's response, and says it did.
func cut(value string, limit int) string {
	switch {
	case value == "":
		return "none"
	case len(value) <= limit:
		return value
	default:
		return value[:limit] + "…"
	}
}

// SecurityTxtFacts is what a site published about how to report a fault in it.
//
// The same shape internal/securitytxt measures, restated here because this
// package imports nothing of the scanning machinery: a rule that depended on a
// probe would be a rule that could only be tested by making a request.
type SecurityTxtFacts struct {
	// Asked is whether the file was looked for at all. Without it everything
	// below is silence rather than absence (R4).
	Asked bool

	// Served is whether the address answered with a file.
	Served bool

	// Reason says which kind of nothing was there, where the server did not
	// simply answer that it has none.
	Reason string

	// Contacts is how many ways to report a fault the file names.
	Contacts int

	// Expires is the date the file gives for itself, zero where it gives none.
	Expires time.Time

	// ExpiresUnreadable separates a file with no expiry from one whose expiry
	// is not a date.
	ExpiresUnreadable bool

	// Signed is whether the file carries a PGP signature. Nothing verifies it.
	Signed bool
}

// securityTxtLine says whether a site publishes a way to report a fault in it,
// and whether that way still stands.
//
// Reported, never graded. RFC 9116 is a proposed standard that defines a
// format; it requires nothing of anybody who has not chosen to publish one, and
// no document says a site must. Grading its absence would be this project
// inventing a threshold, which is what R21 exists to refuse. What the row does
// is put the fact in front of the operator, because the commonest state of this
// file in the wild is neither "there" nor "absent" but "there, and expired two
// years ago" — which is worse than absent. It tells somebody who found a fault
// that they are expected at an address where nobody is waiting.
func securityTxtLine(f SecurityTxtFacts, now time.Time) string {
	switch {
	case !f.Asked:
		return "not looked for"
	case f.Reason != "":
		return f.Reason
	case !f.Served:
		return "none published"
	}

	var parts []string
	switch f.Contacts {
	case 0:
		// The one field RFC 9116 §2.5.3 requires. A file naming nobody has not
		// done the thing the file is for, and saying "published" alone would
		// read as though it had.
		parts = append(parts, "published, naming no contact")
	case 1:
		parts = append(parts, "published, 1 contact")
	default:
		parts = append(parts, "published, "+strconv.Itoa(f.Contacts)+" contacts")
	}

	switch {
	case f.ExpiresUnreadable:
		parts = append(parts, "its expiry date cannot be read")
	case f.Expires.IsZero():
		parts = append(parts, "no expiry date, which RFC 9116 requires")
	case now.After(f.Expires):
		parts = append(parts, "expired "+f.Expires.Format("2006-01-02"))
	default:
		parts = append(parts, "expires "+f.Expires.Format("2006-01-02"))
	}

	if f.Signed {
		parts = append(parts, "signed")
	}
	return strings.Join(parts, "; ")
}

// IPv6Facts is whether the site answered where it published an address for the
// newer protocol.
//
// The same shape internal/webprobe measures, restated here for the reason
// every fact type in this package is restated: a rule that imported the
// probing machinery could only be tested by making a connection.
type IPv6Facts struct {
	// Asked is whether this was measured at all.
	Asked bool

	// Published is how many IPv6 addresses the name has.
	Published int

	// Answered is whether one of them answered on 443.
	Answered bool

	// Verified is whether the certificate it presented was valid for the name.
	Verified bool

	// Reason is the shape of the failure, where there was one.
	Reason string

	// NoRouteFromHere is whether the machine running the scan has an IPv6
	// address of its own at all.
	NoRouteFromHere bool
}

// ipv6Line says whether the site answers over IPv6, and — where it does not —
// which kind of not.
//
// Reported, never graded. No document requires a site to be reachable over
// IPv6, and a great many well-run sites are not; a verdict here would be a
// threshold this project invented (R21), and it would be a loud one.
//
// The row exists because a scan could not answer the question at all. A
// dialler that tries a name's addresses until one answers is the right way to
// reach a site and the wrong way to measure one: a host whose AAAA record
// points at nothing answers every scan through its IPv4 address, reads
// perfectly, and is unreachable from a network that has only the newer
// protocol. The operator is the last to know, because their own machine has
// both.
func ipv6Line(f IPv6Facts) string {
	switch {
	case !f.Asked:
		return "not measured"
	case f.Published == 0 && f.Reason != "":
		// Nothing was looked up, so how many addresses the name publishes is
		// not known. Falling through to the line below would print "no AAAA
		// record" — a flat claim about somebody's zone that was never checked,
		// and the most confident sentence in the row would be the one with
		// nothing behind it (R4).
		//
		// Found by a test of what a scan says when it runs out of time, which
		// leaves exactly this state: asked, nothing looked up, a reason.
		return f.Reason
	case f.Published == 0:
		// Not a fault and not a silence. The zone was asked and published no
		// address, which is a decision somebody made.
		return "no address published (no AAAA record)"
	case f.NoRouteFromHere:
		// The distinction that matters most in this row. Reporting this as a
		// site that does not answer would be printing the scanner's network as
		// somebody else's fault (R4).
		return published(f.Published) + ", and this machine has no IPv6 address of its own, so nothing was measured"
	case f.Answered && f.Verified:
		return published(f.Published) + ", answers on 443, certificate valid for this name"
	case f.Answered:
		// Reachable and unusable, which is a different piece of work from
		// unreachable for whoever has to fix it.
		return published(f.Published) + ", answers on 443, " + f.Reason
	case f.Reason != "":
		return published(f.Published) + ", " + f.Reason
	default:
		return published(f.Published) + ", none of them could be tried"
	}
}

// published says how many addresses the name has, in words a row can carry.
func published(n int) string {
	if n == 1 {
		return "1 address published"
	}
	return strconv.Itoa(n) + " addresses published"
}

// CounterpartFacts is what the other form of the name does, and where the name
// that was scanned itself ended up.
//
// Both halves are needed to say whether the two forms agree, and they arrive
// from different places: one from a single response to the other form, one from
// the chain this check already followed.
type CounterpartFacts struct {
	// Asked is whether this was measured.
	Asked bool

	// Name is the other form that was compared.
	Name string

	// Refused is whether this deployment may not reach that name.
	Refused bool

	// Answered, Status and SendsTo are what the other form's one response was:
	// whether it came, what it said, and the host it points a visitor at where
	// it was a redirect.
	Answered bool
	Status   int
	SendsTo  string

	// Reason is the shape of the failure, where there was one.
	Reason string

	// Scanned is the name that was asked about, and LandsOn is the host its own
	// chain ended at — which may be the other form, in which case the two
	// agree in that direction.
	Scanned string
	LandsOn string
}

// counterpartLine says whether both forms of the name take a visitor to the
// same place.
//
// Reported, never graded. No document requires a `www` form to exist, and none
// requires one to redirect to the other: plenty of well-run sites serve only
// the bare name, and a verdict here would be a threshold this project invented
// (R21).
//
// The row exists because it is the question an operator cannot ask of their own
// site. Their own habit answers it for them — whoever types the bare name every
// day never learns what happens to somebody who types `www`, and whoever
// bookmarked `www` never learns what happens at the bare name. Both forms are in
// every visitor's muscle memory and usually only one of them has ever been
// tried.
func counterpartLine(f CounterpartFacts) string {
	switch {
	case !f.Asked:
		return "not measured"
	case f.Refused:
		return f.Name + " was not checked: this deployment may not reach it"
	case f.Reason != "":
		// A name that does not exist reads the same as one that refused the
		// connection, on purpose: the row is about whether the two forms agree,
		// and in both cases they do not.
		return f.Name + " " + f.Reason
	case !f.Answered:
		return f.Name + " did not answer"
	}

	switch {
	case f.SendsTo != "" && f.SendsTo == f.Scanned:
		return f.Name + " sends visitors to this name"
	case f.SendsTo != "" && f.LandsOn != "" && f.SendsTo == f.LandsOn:
		return f.Name + " and this name both end up at " + f.LandsOn
	case f.SendsTo != "":
		return f.Name + " sends visitors to " + f.SendsTo
	case f.LandsOn != "" && f.LandsOn == f.Name:
		return "this name sends visitors to " + f.Name
	case f.Status >= 400:
		return f.Name + " answers " + strconv.Itoa(f.Status)
	default:
		// Two names, two sites, nothing joining them. Not a fault by any
		// document — and the commonest way a visitor ends up on a copy of a
		// site that stopped being updated two years ago.
		return f.Name + " answers with its own site, and nothing sends visitors from one form to the other"
	}
}
