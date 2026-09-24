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
func Declarations(f HeaderFacts, content ContentFacts, cookies []CookieFacts, sec SecurityTxtFacts, now time.Time) []Declaration {
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

	// Last, because it is the one row that is not about the response a visitor
	// landed on. It cost the only other request this check makes.
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
