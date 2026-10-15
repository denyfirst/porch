// Package announce reads which software a server names about itself, and
// keeps the names and nothing else.
//
// A web server's Server and X-Powered-By headers, and a mail server's
// greeting, often say what answered and which version of it. Which version is
// the part an operator usually did not mean to publish, and it is the part
// this package never keeps: a report is pasted into issue trackers and sent to
// people, and a version copied into it would be publishing the operator's
// patch level a second time. What is kept is the name, where it was said, and
// whether a version came with it — enough to say what to turn off, and
// nothing a reader looking for a known flaw could use that the server does not
// already hand them.
//
// Names are kept only in a fixed shape. A web product name is a token of
// letters, digits and a little punctuation, bounded in length; a mail server
// is named only from a fixed list, because a greeting is free text and a name
// read out of free text is a guess.
package announce

import (
	"net/http"
	"regexp"
	"strings"
)

// Software is one thing a server named about itself.
type Software struct {
	// Name is the product as the server named it, for a web product, or as
	// this package's list names it, for a mail server.
	Name string `json:"name"`

	// Where is the header that named it, or "greeting".
	Where string `json:"where"`

	// Versioned reports that a version came with the name. The version itself
	// is not kept; see the package comment.
	Versioned bool `json:"versioned,omitempty"`
}

// Greeting is the Where of a mail server's greeting.
const Greeting = "greeting"

const (
	// maxProducts bounds what one header can add to a report. A Server header
	// listing ten modules is somebody's build, and the first few say which
	// software answered.
	maxProducts = 4

	// maxValues bounds the repeated headers read.
	maxValues = 2
)

// product is the shape of a name kept from a header: a letter first, then a
// token's characters, short enough to be a name.
var product = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]{0,39}$`)

// FromHeaders reads the headers of one response.
//
// Server and X-Powered-By are read as RFC 9110 reads Server: products of the
// form name/version, separated by spaces, with comments in parentheses, which
// are skipped because they are where an operating system and its modules go.
// X-AspNet-Version and X-AspNetMvc-Version carry nothing but a version, so
// their name is the header's.
func FromHeaders(h http.Header) []Software {
	var out []Software
	for _, where := range []string{"Server", "X-Powered-By"} {
		values := h.Values(where)
		if len(values) > maxValues {
			values = values[:maxValues]
		}
		var found []Software
		for _, v := range values {
			for _, part := range strings.Split(v, ",") {
				found = append(found, products(part, where)...)
			}
		}
		if len(found) > maxProducts {
			found = found[:maxProducts]
		}
		out = append(out, found...)
	}
	for _, fixed := range []struct{ header, name string }{
		{"X-AspNet-Version", "ASP.NET"},
		{"X-AspNetMvc-Version", "ASP.NET MVC"},
	} {
		if v := h.Get(fixed.header); v != "" {
			out = append(out, Software{Name: fixed.name, Where: fixed.header, Versioned: hasDigit(v)})
		}
	}
	return out
}

// products reads the products in one header value.
func products(value, where string) []Software {
	var out []Software
	depth := 0
	for _, field := range strings.Fields(value) {
		// Comments, which may nest, and may start or end mid-field. Counted
		// rather than matched, because a parenthesis left open by a server is
		// a comment that runs to the end, and reading what follows as a name
		// would be reading the server's free text as one.
		opens, closes := strings.Count(field, "("), strings.Count(field, ")")
		if depth > 0 || opens > 0 {
			depth += opens - closes
			if depth < 0 {
				depth = 0
			}
			continue
		}

		name, version, _ := strings.Cut(field, "/")

		// "Apache 2.4.41", a version standing as a field of its own, belongs
		// to the name before it.
		if startsWithDigit(name) {
			if len(out) > 0 && hasDigit(name) {
				out[len(out)-1].Versioned = true
			}
			continue
		}
		if !product.MatchString(name) {
			continue
		}
		out = append(out, Software{Name: name, Where: where, Versioned: hasDigit(version)})
	}
	return out
}

// mailServers are the mail servers a greeting is read for, and the names a
// report gives them. Matched as whole words, case aside.
var mailServers = []struct {
	pattern, name string
}{
	{`postfix`, "Postfix"},
	{`exim`, "Exim"},
	{`sendmail`, "Sendmail"},
	{`microsoft esmtp mail service`, "Microsoft Exchange"},
	{`opensmtpd`, "OpenSMTPD"},
	{`haraka`, "Haraka"},
	{`qmail`, "qmail"},
	{`zimbra`, "Zimbra"},
	{`mdaemon`, "MDaemon"},
	{`hmailserver`, "hMailServer"},
	{`kerio connect`, "Kerio Connect"},
	{`communigate pro`, "CommuniGate Pro"},
	{`smartermail`, "SmarterMail"},
	{`axigen`, "Axigen"},
	{`mailenable`, "MailEnable"},
	{`icewarp`, "IceWarp"},
}

// mailPatterns are mailServers compiled: the name as a whole word, then
// whatever version follows it — "Exim 4.96", "Sendmail 8.17.1/8.17.1",
// "Microsoft ESMTP MAIL Service, Version: 10.0.17763.1".
var mailPatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(mailServers))
	for i, m := range mailServers {
		out[i] = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])` + m.pattern +
			`(?:$|[^a-z0-9])(?:[\s/,:]*(?:version:?\s*|v)?(\d+(?:\.\d+)+))?`)
	}
	return out
}()

// FromGreeting reads the lines of a mail server's greeting.
//
// The first word is skipped. RFC 5321 puts the server's own name there, and a
// server called exim.example.com has said what it is called, not what it runs.
func FromGreeting(lines []string) []Software {
	if len(lines) == 0 {
		return nil
	}
	text := strings.Join(lines, " ")
	if _, rest, ok := strings.Cut(strings.TrimSpace(text), " "); ok {
		text = rest
	} else {
		return nil
	}

	var out []Software
	for i, re := range mailPatterns {
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		out = append(out, Software{Name: mailServers[i].name, Where: Greeting, Versioned: m[1] != ""})
	}
	return out
}

func hasDigit(s string) bool {
	return strings.ContainsAny(s, "0123456789")
}

func startsWithDigit(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}
