package webprobe

import (
	"context"
	"net/http"
	"strings"
)

// CORSOrigin is the site the second request for a page says it comes from.
//
// A name under .invalid, which RFC 6761 reserves so that it can never be
// registered or resolve. A server that names it back has not recognised a
// partner it trusts, because there is no such partner: it can only have
// copied what it was sent, and a server that copies this copies anybody's.
const CORSOrigin = "https://porch-cors-check.invalid"

// CORSFacts is how the page a visitor lands on answered a request saying it
// came from an unrelated site.
//
// Two answers and no header values. Whether the server named the origin back
// is decided by comparing against this program's own text, and a value kept
// would be text chosen by whoever is being measured, for no fact the two
// answers do not already carry.
type CORSFacts struct {
	// Asked reports that the question was put. It is put only where a page
	// was reached over TLS: a host that answered nothing there has no page to
	// ask about.
	Asked bool `json:"asked"`

	// Origin is what the request said it came from, recorded so that a
	// report says how it was obtained rather than requiring the reader to
	// trust a document.
	Origin string `json:"origin,omitempty"`

	// Answered reports that a response came back.
	Answered bool `json:"answered,omitempty"`

	// Reflected reports that Access-Control-Allow-Origin named the origin
	// sent, exactly and alone, which is the only form a browser accepts.
	Reflected bool `json:"reflected,omitempty"`

	// Credentials reports that Access-Control-Allow-Credentials was true,
	// exactly and alone, which is the only form a browser accepts.
	Credentials bool `json:"credentials,omitempty"`

	// Reason says why there is no answer, where there is none.
	Reason string `json:"reason,omitempty"`
}

// notAnsweredAgain is said when the page answered the first request and not
// the second. One phrase for every cause: the page was reached moments ago,
// so whatever stopped the second request is not a fact about where the site
// is, and the row is about whom it trusts.
const notAnsweredAgain = "the page did not answer a second time, so this was not established"

// cors asks the page a visitor lands on once more, saying the request comes
// from CORSOrigin, and reads the two headers that decide whether a browser
// would hand that site the answer.
//
// The page is the last one reached over TLS without a failure, the response
// the header rules read, so what this finds is about the page those rules
// describe. Nothing new is dialled: the address was reached moments ago, by a
// chain that asked whatever decides what this deployment may reach (N9). The
// answer is not followed and its body is not read.
//
// One request, because one answers it. A server that copies the origin it is
// sent copies any origin, and trying a list of look-alikes — the site's own
// name with a suffix, a null origin — would be searching for a weakness
// rather than measuring a configuration, which is a different tool.
func (p *Prober) cors(ctx context.Context, client *http.Client, secure *Chain) CORSFacts {
	page := lastSecure(secure)
	if page == nil {
		return CORSFacts{}
	}

	out := CORSFacts{Asked: true, Origin: CORSOrigin}

	// No guard for a deadline already passed. The transport refuses a request
	// on an expired context before it dials, so nothing reaches the site either
	// way, and the failure below is then read against the scan's clock — the
	// reasoning, and the sabotage that proved it, beside security.txt in Probe.
	reqCtx, cancel := context.WithTimeout(ctx, p.requestTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, page.target, nil)
	if err != nil {
		out.Reason = notAnsweredAgain
		return out
	}
	req.Header.Set("User-Agent", p.userAgent())
	req.Header.Set("Origin", CORSOrigin)

	resp, err := client.Do(req)
	if err != nil {
		// The scan's own clock rather than the site, where the scan's clock
		// is what ran out. Asked of the scan's deadline, not this request's:
		// a page that takes longer than one request may is the site's answer.
		if ranOut(ctx) {
			out.Reason = outOfTime
			return out
		}
		out.Reason = notAnsweredAgain
		return out
	}

	// Closed unread, which drops the connection rather than draining it: the
	// headers are the whole answer, and the body is the page already fetched.
	_ = resp.Body.Close()

	out.Answered = true
	out.Reflected = alone(resp.Header.Values("Access-Control-Allow-Origin")) == CORSOrigin
	out.Credentials = alone(resp.Header.Values("Access-Control-Allow-Credentials")) == "true"
	return out
}

// alone is the value of a header sent exactly once, without the whitespace a
// browser strips, or empty.
//
// A browser fails a CORS check on a repeated header: the values are joined
// with a comma, and the joined text matches neither an origin nor "true". The
// comparison is exact for the same reason — Fetch compares bytes, so a server
// that answers "True" or a capitalised origin shares nothing, and a report
// that said otherwise would describe a browser that does not exist.
func alone(values []string) string {
	if len(values) != 1 {
		return ""
	}
	return strings.Trim(values[0], " \t")
}

// lastSecure is the last hop of a chain that was made over TLS and answered.
//
// The same choice webscan makes for the header rules, so that this and they
// describe one response.
func lastSecure(c *Chain) *Hop {
	if c == nil {
		return nil
	}
	for i := len(c.Hops) - 1; i >= 0; i-- {
		if h := &c.Hops[i]; h.TLS && h.Err == "" && h.target != "" {
			return h
		}
	}
	return nil
}
