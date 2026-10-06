// Package passivedns reads the names a passive register has observed under a
// domain.
//
// # The only source that sees behind a wildcard
//
// A certificate log names a host only where somebody obtained a certificate
// naming it, and `*.example.com` names none of them: an estate behind one
// wildcard shows a single entry and may run a hundred hosts. A domain's own
// records name the machines its mail, its sender policy and its delegation
// have to name, and nothing else. Both are blind to a web server on a name
// nobody ever put in a certificate or an MX record.
//
// A passive register is not blind to it. Resolvers around the world write down
// the answers they saw, and a name that anything ever resolved is in there —
// which is how a host hidden behind a wildcard is found without one packet
// being sent to the estate and without one name being guessed at.
//
// # What that data is, and what it is not
//
// It is **observation, not publication**. A certificate log holds what
// somebody published on purpose; a register holds what somebody's resolver
// happened to see. Three consequences, and the report carries all three
// (N12):
//
//   - A name in here may never have existed. A typo somebody typed once, a
//     name that resolved for an hour in 2019, an internal name that leaked out
//     of a laptop on a hotel network: all of them look exactly like a host.
//     This is why what each name is doing now is asked separately and why a
//     register's name is worth less on its own than a certificate's.
//   - A name that exists may not be in here. A host nobody outside the estate
//     ever looked up was never observed by anybody's resolver.
//   - The register knows because it was watching. That is somebody else's
//     collection, and this project takes no view on it beyond saying, in the
//     report, which source named a host.
//
// # So it is off until an operator turns it on
//
// Every register worth reading wants an account, and the key is the operator's
// own: the question names their domain to a company they chose, on an account
// they hold, and the answer is billed to them. Nothing here picks one for
// them, nothing falls back to one, and a build with no register configured
// asks nobody anything.
package passivedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

// UserAgent names this tool to a register, and names the page that says what
// it does. The same shape the certificate monitors are given (N7).
const UserAgent = "porch/1 (+https://porch.denyfirst.dev/privacy#stopping)"

const (
	// defaultTimeout bounds a whole search, every page of it.
	defaultTimeout = 20 * time.Second

	// maxBody bounds one answer. Refused rather than cut: half a register's
	// answer is an inventory that is short without saying so (R4).
	maxBody = 4 << 20

	// maxNames bounds what one register may contribute. Past this the answer
	// is about the size of the estate rather than about any name in it, and
	// the report says it was cut.
	maxNames = 2000

	// maxName bounds one name. A register returns what it observed, and what
	// it observed was chosen by whoever made the query.
	maxName = 253

	// maxPages bounds how far a paged answer is followed.
	maxPages = 25
)

// Found is what a register has seen under a domain.
type Found struct {
	// Asked reports that a register was read. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Register names the one that answered, so that a reader can tell whose
	// observation this is. It is the operator's own choice and no secret.
	Register string `json:"register,omitempty"`

	// Names are the hosts under the domain, folded and sorted.
	//
	// Names only, with no dates. Registers report windows in their own terms —
	// first observed, last observed, last resolved, last modified — and the
	// four are not the same measurement. Printing one of them beside the dates
	// a certificate log gives, under a heading a reader takes as one thing,
	// would be this project inventing a meaning nobody published (R17).
	Names []string `json:"names,omitempty"`

	// Foreign is how many names the register returned that are not under this
	// domain, and were therefore dropped.
	Foreign int `json:"foreign,omitempty"`

	// Truncated is set where the register held more than this read.
	Truncated bool `json:"truncated,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// Register is a passive register that can be asked what it has observed under
// a domain.
//
// An interface with two implementations, for the reason the certificate search
// has two: a dependency described as replaceable and never replaced is a claim
// nobody has checked.
type Register interface {
	Under(ctx context.Context, domain string) Found
}

// collector gathers names under one domain, keeping only what belongs to it.
type collector struct {
	domain    string
	found     map[string]bool
	foreign   int
	truncated bool
}

func newCollector(domain string) *collector {
	return &collector{domain: domain, found: map[string]bool{}}
}

// keep takes one name the register returned.
//
// Everything a register says is untrusted input: the names are whatever
// somebody's resolver was asked for, so control characters are stripped, the
// length is bounded, and the label boundary decides whether it belongs here at
// all. A wrong name in an inventory is worse than a missing one — the missing
// one is found by the next method, and the wrong one is investigated,
// escalated and reported.
func (c *collector) keep(raw string) {
	name := fold(clean(raw))
	if !looksLikeAName(name) {
		return
	}
	if !under(name, c.domain) {
		c.foreign++
		return
	}
	if c.found[name] {
		return
	}
	if len(c.found) >= maxNames {
		c.truncated = true
		return
	}
	c.found[name] = true
}

// found turns what was kept into an answer.
func (c *collector) result(register string) Found {
	out := Found{
		Asked:     true,
		Register:  register,
		Foreign:   c.foreign,
		Truncated: c.truncated,
	}
	for name := range c.found {
		out.Names = append(out.Names, name)
	}
	sort.Strings(out.Names)
	return out
}

// looksLikeAName reports whether this is a host name at all.
//
// Stricter than stripping the characters a terminal would act on, and
// deliberately. What a register returns is whatever somebody's resolver was
// asked for, which includes text that is not a name in any sense: a URL
// somebody pasted, a sentence, a query with an escape sequence in it. None of
// that belongs in a list an operator reads down and acts on, and a name this
// cannot recognise is dropped rather than printed with its odd parts removed —
// what would be left is not the thing the register saw.
//
// Letters, digits, hyphen, dot, and the underscore that real service names
// carry (`_dmarc`, `_smtp._tls`). No wildcard: a register observes queries,
// and nothing resolves `*.example.com`.
func looksLikeAName(name string) bool {
	if name == "" || len(name) > maxName || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}

// under reports whether a name belongs to the domain asked about.
//
// The same label boundary every other source here draws. `notexample.com` ends
// with `example.com` as text and is somebody else's estate.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// fold is one spelling of a name, so that two sources naming one host produce
// one entry.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// clean bounds a name and strips what no name may carry.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxName {
		s = s[:maxName]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// registerClient builds the client every register here is read with.
//
// Built the same way the certificate monitors' is, and for the same reasons: a
// register's address is refused where it resolves to a private, loopback or
// reserved destination, the trust store is the one this project names rather
// than whatever the platform hands over (R7), no proxy is consulted, and a
// redirect is not followed — a redirect from a register is an address that
// register chose.
func registerClient(dial func(ctx context.Context, network, address string) (net.Conn, error), roots *x509.CertPool, timeout time.Duration) *http.Client {
	if dial == nil {
		d := &safedial.Dialer{Timeout: timeout, AllowedPorts: []string{"443", "80"}}
		dial = d.DialContext
	}

	resolved, _ := truststore.Resolve(roots)

	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:         dial,
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: resolved},
			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: timeout,
		},
	}
}

// reasonFor turns a register's HTTP status into this project's words.
//
// Its own sentence for each of the three an operator can act on. "Did not
// answer" for a refused key would send somebody looking for a fault in their
// network when what they need is to look at their account (I6: the message
// says what the rule is and never echoes what was sent).
func reasonFor(status int) string {
	switch status {
	case http.StatusOK:
		return ""
	case http.StatusUnauthorized, http.StatusForbidden:
		return "the passive register refused the key this installation was given"
	case http.StatusTooManyRequests:
		return "the passive register is rate limiting this search"
	case http.StatusNotFound:
		// Not an error and not an empty estate either: the register holds
		// nothing under this name. Said as what it is.
		return ""
	}
	return "the passive register did not answer the search"
}
