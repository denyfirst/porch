// Package securitytxt reads the file a site publishes to say how to report a
// fault in it.
//
// RFC 9116 defines one address, /.well-known/security.txt, and defines it as a
// document meant for strangers: its whole purpose is that somebody who finds a
// problem does not have to guess who to tell. Reading it is therefore the
// clearest case N7 allows — the address is registered rather than invented, and
// the file is published in order to be read.
//
// What is kept is deliberately not what it says. A contact is an address
// somebody chose to publish, and a report is a thing people paste into issue
// trackers; the count of them answers the operator's question — is there a way
// to reach us, and has it expired — without this project carrying anybody's
// address anywhere. The one date kept is the expiry, because a file that
// expired two years ago is worse than no file: it tells a finder they are
// expected somewhere they are not.
package securitytxt

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Path is the one address RFC 9116 defines, and there is no other. A file
// served anywhere else is not a security.txt, whatever it holds.
const Path = "/.well-known/security.txt"

const (
	// securePort is where this is fetched. RFC 9116 §3 requires HTTPS and
	// nothing else: a contact address read over plaintext is one anybody on
	// the path can rewrite, which turns the file into a way of directing
	// reports at the wrong person.
	securePort = "443"

	// maxBody bounds what a host can make this carry. The file is a handful
	// of lines, and a signed one carries a block of base64 after them. The
	// same bound the mail policy gets, for the same reason: this is text
	// chosen by whoever is being measured.
	maxBody = 64 << 10

	// maxFields bounds how many lines are counted. A file with a million
	// contact lines is not a file this project is going to describe
	// accurately, and the count is all that is kept.
	maxFields = 1000
)

// Facts is what was learned, and how much of it was learned at all.
//
// Asked separates "this was not looked for" from every other outcome, because
// a caller that had to infer the difference from an empty struct would
// eventually stop doing it (R4).
type Facts struct {
	// Asked reports that the request was made. False where the site did not
	// answer at all, and then nothing below means anything.
	Asked bool `json:"asked"`

	// Served reports that the address answered with a file. False where the
	// server said it has none, which is a measurement rather than a failure.
	Served bool `json:"served,omitempty"`

	// Reason says why nothing was read, where that was not a plain absence.
	// Empty where the file was read or where the server answered that there
	// is none.
	Reason string `json:"reason,omitempty"`

	// Contacts is how many Contact fields the file carries. RFC 9116 §2.5.3
	// requires at least one; a file with none names nobody, which is the
	// whole thing it exists to do.
	Contacts int `json:"contacts,omitempty"`

	// Expires is the date in the file's Expires field, which RFC 9116 §2.5.5
	// requires. Zero where the file carries none, or carries one that is not
	// a date.
	Expires time.Time `json:"expires,omitempty"`

	// ExpiresUnreadable separates a file with no Expires field from one whose
	// Expires field is not a date. Both leave Expires zero and they are not
	// the same fault.
	ExpiresUnreadable bool `json:"expiresUnreadable,omitempty"`

	// Signed reports a PGP cleartext signature around the file. RFC 9116
	// §2.3 makes it a SHOULD, and nothing here checks it: whether a signature
	// verifies depends on a key this project has no way to know is the right
	// one, and a report saying "signed" about a signature from anybody at all
	// would be worse than saying nothing.
	Signed bool `json:"signed,omitempty"`
}

// Fetcher reads the file over HTTPS.
type Fetcher struct {
	// Client is the HTTP client to use. Required: the caller owns which
	// destinations may be dialled, and a client built here would be a second
	// place that decides it (N6).
	Client *http.Client

	// UserAgent names this program to whoever is being asked, so that a line
	// in their log leads somewhere.
	UserAgent string

	// Timeout bounds the whole fetch. Zero means the default below.
	Timeout time.Duration
}

// Fetch asks one host for its security.txt.
//
// Every failure returns Facts rather than an error, with Reason saying which
// kind of nothing it is. A caller that had to tell an absent file from an
// unreachable one by reading an error would eventually stop doing it, and the
// two mean entirely different things to the operator: the first is a decision
// they made, the second is a question nobody answered.
func (f *Fetcher) Fetch(ctx context.Context, host string) Facts {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, securePort),
		Path:   Path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Facts{Asked: true, Reason: "the address could not be built"}
	}
	req.Header.Set("User-Agent", f.UserAgent)

	resp, err := f.Client.Do(req)
	if err != nil {
		// The shape of the failure only. Go words network errors for somebody
		// reading a terminal and names addresses doing it, and this reaches a
		// report (I6). One phrase for every cause, because the operator's next
		// step is the same in each.
		return Facts{Asked: true, Reason: "the file could not be fetched over HTTPS"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Not a failure. A server that answers 404 here has said it publishes
		// no security contact, which is a fact about the site and the one the
		// report carries.
		return Facts{Asked: true}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Facts{Asked: true, Reason: "the file could not be read"}
	}
	if len(body) > maxBody {
		return Facts{Asked: true, Reason: "the file is longer than this reads"}
	}

	return parse(string(body))
}

// parse counts what the file says without keeping any of it.
func parse(body string) Facts {
	out := Facts{Asked: true, Served: true}

	var fields int
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNED MESSAGE-----") {
			out.Signed = true
			continue
		}
		// A signature block is base64 and a colon in it would otherwise read
		// as a field. Everything from the signature to the end is skipped.
		if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----") {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if fields++; fields > maxFields {
			break
		}

		name, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		// RFC 9116 §2.4 says field names are case-insensitive.
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "contact":
			out.Contacts++
		case "expires":
			// Only the first is read. RFC 9116 §2.5.5 allows exactly one, and
			// a file with two has not said when it expires — taking the later
			// of them would be this project deciding on the operator's behalf,
			// in the direction that flatters them.
			if out.Expires.IsZero() && !out.ExpiresUnreadable {
				at, err := time.Parse(time.RFC3339, value)
				if err != nil {
					out.ExpiresUnreadable = true
					continue
				}
				out.Expires = at.UTC()
			}
		}
	}
	return out
}

// Expired says whether the file has passed the date it gave, and whether it
// gave one that can be compared at all.
func (f Facts) Expired(now time.Time) (expired, known bool) {
	if f.Expires.IsZero() {
		return false, false
	}
	return now.After(f.Expires), true
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return 10 * time.Second
}
