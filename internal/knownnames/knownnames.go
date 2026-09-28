// Package knownnames takes the names somebody already has and makes a source
// of them.
//
// # Why a source at all
//
// Every other source here goes and asks something: a transparency log, a
// register, a zone, a host, an address. This one asks nothing. It is the list
// the operator already holds — out of their own inventory, their own
// configuration management, or typed from memory — and it exists because of
// what the other six cannot do.
//
// DNS answers questions; it does not list. There is no query that says "give
// me every name under this domain", which is exactly why every source above is
// a register, a zone or a log rather than the DNS itself: each of them is
// somewhere a list is kept. A host with no publicly logged certificate, under
// a zone that refuses to transfer, in a zone that is not signed, with no
// register account configured, is a name no amount of reading will produce. It
// is not secret — anybody who knows it can look it up — but knowing it is the
// whole problem.
//
// The one place that name certainly exists is the estate's own operator. So
// they can hand it over, and everything this mode does to a name it found it
// does to a name it was given: resolves it, says what it is doing, and says
// which of the public sources also named it.
//
// # Why this is not a wordlist
//
// A wordlist tried against DNS — mail, dev, staging, old — invents names, and
// N7 draws that line. A report built from one would be about the wordlist as
// much as about the estate, and a host whose name was not in the wordlist
// would be missing from the report with nothing saying so. This takes names
// somebody states they have. MaxNames is where the difference lives.
//
// What comes back is the more useful half of the answer either way. A name the
// operator gave that no public source named is a host the outside cannot see.
// A name they gave that does not resolve is one their own records have already
// let go of.
package knownnames

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// MaxNames is how many names one list may carry.
//
// This is the line between a list and a dictionary, and holding it is the
// reason the bound exists rather than housekeeping. An estate somebody exports
// from their own inventory is in the tens or the hundreds; a file of a hundred
// thousand lines is a wordlist being tried against somebody's resolver under
// another name, which is the one thing this mode is built not to be (N7).
//
// A longer list is refused rather than cut short, because a list silently
// shortened is an inventory that is quietly incomplete (R4).
const MaxNames = 1000

// maxFileBytes bounds the file, because the bound above cannot be applied to
// one before it is read.
const maxFileBytes = 1 << 20

// maxName is the longest a name may be, from RFC 1035.
const maxName = 253

// Found is the list, cleaned and held to the domain asked about.
type Found struct {
	// Asked reports that a list was given at all. Everything below is silence
	// rather than absence without it (R4).
	Asked bool `json:"asked"`

	// Names are the names given that belong under the domain: folded, sorted,
	// and without duplicates.
	Names []string `json:"names,omitempty"`

	// Foreign is how many were given that are not under the domain asked
	// about. Counted rather than listed, as everywhere else here: a list
	// pasted out of somebody's inventory carries their other estates too, and
	// this report is about one domain.
	Foreign int `json:"foreign,omitempty"`

	// Reason says why nothing was established, where nothing was.
	Reason string `json:"reason,omitempty"`
}

// From takes a list of names and holds it to one domain.
//
// The list is untrusted in the same way every other source is. It arrives over
// the API on an installation that has one, so it is bounded, folded, stripped
// of what no name may carry and held to the label boundary before any of it is
// resolved or connected to.
func From(domain string, given []string) Found {
	domain = fold(domain)
	if domain == "" {
		return Found{Asked: true, Reason: "no domain was given"}
	}
	if len(given) > MaxNames {
		return Found{Asked: true, Reason: fmt.Sprintf(
			"a list may name up to %d hosts; a longer one is a wordlist rather than an estate",
			MaxNames)}
	}

	out := Found{Asked: true}
	seen := map[string]bool{}

	for _, raw := range given {
		name := fold(clean(raw))
		if name == "" || name == domain {
			// The domain itself is what was asked about rather than something
			// this list contributes, and it is in the inventory already.
			continue
		}
		if !under(name, domain) {
			out.Foreign++
			continue
		}
		if !plausible(name) {
			// Not a name at all. Dropped rather than counted as foreign,
			// because foreign is a statement about whose estate something is
			// and this is a statement about whether it is a host name.
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out.Names = append(out.Names, name)
	}

	sort.Strings(out.Names)
	return out
}

// ReadFile reads a list from a file: one name to a line.
//
// Blank lines and lines beginning with # are skipped, and anything after the
// first space on a line is dropped, so that a file an operator keeps with
// notes beside the names stays usable without being edited first.
func ReadFile(path string) ([]string, error) {
	file, err := os.Open(path) // #nosec G304 -- a path the operator typed on their own command line
	if err != nil {
		// The rule rather than the path (I6). A reader who typed the path has
		// it in front of them.
		return nil, errors.New("the file of names could not be opened")
	}
	defer file.Close() //nolint:errcheck // opened for reading

	return read(file)
}

func read(r io.Reader) ([]string, error) {
	var out []string

	scanner := bufio.NewScanner(io.LimitReader(r, maxFileBytes+1))
	scanner.Buffer(make([]byte, 0, 4096), maxName+1)

	seen := 0
	for scanner.Scan() {
		line := scanner.Text()
		seen += len(line) + 1
		if seen > maxFileBytes {
			return nil, fmt.Errorf("a file of names is read up to %d bytes", maxFileBytes)
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, _ := strings.Cut(line, " ")
		if name = strings.TrimSpace(name); name == "" {
			continue
		}

		if len(out) >= MaxNames {
			// Refused rather than cut, for the reason MaxNames is written
			// about.
			return nil, fmt.Errorf("a list may name up to %d hosts", MaxNames)
		}
		out = append(out, name)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("a name is at most %d characters", maxName)
		}
		return nil, errors.New("the file of names could not be read")
	}
	return out, nil
}

// under reports whether a name belongs to the domain asked about.
func under(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// plausible reports whether this could be a host name.
//
// Not a validator — the resolver is that, and a name this rejects is one
// nothing here would have resolved. It is here so that a pasted spreadsheet
// cell, a URL somebody typed, or a line of a CSV becomes a dropped line rather
// than a row in an inventory saying a host exists.
func plausible(name string) bool {
	if name == "" || len(name) > maxName || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '*':
			default:
				return false
			}
		}
	}
	return true
}

// fold is one spelling of a name, so that a name given and a name found are
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
