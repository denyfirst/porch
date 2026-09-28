package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
)

// expiryMargin is how long before the Expires date these tests start failing.
//
// The point is that the date is moved by somebody who has re-read the file,
// not by whoever happens to be on call the week it lapses. Sixty days is
// enough to notice a failing build, decide the contacts are still right, and
// merge a change without hurrying.
const expiryMargin = 60 * 24 * time.Hour

// maxLifetime is the longest an Expires date may be set into the future.
//
// RFC 9116 says the value should be less than a year away. A file that
// promises a working contact address for three years is making a promise
// about a mailbox nobody has checked.
const maxLifetime = 365 * 24 * time.Hour

// denyfirstFile is one of our own contact files as a reporter receives it.
//
// On the demonstration, which serves it, that is the bytes the handler sends.
// On an installation it is served by nothing, so the file embedded for the
// demonstration is read instead — the Expires reminder then fails on every
// build, and not only on the one job that builds with the tag.
func denyfirstFile(t *testing.T, path string) string {
	t.Helper()

	file, found := denyfirstFiles[path]
	if !found {
		t.Fatalf("%s is not one of this project's own files", path)
	}
	if !demo.Enabled {
		body, err := assets.ReadFile(file.name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	w := get(t, path)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200", path, w.Code)
	}
	return w.Body.String()
}

// securityTxtFields parses the file the way a reporter's tool would: comments
// and blank lines dropped, field names lowercased, values kept in order of
// appearance.
func securityTxtFields(t *testing.T) map[string][]string {
	t.Helper()

	body := denyfirstFile(t, SecurityTxtPath)

	// RFC 9116's grammar ends every line, the last included, with a line
	// break. A file without one parses in most tools and fails in a strict
	// one, which is the tool least likely to be forgiving elsewhere.
	if !strings.HasSuffix(body, "\n") {
		t.Error("security.txt does not end with a line break; RFC 9116 ends every line with one")
	}

	fields := map[string][]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, value, found := strings.Cut(line, ":")
		if !found {
			t.Errorf("line is neither a comment nor a field: %q", line)
			continue
		}

		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if value == "" {
			t.Errorf("field %q has no value", name)
			continue
		}
		fields[name] = append(fields[name], value)
	}
	return fields
}

// An installation publishes no contact of ours, at any of the addresses the
// demonstration publishes one.
//
// Its Canonical would name another host, its reporter would be sent to people
// who cannot fix that host, its Expires date would lapse on an installation
// left on one release, and our name would answer anyone probing for copies of
// this tool. See denyfirstFiles.
func TestAnInstallationPublishesNoContactOfOurs(t *testing.T) {
	for _, path := range []string{SecurityTxtPath, "/security.txt", PGPKeyPath} {
		w := get(t, path)
		if demo.Enabled {
			if w.Code != http.StatusOK && w.Code != http.StatusMovedPermanently {
				t.Errorf("GET %s on the demonstration returned %d", path, w.Code)
			}
			continue
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on an installation returned %d, want 404", path, w.Code)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "denyfirst") {
			t.Errorf("GET %s on an installation names us: %q", path, w.Body.String())
		}
	}
}

// The file is reachable at the path RFC 9116 names, and nowhere else that
// would produce a second copy to keep in step.
func TestSecurityTxtIsServedAtTheWellKnownPath(t *testing.T) {
	if !demo.Enabled {
		t.Skip("served by the demonstration alone; TestAnInstallationPublishesNoContactOfOurs covers this build")
	}
	w := get(t, SecurityTxtPath)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200", SecurityTxtPath, w.Code)
	}

	// text/plain matters: served as anything else, a reporter's tool will not
	// read it, and a browser may offer to download a file instead of showing
	// one.
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}

	// The security headers apply here as they do everywhere else. This route
	// is new, and a route added to the table without them would be the first
	// hole in a claim the rest of the file makes.
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// Somebody looking for a way to report a problem tries the short path first.
// Answering that with a 404 costs a report.
func TestLegacySecurityTxtPathRedirects(t *testing.T) {
	if !demo.Enabled {
		t.Skip("served by the demonstration alone; TestAnInstallationPublishesNoContactOfOurs covers this build")
	}
	w := get(t, "/security.txt")

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /security.txt returned %d, want 301", w.Code)
	}
	if got := w.Header().Get("Location"); got != SecurityTxtPath {
		t.Errorf("Location = %q, want %q", got, SecurityTxtPath)
	}
}

// RFC 9116 requires Contact at least once and Expires exactly once. A second
// Expires makes the file ambiguous, and a parser that picks the later one
// reads a file that has already lapsed as current.
func TestSecurityTxtHasTheRequiredFields(t *testing.T) {
	fields := securityTxtFields(t)

	if len(fields["contact"]) == 0 {
		t.Error("no Contact field; RFC 9116 requires at least one")
	}
	if n := len(fields["expires"]); n != 1 {
		t.Errorf("%d Expires fields, want exactly 1", n)
	}

	// Canonical has to name the URL this is actually served from. A stale one
	// tells a reporter the file they are reading is a copy, which invites
	// them to go looking for an original that does not exist.
	for _, canonical := range fields["canonical"] {
		if !strings.HasSuffix(canonical, SecurityTxtPath) {
			t.Errorf("Canonical %q does not end at %s", canonical, SecurityTxtPath)
		}
		if !strings.HasPrefix(canonical, "https://") {
			t.Errorf("Canonical %q is not https", canonical)
		}
	}

	// Every contact must be a URI. A bare address is a common mistake and
	// parsers drop it silently, which leaves a file that looks complete and
	// names nobody.
	for _, contact := range fields["contact"] {
		if !strings.HasPrefix(contact, "mailto:") &&
			!strings.HasPrefix(contact, "https://") &&
			!strings.HasPrefix(contact, "tel:") {
			t.Errorf("Contact %q is not a URI; RFC 9116 requires mailto:, https: or tel:", contact)
		}
	}
}

// The date in the file is the only copy of it, and this is what moves it.
//
// An expired security.txt is worse than none at all. A parser treats it as
// stale, and a person reads it as a project that stopped paying attention —
// which is the opposite of what publishing one is for.
func TestSecurityTxtExpiryIsMovedByAPerson(t *testing.T) {
	fields := securityTxtFields(t)
	if len(fields["expires"]) != 1 {
		t.Skip("the required-fields test already reports this")
	}

	expires, err := time.Parse(time.RFC3339, fields["expires"][0])
	if err != nil {
		t.Fatalf("Expires %q is not an RFC 3339 timestamp: %v", fields["expires"][0], err)
	}

	now := time.Now().UTC()

	switch {
	case !expires.After(now):
		t.Errorf("security.txt expired on %s; re-read the contacts and move the date",
			expires.Format(time.RFC3339))

	case expires.Sub(now) < expiryMargin:
		// A reminder rather than a defect, in the same shape as policy.ReviewBy.
		t.Errorf("security.txt expires on %s, within %s; re-read the contacts and move the date",
			expires.Format(time.RFC3339), expiryMargin)

	case expires.Sub(now) > maxLifetime:
		t.Errorf("security.txt expires on %s, more than %s away; RFC 9116 asks for less than a year",
			expires.Format(time.RFC3339), maxLifetime)
	}
}

// The file names a mailbox for vulnerabilities and points a domain owner at a
// different one for exclusion requests. Mixing the two means a takedown
// request sits in a queue meant for embargoed reports, or the reverse.
func TestSecurityTxtDoesNotSendExclusionRequestsToSecurity(t *testing.T) {
	fields := securityTxtFields(t)

	for _, contact := range fields["contact"] {
		if strings.Contains(strings.ToLower(contact), "abuse@") {
			t.Error("Contact names the abuse mailbox; exclusion requests and vulnerability reports are different queues")
		}
	}
}
