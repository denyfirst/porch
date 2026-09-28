package securitytxt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// What is read out of the file is counts and one date, and never a contact.
//
// A contact is an address a person published, and a report is a thing people
// paste into issue trackers. The operator's question is whether there is a way
// to reach them and whether it has expired; neither answer needs anybody's
// address, so there is no field here that could carry one. The same
// arrangement that keeps a cookie's value out of a report.
func TestWhatIsReadIsCountedAndNotKept(t *testing.T) {
	got := parse(strings.Join([]string{
		"# a comment",
		"Contact: mailto:security@example.test",
		"Contact: https://example.test/report",
		"Expires: 2027-01-31T23:59:00.000Z",
		"Preferred-Languages: en, az",
		"",
	}, "\n"), false)

	if !got.Served || got.Contacts != 2 {
		t.Errorf("two contacts were published and this read %d (served=%v)", got.Contacts, got.Served)
	}
	want := time.Date(2027, 1, 31, 23, 59, 0, 0, time.UTC)
	if !got.Expires.Equal(want) {
		t.Errorf("the expiry read as %v, not %v", got.Expires, want)
	}
	if got.Signed {
		t.Error("an unsigned file was read as signed")
	}

	// The thing that must not be possible. Every string this struct carries is
	// checked for the address that was in the file: a field added later with
	// somewhere to put one would fail here rather than in somebody's report.
	for _, s := range []string{got.Reason} {
		if strings.Contains(s, "security@example.test") || strings.Contains(s, "example.test/report") {
			t.Errorf("a published contact reached the facts: %q", s)
		}
	}
}

// An absent expiry, an unreadable one and a valid one are three different
// facts, and none of them is the others.
//
// RFC 9116 §2.5.5 requires the field. A file without one has not said when it
// stops being true, and a file whose date cannot be read has said something
// that cannot be acted on — reporting either as "no expiry" would flatten a
// fault into an absence, and reporting either as expired would invent one.
func TestTheThreeThingsAnExpiryCanBe(t *testing.T) {
	none := parse("Contact: mailto:a@example.test\n", false)
	if !none.Expires.IsZero() || none.ExpiresUnreadable {
		t.Errorf("a file with no expiry read as %+v", none)
	}

	junk := parse("Contact: mailto:a@example.test\nExpires: next Tuesday\n", false)
	if !junk.ExpiresUnreadable || !junk.Expires.IsZero() {
		t.Errorf("an unreadable expiry read as %+v", junk)
	}

	// Two expiry fields are not a later expiry. RFC 9116 allows exactly one,
	// and taking the second would be this project choosing on the operator's
	// behalf — always in the direction that flatters them.
	two := parse("Expires: 2020-01-01T00:00:00Z\nExpires: 2099-01-01T00:00:00Z\n", false)
	if got := two.Expires.Year(); got != 2020 {
		t.Errorf("with two expiry fields the year read as %d, so the later one won", got)
	}
}

// A signature is noticed and nothing inside it is read as a field.
//
// A PGP signature block is base64, and base64 holds colons. Read line by line
// without stopping at the block, a signature turns into fields — and a file
// whose signature happened to contain "Contact:" would be reported as naming
// contacts nobody published.
func TestASignatureIsNotReadAsFields(t *testing.T) {
	got := parse(strings.Join([]string{
		"-----BEGIN PGP SIGNED MESSAGE-----",
		"Hash: SHA256",
		"",
		"Contact: mailto:a@example.test",
		"Expires: 2027-01-01T00:00:00Z",
		"-----BEGIN PGP SIGNATURE-----",
		"",
		"Contact: mailto:nobody@example.test",
		"iQIzBAEBCgAdFiEE:not/a:field+at+all",
		"-----END PGP SIGNATURE-----",
		"",
	}, "\n"), false)

	if !got.Signed {
		t.Error("a cleartext-signed file was not read as signed")
	}
	if got.Contacts != 1 {
		t.Errorf("the signature block was read as fields: %d contacts", got.Contacts)
	}
}

// A server that has no security.txt has said so, and that is not a failure.
//
// The three outcomes are different and a report says which: the file is there,
// the server answered that it has none, or nothing answered at all. A caller
// that could not tell the second from the third would be reading a network
// problem as a decision the operator made (R4).
func TestTheThreeKindsOfNothing(t *testing.T) {
	absent := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	if got := absent; !got.Asked || got.Served || got.Reason != "" {
		t.Errorf("a 404 read as %+v, and it means the site publishes none", got)
	}

	unreachable := (&Fetcher{
		Client:    &http.Client{Timeout: time.Second},
		UserAgent: "test",
	}).Fetch(context.Background(), "localhost.invalid")
	if !unreachable.Asked || unreachable.Served || unreachable.Reason == "" {
		t.Errorf("an unreachable host read as %+v, which does not say the question went unanswered", unreachable)
	}
	// And the reason says the shape of the failure without naming the host or
	// quoting what Go said about it (I6).
	if strings.Contains(unreachable.Reason, "localhost.invalid") || strings.Contains(unreachable.Reason, "lookup") {
		t.Errorf("the reason echoes the input or the library: %q", unreachable.Reason)
	}

	never := Facts{}
	if never.Asked {
		t.Error("the zero value claims the question was put")
	}
}

// A host cannot make this carry an unbounded file.
//
// This is text chosen by whoever is being measured, and the only bound that
// holds is the one applied while reading rather than after.
func TestAFileLongerThanTheBoundIsRefused(t *testing.T) {
	got := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		line := "Contact: mailto:a@example.test\n"
		for n := 0; n < (maxBody/len(line))+64; n++ {
			if _, err := w.Write([]byte(line)); err != nil {
				return
			}
		}
	})
	if got.Served || got.Reason == "" {
		t.Errorf("an oversized file read as %+v rather than being refused", got)
	}
}

// The request goes to the one address RFC 9116 defines, over HTTPS, and says
// who is asking.
func TestWhatIsAskedFor(t *testing.T) {
	var path, agent, scheme string
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		path, agent = r.URL.Path, r.Header.Get("User-Agent")
		if r.TLS != nil {
			scheme = "https"
		}
		http.NotFound(w, r)
	})

	if path != "/.well-known/security.txt" {
		t.Errorf("the request went to %q", path)
	}
	if agent != "porch-test" {
		t.Errorf("the request named itself %q", agent)
	}
	if scheme != "https" {
		t.Error("the request was not made over TLS, and a contact read in the clear is one anybody on the path can rewrite")
	}
}

// Expired says whether the date has passed, and says when it cannot tell.
func TestExpiredSaysWhenItCannotTell(t *testing.T) {
	at := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)

	gone, known := Facts{Expires: at.Add(-time.Hour)}.Expired(at)
	if !known || !gone {
		t.Errorf("a date an hour in the past read as expired=%v known=%v", gone, known)
	}
	standing, known := Facts{Expires: at.Add(time.Hour)}.Expired(at)
	if !known || standing {
		t.Errorf("a date an hour in the future read as expired=%v known=%v", standing, known)
	}
	if _, known := (Facts{}).Expired(at); known {
		t.Error("a file with no date was answered about as though it had one")
	}
}

// serve runs one request against a TLS server the fetcher trusts, and returns
// what was read.
func serve(t *testing.T, h http.HandlerFunc) Facts {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("reading the test address: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	// The fetcher builds the address on 443, so the test's port is put back by
	// the dialler rather than by changing what is fetched: what address this
	// asks for is the thing under test.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	}}
	f := &Fetcher{Client: client, UserAgent: "porch-test", Timeout: 5 * time.Second}
	return f.Fetch(context.Background(), host)
}

// The addresses are kept only where the caller asked, and the count is there
// either way.
//
// A contact is published for strangers to read and is still a person's
// address, so a deployment scanning names nobody proved anything about does
// not carry one into a report a stranger asked for. What the operator gets in
// return for asking is the question a count cannot answer: two contacts and
// two contacts are the same number whether they reach the security team or
// somebody who left, and that is what somebody reading their own file is
// checking.
func TestTheAddressesAreKeptOnlyWhereTheCallerAsked(t *testing.T) {
	file := strings.Join([]string{
		"Contact: mailto:security@example.test",
		"Contact: https://example.test/report",
		"Expires: 2027-01-31T23:59:00Z",
		"",
	}, "\n")

	withheld := parse(file, false)
	if withheld.Contacts != 2 {
		t.Errorf("the count is %d whether or not the addresses are kept, want 2", withheld.Contacts)
	}
	if len(withheld.ContactList) != 0 {
		t.Errorf("an address was kept by a caller that did not ask: %v", withheld.ContactList)
	}

	kept := parse(file, true)
	if kept.Contacts != 2 || len(kept.ContactList) != 2 {
		t.Fatalf("the file read as %+v", kept)
	}
	for i, want := range []string{"mailto:security@example.test", "https://example.test/report"} {
		if kept.ContactList[i] != want {
			t.Errorf("contact %d is %q, want %q", i, kept.ContactList[i], want)
		}
	}
}

// A file naming more contacts than anybody reads is bounded, and the count
// still says how many there were.
//
// The count is what makes the bound honest: a list of eight under a count of
// forty says both what was kept and what was not, where a bounded list alone
// would read as the whole file (R4).
func TestTheContactsKeptAreBoundedAndTheCountIsNot(t *testing.T) {
	var lines []string
	for i := 0; i < maxContacts+5; i++ {
		lines = append(lines, fmt.Sprintf("Contact: mailto:a%d@example.test", i))
	}

	got := parse(strings.Join(lines, "\n"), true)
	if got.Contacts != maxContacts+5 {
		t.Errorf("%d contacts were counted, want %d", got.Contacts, maxContacts+5)
	}
	if len(got.ContactList) != maxContacts {
		t.Errorf("%d addresses were kept, want %d", len(got.ContactList), maxContacts)
	}
}

// What a contact carries is stripped before it is kept.
//
// The value is written by whoever is being measured and reaches a terminal. An
// escape sequence in it is a report that can move the cursor, and a very long
// one is a line nobody can read.
func TestAContactIsCleanedBeforeItIsKept(t *testing.T) {
	got := parse("Contact: mailto:a@example.test\x1b[2Jcleared\n", true)
	if len(got.ContactList) != 1 {
		t.Fatalf("the file read as %+v", got)
	}
	if strings.ContainsRune(got.ContactList[0], 0x1b) {
		t.Errorf("an escape survived into the report: %q", got.ContactList[0])
	}

	long := parse("Contact: mailto:"+strings.Repeat("a", 400)+"@example.test\n", true)
	if len(long.ContactList[0]) > maxContact {
		t.Errorf("a contact of %d characters was kept", len(long.ContactList[0]))
	}
}
