//go:build !demo

package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
)

// The ordinary build reads the list the certificate names.
//
// The direction that is easy to lose. A guard written to keep the
// demonstration quiet is one `if` away from keeping everything quiet, and the
// failure would be silent: every report would say revocation was not checked,
// which is a sentence this project prints honestly in so many other situations
// that nobody would look twice.
func TestTheOrdinaryBuildReadsTheRevocationList(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var asked atomic.Bool
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked), nil)

	// And what came of it. The fetcher refuses every connection, so nothing was
	// established — and a report that said otherwise would be claiming a check
	// it did not perform, which is the one wrong answer here that matters (R4).
	if strings.Contains(out.RevocationLine, "does not name this certificate") {
		t.Errorf("the report says the list cleared this certificate after every fetch was "+
			"refused: %q", out.RevocationLine)
	}

	if !asked.Load() {
		t.Error("nothing tried to read the revocation list the certificate names. On every " +
			"deployment but the demonstration this is how revocation is established at all, " +
			"since the authorities issuing for most of the web publish no responder to staple " +
			"from")
	}
}

// The ordinary build searches, when a caller configured a searcher.
//
// The direction that is easy to lose. A guard written to keep the demonstration
// quiet is one condition away from keeping everything quiet, and the failure
// would be silent: every report would simply omit the line, which is also what a
// deployment that configured no searcher correctly does.
func TestTheOrdinaryBuildSearchesTheLogsWhenAsked(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched, searched atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), watchingSearcher{asked: &searched})

	if !searched.Load() {
		t.Error("a searcher was configured and nothing asked it. A certificate somebody else " +
			"obtained for this name is on somebody else's server and will never appear in a " +
			"handshake here; the logs are the only place it is visible")
	}
}

// And a deployment that configured none asks nobody.
func TestNoSearcherMeansNoSearch(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched atomic.Bool
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), nil)

	if out.LoggedLine != "" {
		t.Errorf("a report carries %q with no searcher configured; a sentence about the logs "+
			"from a scan that never asked them is a claim about somebody else's records",
			out.LoggedLine)
	}
}

// findingSearcher answers with the entries it was given.
type findingSearcher struct{ entries []ctsearch.Entry }

func (f findingSearcher) Search(context.Context, string) ctsearch.Result {
	return ctsearch.Result{Entries: f.entries, Distinct: len(f.entries)}
}

// The certificates the Logged line counts are listed, and only those.
//
// The line ends on "N of which are valid today and were not the one presented
// here", which asks a reader to check a list, and until 2026-09-28 no face of
// the report showed one. A count is not something anybody can check against
// what they ordered. Listed: valid today and not the one presented. Not
// listed: the one presented, whatever its serial is written as, and one that
// has expired.
func TestTheCertificatesTheLoggedLineCountsAreListed(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")
	now := time.Now()

	// The certificate the server presents, read first so its serial can be
	// logged beside the stranger's.
	var fetched atomic.Bool
	presented := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&fetched), nil)
	serial := fmt.Sprintf("%x", presented.TLS.Certificates[0].SerialNumber)

	logs := findingSearcher{entries: []ctsearch.Entry{
		{Serial: serial, Issuer: "CN=Our Authority", Names: []string{"denyfirst.dev"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)},
		{Serial: "0badc0de", Issuer: "CN=Somebody Else's Authority", Names: []string{"denyfirst.dev", "www.denyfirst.dev"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(48 * time.Hour)},
		{Serial: "0ld", Issuer: "CN=Expired", Names: []string{"denyfirst.dev"},
			NotBefore: now.Add(-400 * 24 * time.Hour), NotAfter: now.Add(-300 * 24 * time.Hour)},
	}}
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&fetched), logs)

	if len(out.LoggedUnaccounted) != 1 {
		t.Fatalf("listed %d certificates, want the one stranger's: %v", len(out.LoggedUnaccounted), out.LoggedUnaccounted)
	}
	got := out.LoggedUnaccounted[0]
	for _, want := range []string{"serial 0badc0de", "Somebody Else's Authority", "www.denyfirst.dev",
		now.Add(48 * time.Hour).UTC().Format("2006-01-02")} {
		if !strings.Contains(got, want) {
			t.Errorf("the listed certificate does not say %q: %q", want, got)
		}
	}
	if !strings.Contains(out.LoggedLine, "one of which is valid today") {
		t.Errorf("the line and the list disagree: %q beside %v", out.LoggedLine, out.LoggedUnaccounted)
	}
}
