package httpapi

import (
	"testing"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
)

// The operator's own copy shows the operator the whole report, with or without
// a scope.
//
// The command line shows the person who ran it the page, the security.txt
// addresses, the MTA-STS policy, the exchangers, the DMARC mailboxes and what
// the zone's own servers say. A porchd only its operator can call — nobody
// else can reach it, or their password stands in front of it — is that person
// with a browser in front of the command line, and every one of those followed
// the scope alone: a rule from when a copy without one answered strangers. A
// copy that still answers strangers — reachable, no password, no scope — still
// shows only what any visitor sees.
func TestTheOperatorsOwnCopyShowsTheWholeReport(t *testing.T) {
	view := func(s *Server) map[string]bool {
		return map[string]bool{
			"page":             s.web.ReadMarkup,
			"security.txt":     s.web.ShowContacts,
			"MTA-STS policy":   s.mail.ReadSTSPolicy,
			"exchangers":       s.mail.ReadExchangers,
			"DMARC mailboxes":  s.mail.ShowReportAddresses,
			"the records":      s.mail.ShowRecords,
			"the zone servers": s.dns.AskServers,
		}
	}
	want := func(t *testing.T, s *Server, on bool, who string) {
		t.Helper()
		for what, got := range view(s) {
			if got != on {
				t.Errorf("%s: %s shown %v, want %v", who, what, got, on)
			}
		}
	}

	// A stranger's copy shows what a visitor sees — except on the
	// demonstration, whose hosts are ours; see the test named for it.
	stranger := New(offlineScanner(), Limits{}, nil)
	want(t, stranger, demo.Enabled, "a copy anybody can reach, with no password and no scope")

	loopback := New(offlineScanner(), Limits{}, nil)
	loopback.ReachableByOthers(false)
	want(t, loopback, true, "a copy nobody else can reach")

	guarded := New(offlineScanner(), Limits{}, nil)
	guarded.ReachableByOthers(true)
	guarded.BehindPassword(true)
	want(t, guarded, true, "a copy behind the operator's password")

	// And back: a copy told it is reachable after all, with no password, goes
	// back to what any visitor sees rather than keeping a wider view it was
	// given for a different answer.
	loopback.ReachableByOthers(true)
	want(t, loopback, demo.Enabled, "a copy told it is reachable after all")

	proven := New(&scan.Scanner{Verify: &verify.Scope{Secret: verificationSecret}}, Limits{}, nil)
	proven.ReachableByOthers(true)
	proven.BehindPassword(false)
	want(t, proven, true, "a copy with a scope")
}
