package scan

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// A standing limit describes what this build actually does.
//
// It is the strongest sentence in a report: findings are about one server, and
// a standing limit says what is true of every scan this program runs. So a
// stale one is the worst kind of wrong — it is wrong about us, on every report,
// and a reader has no way to check it.
//
// One went stale and shipped. "No certificate authority is ever asked ...
// revocation is read only from a response the server stapled into the
// handshake, so where none was stapled it has not been established here by any
// means" stayed word for word while an ordinary build started fetching the
// authority's revocation list — so a single report said the list had been
// fetched and verified, two inches above a limit saying nothing had been asked
// of anybody.
//
// This test lives here rather than in internal/policy because this is the
// package that does the fetching. The limit is written where the rules are; the
// behaviour it describes is here, and only something that can see both can tell
// whether they agree.
func TestTheRevocationLimitDescribesThisBuild(t *testing.T) {
	var limit policy.StandingLimit
	for _, l := range policy.StandingLimits() {
		if l.ID == "revocation-published" {
			limit = l
		}
	}
	if limit.ID == "" {
		t.Fatal("the revocation limit is no longer declared, so nothing on a report says what " +
			"revocation is read from")
	}

	text := limit.Title + " " + limit.Text

	// Every build fetches a revocation list when a certificate names one, and
	// asks the responder where a certificate names one and a scan may reach
	// the name. A limit claiming otherwise is a report contradicting itself.
	for _, want := range []string{"revocation list", "responder is asked"} {
		if !strings.Contains(text, want) {
			t.Errorf("the limit does not say %q, which this build does", want)
		}
	}

	for _, stale := range []string{
		// The sentences that went stale, in the text and the title. A
		// sabotage putting only the old title back escaped the first version
		// of this test, because the list described the paragraph and the
		// heading above it said something broader and untrue.
		"No certificate authority is asked anything",
		"read only from a response the server stapled",
		"has not been established here by any means",
		"is ever asked",
		"No authority is asked about this certificate",
		"-ask-responder",
		"compiled out",
	} {
		if strings.Contains(text, stale) {
			t.Errorf("the limit still says %q, which is not true of this build", stale)
		}
	}
}

// And the fetch it describes is really in this build.
//
// The other direction. If the fetch were removed and the limit kept, the limit
// would be describing something that no longer happens — the same defect
// pointing the other way, and the one a reader could not detect at all because
// it errs towards claiming less.
func TestThisBuildReallyFetchesWhatTheLimitDescribes(t *testing.T) {
	s := &Scanner{}

	// Every build, the demonstration included since 2026-09-28: the limit says
	// a named list is fetched, and says it of every report.
	if !s.revocationFetched() {
		t.Error("this build fetches no revocation list, and the limit on every report says it " +
			"does. A limit claiming less than the truth is one nobody can check.")
	}
}
