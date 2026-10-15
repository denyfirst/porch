package webscan

import (
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/announce"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/webprobe"
)

// How the page answered a site it cannot know reaches the rules and the row.
//
// Dropped on the way, every report would say the page names nobody back and
// grade nothing, about sites that hand any visitor's session to any site.
func TestHowThePageAnsweredAnotherSiteReachesTheReport(t *testing.T) {
	report := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, nil)),
		CORS: webprobe.CORSFacts{
			Asked: true, Origin: webprobe.CORSOrigin, Answered: true, Reflected: true, Credentials: true,
		},
	}
	got := GradeAt(report, time.Now())

	var found bool
	for _, f := range got.Findings {
		found = found || f.RuleID == "headers.cors-trusts-any-origin"
	}
	if !found || got.Verdict != policy.Insecure {
		t.Errorf("a page that trusts any origin with credentials graded %q with %+v", got.Verdict, got.Findings)
	}
	if row := says(t, got, "Asked from another site"); !strings.Contains(row, "named back, with credentials") {
		t.Errorf("the row reads %q", row)
	}
}

// The sentence names what this program sends, whatever the report it is
// built from says was sent: a report read back from a file is somebody's
// text, and the origin goes into a sentence.
func TestTheOriginInTheSentenceIsTheOneThisProgramSends(t *testing.T) {
	report := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, nil)),
		CORS: webprobe.CORSFacts{
			Asked: true, Origin: "https://evil.example/see-attached", Answered: true,
		},
	}
	row := says(t, GradeAt(report, time.Now()), "Asked from another site")
	if row != webprobe.CORSOrigin+" was not named back" {
		t.Errorf("the row reads %q", row)
	}
}

// What the landing response named about its software reaches the row.
func TestTheSoftwareTheResponseNamedReachesTheRow(t *testing.T) {
	h := hop(true, 200, nil)
	h.Software = []announce.Software{{Name: "nginx", Where: "Server", Versioned: true}}
	report := &webprobe.Report{Host: "example.test", Secure: chain(h)}

	if row := says(t, GradeAt(report, time.Now()), "Software named"); row != "nginx in Server, with its version" {
		t.Errorf("the row reads %q", row)
	}
}
