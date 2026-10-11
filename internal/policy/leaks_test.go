package policy

import (
	"strings"
	"testing"
)

// One finding per kind, graded by what the file gives away, each citing the
// weakness it is and naming the paths.
func TestServedSecretsAreGradedByWhatTheyGiveAway(t *testing.T) {
	got := GradeLeaks([]ServedFile{
		{Path: "/.git/HEAD", What: "a Git repository", Kind: "source"},
		{Path: "/.git/config", What: "a Git repository's settings", Kind: "source"},
		{Path: "/.env", What: "an environment file", Kind: "secrets"},
		{Path: "/.DS_Store", What: "a macOS folder index", Kind: "listing"},
	})
	if got.Verdict != Insecure || len(got.Findings) != 3 {
		t.Fatalf("graded %q with %+v", got.Verdict, got.Findings)
	}
	want := map[string]Verdict{"web.exposed-source": Insecure, "web.exposed-secrets": Insecure, "web.exposed-listing": Weak}
	for _, f := range got.Findings {
		if want[f.RuleID] != f.Verdict || f.Policy != WebVersion || len(f.References) != 1 ||
			!strings.HasPrefix(f.References[0].Label, "CWE-") {
			t.Errorf("finding %+v", f)
		}
	}
	if !strings.Contains(got.Findings[0].Rationale, "/.git/HEAD (a Git repository) and /.git/config") {
		t.Errorf("the rationale reads %q", got.Findings[0].Rationale)
	}
	if empty := GradeLeaks(nil); empty.Verdict != "" || len(empty.Findings) != 0 {
		t.Errorf("nothing served graded %+v", empty)
	}
}

// The row says what was checked, what was served, and what could not be asked.
func TestTheLeaksLineSaysWhatWasChecked(t *testing.T) {
	for _, tc := range []struct {
		served     []ServedFile
		unanswered int
		reason     string
		want       string
	}{
		{nil, 0, "", "none of the 11 checked is served"},
		{nil, 2, "", "none of the 9 checked is served; 2 could not be asked"},
		{[]ServedFile{{Path: "/.env"}}, 0, "", "/.env is served"},
		{[]ServedFile{{Path: "/.env"}, {Path: "/.git/HEAD"}}, 0, "", "/.env and /.git/HEAD are served"},
		{nil, 0, "the site could not be reached over HTTPS", "not established: the site could not be reached over HTTPS"},
	} {
		if got := LeaksLine(true, 11, tc.unanswered, tc.served, tc.reason); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
	if LeaksLine(false, 0, 0, nil, "") != "" {
		t.Error("nothing asked was described")
	}
}
