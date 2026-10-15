package webscan

import (
	"testing"

	"github.com/denyfirst/porch/internal/leaks"
	"github.com/denyfirst/porch/internal/policy"
)

// A served file reaches the findings, the verdict and a declared row; nothing
// served reaches only the row.
func TestAServedSecretIsGradedAndShown(t *testing.T) {
	out := &Result{Verdict: policy.Strong}
	withLeaks(out, leaks.Result{Asked: true, Paths: 11,
		Exposed: []leaks.Exposed{{Path: "/.env", What: "an environment file", Kind: leaks.Secrets}}})
	if out.Verdict != policy.Insecure || len(out.Findings) != 1 || out.Findings[0].RuleID != "web.exposed-secrets" {
		t.Errorf("graded %q with %+v", out.Verdict, out.Findings)
	}
	if len(out.Declared) != 1 || out.Declared[0].Label != policy.LeaksLabel || out.Declared[0].Says != "/.env is served" {
		t.Errorf("the rows read %+v", out.Declared)
	}

	clean := &Result{Verdict: policy.Strong}
	withLeaks(clean, leaks.Result{Asked: true, Paths: 11})
	if clean.Verdict != policy.Strong || len(clean.Findings) != 0 || clean.Declared[0].Says != "none of the 11 checked is served" {
		t.Errorf("nothing served reads %q, %+v, %+v", clean.Verdict, clean.Findings, clean.Declared)
	}
}

// The row carries every path asked, with what came back, so its count says
// what it counted; a row where nothing was established carries no list.
func TestTheLeaksRowListsEveryPathAsked(t *testing.T) {
	out := &Result{}
	withLeaks(out, leaks.Result{Asked: true, Paths: len(leaks.Files), Unanswered: 1,
		NoAnswer: []string{"/.htpasswd"},
		Exposed:  []leaks.Exposed{{Path: "/.env", What: "an environment file", Kind: leaks.Secrets}}})
	checked := out.Declared[0].Checked
	if len(checked) != len(leaks.Files) {
		t.Fatalf("the row lists %d paths, want %d", len(checked), len(leaks.Files))
	}
	for i, c := range checked {
		if c.Item != leaks.Files[i].Path || c.What != leaks.Files[i].What {
			t.Errorf("item %d is %+v, out of the list's order", i, c)
		}
		switch c.Item {
		case "/.env":
			if c.State != "served" || !c.Found {
				t.Errorf("the served file reads %+v", c)
			}
		case "/.htpasswd":
			if c.State != "no answer" || c.Found {
				t.Errorf("the unanswered path reads %+v", c)
			}
		default:
			if c.State != "not served" || c.Found {
				t.Errorf("%s reads %+v", c.Item, c)
			}
		}
	}

	unreached := &Result{}
	withLeaks(unreached, leaks.Result{Asked: true, Paths: 11, Reason: "the site could not be reached over HTTPS"})
	if len(unreached.Declared) != 1 || len(unreached.Declared[0].Checked) != 0 {
		t.Errorf("a site not reached lists %+v", unreached.Declared)
	}
}
