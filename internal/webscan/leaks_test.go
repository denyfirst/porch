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
