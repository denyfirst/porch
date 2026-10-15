package policy

import (
	"strings"
	"testing"
)

const testOrigin = "https://porch-cors-check.invalid"

// A page that names back a site that cannot exist, and lets it send the
// visitor's cookies, lets every site read it as that visitor. Nothing a site
// intends produces that, so it is graded, and as insecure: the attack is
// published and needs nothing but a page the visitor has open.
func TestAPageThatTrustsAnyOriginWithCredentialsIsInsecure(t *testing.T) {
	f := present("Content-Security-Policy")
	f.CORS = CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Reflected: true, Credentials: true}

	got := GradeHeaders(f)
	if !hasFinding(got, "headers.cors-trusts-any-origin") {
		t.Fatalf("got %v, want the page that trusts any origin graded", findingIDs(got))
	}
	if got.Verdict != Insecure {
		t.Errorf("graded %q, want insecure", got.Verdict)
	}
	for _, fd := range got.Findings {
		if fd.RuleID == "headers.cors-trusts-any-origin" && !strings.Contains(fd.Rationale, testOrigin) {
			t.Errorf("the rationale does not say what was sent: %q", fd.Rationale)
		}
	}
}

// And neither half alone is graded, nor a question that was not answered.
//
// The origin named back without credentials shares what any stranger can
// fetch, which is what * says. Credentials with any other origin is how a
// site shares with a partner it names. A question with no answer established
// nothing, and a finding there would be a measurement the report never made.
func TestOnlyBothHalvesOfTheReflectionAreGraded(t *testing.T) {
	for _, c := range []struct {
		name string
		cors CORSAnswer
	}{
		{"named back without credentials", CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Reflected: true}},
		{"credentials for another origin", CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Credentials: true}},
		{"nothing shared", CORSAnswer{Asked: true, Origin: testOrigin, Answered: true}},
		{"no answer", CORSAnswer{Asked: true, Origin: testOrigin, Reflected: true, Credentials: true, Reason: "x"}},
		{"not asked", CORSAnswer{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := present("Content-Security-Policy")
			f.CORS = c.cors
			if got := GradeHeaders(f); hasFinding(got, "headers.cors-trusts-any-origin") {
				t.Errorf("%s was graded %v", c.name, findingIDs(got))
			}
		})
	}
}

// The row says which answer the page gave, every time, including when there
// was none: a missing row reads as a question nobody asked (R4).
func TestTheRowSaysWhetherAnotherSiteWasNamedBack(t *testing.T) {
	for _, c := range []struct {
		cors CORSAnswer
		want string
	}{
		{CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Reflected: true, Credentials: true},
			testOrigin + " was named back, with credentials allowed"},
		{CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Reflected: true},
			testOrigin + " was named back, without credentials, which shares what anyone can fetch"},
		{CORSAnswer{Asked: true, Origin: testOrigin, Answered: true, Credentials: true},
			testOrigin + " was not named back"},
		{CORSAnswer{Asked: true, Origin: testOrigin, Reason: "the scan ran out of time before this was measured"},
			"the scan ran out of time before this was measured"},
		{CORSAnswer{}, "not asked"},
	} {
		f := present("Content-Security-Policy")
		f.CORS = c.cors
		var row *Declaration
		rows := Declarations(f, ContentFacts{}, nil, SecurityTxtFacts{}, IPv6Facts{}, CounterpartFacts{}, testNow)
		for i := range rows {
			if rows[i].Label == "Asked from another site" {
				row = &rows[i]
			}
		}
		if row == nil {
			t.Fatalf("no row about another site was drawn: %+v", rows)
		}
		if row.Says != c.want {
			t.Errorf("%+v reads %q, want %q", c.cors, row.Says, c.want)
		}
	}
}
