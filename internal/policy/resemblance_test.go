package policy

import (
	"strings"
	"testing"
	"time"
)

// Each logged certificate says how it compares with the one presented, and
// the comparison is the authority's organisation and the set of names, not
// the intermediate that signed it: a renewal from YE2 after one from YE1 is
// the same authority.
func TestResemblanceSaysWhatMatches(t *testing.T) {
	presented := []string{"denyfirst.dev", "porch.denyfirst.dev", "mta-sts.denyfirst.dev"}
	for _, c := range []struct {
		name   string
		issuer string
		names  []string
		org    string
		want   string
	}{
		{"an early renewal from another intermediate", "C=US, O=Let's Encrypt, CN=YE2",
			[]string{"MTA-STS.denyfirst.dev.", "denyfirst.dev", "porch.denyfirst.dev"}, "Let's Encrypt",
			"the same authority and names as the one presented"},
		{"an older one for fewer names", "C=US, O=Let's Encrypt, CN=YE1",
			[]string{"denyfirst.dev"}, "Let's Encrypt",
			"the same authority as the one presented, other names"},
		{"another authority for the same names", "C=US, O=DigiCert, Inc., CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
			presented, "Let's Encrypt",
			"another authority than the one presented, the same names"},
		{"another authority and other names", "C=US, O=Google Trust Services, CN=WR1",
			[]string{"denyfirst.dev", "www.denyfirst.dev"}, "Let's Encrypt",
			"another authority and other names than the one presented"},
		{"no organisation in the issuer", "CN=Somebody Else", presented, "Let's Encrypt",
			"the same names as the one presented"},
		{"no organisation on the presented one", "C=US, O=Let's Encrypt, CN=YE1", []string{"x.denyfirst.dev"}, "",
			"other names than the one presented"},
	} {
		if got := Resemblance(c.issuer, c.names, c.org, presented); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// A value with a comma in it is one organisation, not two.
	if got := organisationOf("C=US, O=DigiCert, Inc., CN=Some CA"); got != "DigiCert, Inc." {
		t.Errorf("the organisation of a DigiCert issuer read as %q", got)
	}

	// The sentence ends on it, and a sentence with nothing to compare does not
	// grow an empty clause.
	from, until := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 7, 0, 0, 0, 0, time.UTC)
	line := UnaccountedLine("0a", "C=US, O=Let's Encrypt, CN=YE1", []string{"denyfirst.dev"}, from, until, "the same authority as the one presented, other names")
	if !strings.HasSuffix(line, "; the same authority as the one presented, other names") {
		t.Errorf("the sentence does not end on the comparison: %q", line)
	}
	if bare := UnaccountedLine("0a", "x", nil, from, until, ""); strings.Contains(bare, ";") {
		t.Errorf("a sentence with nothing to compare ends on an empty clause: %q", bare)
	}
}

// Nothing here calls a match safe: the note under the list says what a match
// also looks like.
func TestAMatchIsNotCalledSafe(t *testing.T) {
	notes := DescribeLogged(LogFacts{Searched: true, Distinct: 2, Unseen: 1})
	var all strings.Builder
	for _, n := range notes {
		all.WriteString(n.Text + " ")
	}
	text := all.String()
	for _, want := range []string{"controls this domain's DNS", "another authority is the one to ask about first"} {
		if !strings.Contains(text, want) {
			t.Errorf("the note does not say %q: %s", want, text)
		}
	}
	for _, never := range []string{"safe", "harmless", "yours"} {
		if strings.Contains(strings.ToLower(text), never) {
			t.Errorf("the note calls a certificate %q: %s", never, text)
		}
	}
}
