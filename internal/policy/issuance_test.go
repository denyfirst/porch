package policy

import (
	"strings"
	"testing"
)

// Every state a resolver's answer can put a name in, and no two of them read
// the same.
//
// The cases below are not invented. Each was seen against a live host while
// the DNS client was being written, which is where the distinction the second
// one draws came from: microsoft.com publishes a CAA record set carrying only
// contactemail, and a report saying "CAA present" would have been true and
// useless.
func TestDescribeIssuanceSeparatesEveryState(t *testing.T) {
	cases := []struct {
		name  string
		facts IssuanceFacts
		want  string
	}{
		{
			name: "one authority",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				Authorities: []string{"letsencrypt.org"},
				FoundAt:     "denyfirst.dev", SearchedTo: "denyfirst.dev",
			},
			want: "issuance limited to letsencrypt.org (from denyfirst.dev)",
		},
		{
			name: "four authorities and separate wildcards",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{"digicert.com", "globalsign.com", "letsencrypt.org", "sectigo.com"},
				Wildcards:   []string{"sectigo.com", "digicert.com"},
				FoundAt:     "github.com", SearchedTo: "github.com",
			},
			want: "issuance limited to digicert.com, globalsign.com, letsencrypt.org and sectigo.com; " +
				"wildcards limited to sectigo.com and digicert.com (from github.com)",
		},
		{
			// The case that looks like protection and is not.
			name: "a record set that restricts nobody",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Other: 1,
				FoundAt: "microsoft.com", SearchedTo: "microsoft.com",
			},
			want: "CAA present at microsoft.com, and none of it restricts issuance",
		},
		{
			name: "nothing anywhere up the tree",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				SearchedTo: "az", SearchComplete: true,
			},
			want: "no CAA at this name or above it, searched to az",
		},
		{
			// The same empty answer, reached the other way. The walk ran out
			// of budget, so the names above it were never asked, and the
			// sentence above would be claiming an absence nobody looked for.
			name: "nothing found, but the walk stopped short",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				SearchedTo: "d.example.com", SearchComplete: false,
			},
			want: "no CAA found, but the search stopped at d.example.com before reaching the top",
		},
		{
			name: "nobody may issue",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{";"},
				FoundAt:     "locked.example", SearchedTo: "locked.example",
			},
			want: "no authority is permitted to issue (from locked.example)",
		},
		{
			// issuewild without issue leaves ordinary issuance open, which is
			// worth saying rather than leaving a reader to infer from silence.
			name: "wildcards restricted and nothing else",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Wildcards: []string{"digicert.com"},
				FoundAt:   "wild.example", SearchedTo: "wild.example",
			},
			want: "ordinary issuance is not restricted; wildcards limited to digicert.com (from wild.example)",
		},
		{
			name: "wildcards refused outright",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{"letsencrypt.org"},
				Wildcards:   []string{";"},
				FoundAt:     "nowild.example", SearchedTo: "nowild.example",
			},
			want: "issuance limited to letsencrypt.org; wildcards refused (from nowild.example)",
		},
		{
			// Not a finding about the name. No resolver, or the budget went
			// elsewhere.
			name:  "no lookup happened",
			facts: IssuanceFacts{},
			want:  "not checked",
		},
		{
			name:  "the name does not exist",
			facts: IssuanceFacts{Checked: true},
			want:  "the name does not resolve",
		},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DescribeIssuance(tc.facts)

			if got.Line != tc.want {
				t.Errorf("line is\n  %q\nwant\n  %q", got.Line, tc.want)
			}
			if len(got.Notes) == 0 {
				t.Error("no note; a line without one leaves a reader with a verdict and no reason")
			}
			if other, dup := seen[got.Line]; dup {
				t.Errorf("this reads the same as %q", other)
			}
			seen[got.Line] = tc.name
		})
	}
}

// Not checking is not a finding, and must not read like one.
func TestNotCheckedIsNotAnAccusation(t *testing.T) {
	got := DescribeIssuance(IssuanceFacts{})

	joined := strings.Join(Texts(got.Notes), " ")
	if !strings.Contains(joined, "not a finding about the name") {
		t.Errorf("the note does not say a missing lookup is not a fault: %s", joined)
	}
	for _, wrong := range []string{"any publicly trusted", "may therefore issue"} {
		if strings.Contains(joined, wrong) {
			t.Errorf("the note for an unchecked name borrows wording from a checked one: %q", wrong)
		}
	}
}

// The answer came from somewhere, and the report says where. Everything else
// this policy describes arrives in the handshake; this arrives from a resolver
// over a path nothing here authenticates, and a reader deciding how much to
// rely on it needs that.
func TestProvenanceIsAlwaysStated(t *testing.T) {
	validated := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true, Validated: true,
		Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test", SearchedTo: "x.test",
	})
	plain := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true,
		Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test", SearchedTo: "x.test",
	})

	v := strings.Join(Texts(validated.Notes), " ")
	p := strings.Join(Texts(plain.Notes), " ")

	if !strings.Contains(v, "DNSSEC-validated") {
		t.Error("a validated answer does not say so")
	}
	if !strings.Contains(v, "its claim rather than a check this service performed") {
		t.Error("a validated answer is presented as this service's own work")
	}

	// The ambiguity has to be stated. Most zones are unsigned, so an absent
	// AD bit usually means there was nothing to validate rather than that
	// validation failed, and the two are the same bit from here.
	if !strings.Contains(p, "not signed") || !strings.Contains(p, "look the same") {
		t.Errorf("an unvalidated answer does not say why the bit is ambiguous: %s", p)
	}
}

// Prevention and detection are two halves of one question, and the report puts
// them on adjacent lines. A reader told that issuance is restricted is exactly
// the reader most likely to stop there.
func TestEveryCheckedStateMentionsTransparency(t *testing.T) {
	states := []IssuanceFacts{
		{Checked: true, Exists: true, Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test"},
		{Checked: true, Exists: true, Other: 1, FoundAt: "x.test"},
		{Checked: true, Exists: true, SearchedTo: "com"},
	}

	for _, facts := range states {
		joined := strings.Join(Texts(DescribeIssuance(facts).Notes), " ")
		if !strings.Contains(joined, "transparency") {
			t.Errorf("a checked state does not mention what records issuance when a restriction fails: %s", joined)
		}
		// Not as a section "below": a report whose handshake did not complete
		// has none, and until 2026-10-25 the sentence pointed at it anyway.
		if strings.Contains(joined, "below") {
			t.Errorf("the issuance notes point at a section that may not be there: %s", joined)
		}
	}
}

// The finding a name with no CAA most needs to read.
func TestNoRecordSaysWhatFollowsFromIt(t *testing.T) {
	joined := strings.Join(Texts(DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true, SearchedTo: "az", SearchComplete: true,
	}).Notes), " ")

	for _, required := range []string{
		"Any publicly trusted certificate authority may therefore issue",
		"around a hundred",
		"mandatory for authorities since 2017",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("the note does not say %q", required)
		}
	}
}

// A walk that ran out of budget must not be reported as one that found
// nothing.
//
// The two produce the same empty record list and lead to opposite
// conclusions. CAA is inherited, so a policy on example.com governs
// a.b.c.d.example.com — and with a budget of four the walk reached only
// d.example.com and reported that any authority may issue. The sentence was a
// claim about every parent, made after visiting some of them.
func TestAnUnfinishedWalkDoesNotClaimNobodyIsRestricted(t *testing.T) {
	short := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true,
		SearchedTo: "d.example.com", SearchComplete: false,
	})

	joined := strings.Join(Texts(short.Notes), " ") + " " + short.Line
	for _, forbidden := range []string{
		"Any publicly trusted certificate authority may therefore issue",
		"no CAA at this name or above it",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("an unfinished walk said %q, which is a claim about parents it never asked", forbidden)
		}
	}
	for _, required := range []string{"stopped", "not established"} {
		if !strings.Contains(strings.ToLower(joined), required) {
			t.Errorf("an unfinished walk does not say %q, so a reader cannot tell it from a finished one", required)
		}
	}
}

// A CAA value is an authority and, optionally, parameters after it.
//
// RFC 8659 §4.2 separates them with a semicolon inside one value, and this
// list is joined with commas while the clauses around it are joined with
// semicolons. The whole value used to go in unchanged, so a real record set
// came out as
//
//	issuance limited to comodoca.com, digicert.com; cansignhttpexchanges=yes,
//	letsencrypt.org, pki.goog; cansignhttpexchanges=yes and ssl.com
//
// which a reader cannot parse and might read as naming an authority called
// cansignhttpexchanges=yes. These are the values kapitalbank.az publishes,
// read from a live scan on 2026-08-23.
func TestCAAParametersAreNotMistakenForAuthorities(t *testing.T) {
	line := describeAuthorities(IssuanceFacts{
		Checked: true, Exists: true, FoundAt: "kapitalbank.az",
		Authorities: []string{
			"comodoca.com",
			"digicert.com; cansignhttpexchanges=yes",
			"letsencrypt.org",
			"pki.goog; cansignhttpexchanges=yes",
			"ssl.com",
		},
	})

	// The parameter has to be attached to the authority it belongs to, not
	// floating between two commas.
	for _, want := range []string{
		"digicert.com (cansignhttpexchanges=yes)",
		"pki.goog (cansignhttpexchanges=yes)",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the line does not contain %q:\n  %s", want, line)
		}
	}

	// And the semicolon must not survive inside the list, where it collides
	// with the separator between clauses.
	if strings.Contains(line, "com; cansignhttpexchanges") ||
		strings.Contains(line, "goog; cansignhttpexchanges") {
		t.Errorf("a parameter is still separated from its authority by a semicolon:\n  %s", line)
	}
}

// An authority with no parameters is written plainly, and an empty value —
// which permits nobody — must not silently vanish from a list.
func TestAuthoritiesWithoutParametersAreUnchanged(t *testing.T) {
	got := readable([]string{"letsencrypt.org", "digicert.com;", " ", ";"})

	want := []string{
		"letsencrypt.org",
		"digicert.com",
		"an empty value, which names no authority",
		"an empty value, which names no authority",
	}
	if len(got) != len(want) {
		t.Fatalf("readable returned %d values, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Each authority is read with its RFC 8657 limits, and an authority is bound
// to accounts only if every property naming it names one.
//
// The record set is this project's own, as published on 2026-10-09: two
// properties for Let's Encrypt, one per account — production and the staging
// account a dry run uses.
func TestAnAuthorityIsBoundOnlyIfEveryPropertyBindsIt(t *testing.T) {
	const prod = "https://acme-v02.api.letsencrypt.org/acme/acct/3624113041"
	const staging = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/324153244"
	ours := []string{
		"letsencrypt.org; accounturi=" + prod + "; validationmethods=dns-01",
		"letsencrypt.org; accounturi=" + staging + "; validationmethods=dns-01",
	}
	got := DescribeIssuance(IssuanceFacts{Checked: true, Exists: true, SearchComplete: true,
		FoundAt: "denyfirst.dev", Authorities: ours, Wildcards: []string{";"}})
	if len(got.Bindings) != 1 {
		t.Fatalf("bindings %+v", got.Bindings)
	}
	b := got.Bindings[0]
	if b.Authority != "letsencrypt.org" || !b.Bound() || len(b.Accounts) != 2 ||
		len(b.Methods) != 1 || b.Methods[0] != "dns-01" {
		t.Errorf("our record reads as %+v", b)
	}
	notes := strings.Join(Texts(got.Notes), " ")
	if !strings.Contains(notes, "Only the accounts the record names may ask letsencrypt.org") {
		t.Errorf("the notes do not say issuance is held to our accounts: %s", notes)
	}

	// One more property without the parameter opens the authority to every
	// account it has, whatever the others say.
	opened := append(ours, "letsencrypt.org")
	got = DescribeIssuance(IssuanceFacts{Checked: true, Exists: true, SearchComplete: true,
		FoundAt: "example.com", Authorities: opened})
	if got.Bindings[0].Bound() || got.Bindings[0].Methods != nil {
		t.Errorf("a property without accounturi left the authority bound: %+v", got.Bindings[0])
	}
	if notes := strings.Join(Texts(got.Notes), " "); !strings.Contains(notes, "Any account at letsencrypt.org may ask") {
		t.Errorf("the notes do not say any account may ask: %s", notes)
	}

	// Nobody permitted is nothing to bind, and says nothing about accounts.
	none := DescribeIssuance(IssuanceFacts{Checked: true, Exists: true, SearchComplete: true,
		FoundAt: "example.com", Authorities: []string{";"}})
	if len(none.Bindings) != 0 || strings.Contains(strings.Join(Texts(none.Notes), " "), "account") {
		t.Errorf("a record permitting nobody reads as %+v", none)
	}
}

// An authority is written once, with how far it is held, and the accounts are
// named in the note rather than on the line.
//
// This project's own record set came out on 2026-10-11 as
//
//	issuance limited to letsencrypt.org (accounturi=https://acme-staging-v02…,
//	validationmethods=dns-01) and letsencrypt.org (accounturi=https://acme-v02…,
//	validationmethods=dns-01); wildcards refused (from denyfirst.dev)
//
// which is one authority, two accounts and one method, and read as noise.
func TestAnAuthorityIsWrittenOnceWithWhatItIsHeldTo(t *testing.T) {
	const prod = "https://acme-v02.api.letsencrypt.org/acme/acct/3624113041"
	const staging = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/324153244"
	got := DescribeIssuance(IssuanceFacts{Checked: true, Exists: true, SearchComplete: true,
		FoundAt: "denyfirst.dev", Wildcards: []string{";"}, Authorities: []string{
			"letsencrypt.org; accounturi=" + staging + "; validationmethods=dns-01",
			"letsencrypt.org; accounturi=" + prod + "; validationmethods=dns-01",
		}})
	const want = "issuance limited to letsencrypt.org (2 accounts, dns-01 only); wildcards refused (from denyfirst.dev)"
	if got.Line != want {
		t.Errorf("line = %q, want %q", got.Line, want)
	}
	notes := strings.Join(Texts(got.Notes), " ")
	for _, account := range []string{prod, staging} {
		if !strings.Contains(notes, account) {
			t.Errorf("the notes do not name %s: %s", account, notes)
		}
	}

	// Held only where every value holds it: one value without the parameters
	// leaves the authority open, and the line does not count accounts for it.
	// A parameter RFC 8657 does not define is kept as written.
	for values, want := range map[string]string{
		"letsencrypt.org; accounturi=" + prod + "|letsencrypt.org":    "letsencrypt.org",
		"letsencrypt.org; validationmethods=dns-01,http-01":           "letsencrypt.org (dns-01 or http-01 only)",
		"pki.goog; accounturi=" + prod + "; cansignhttpexchanges=yes": "pki.goog (1 account, cansignhttpexchanges=yes)",
		"LetsEncrypt.org|letsencrypt.org":                             "LetsEncrypt.org",
	} {
		if got := readable(strings.Split(values, "|")); len(got) != 1 || got[0] != want {
			t.Errorf("readable(%q) = %q, want %q", values, got, want)
		}
	}
}
