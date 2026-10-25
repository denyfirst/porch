package policy

import (
	"regexp"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dmarcreports"
)

// The verdict matrix: one row per situation a domain can be in, and the
// verdict each check owes it.
//
// Every rule has tests of its own. This table is the other direction: it asks
// what the whole check says about a domain, which is where a vacuous strong
// hides. Until 2026-10-23 a domain publishing nothing about its mail, and a
// zone whose delegation could not be read, both came back strong — every rule
// was correct, and each one was about something that existed.
//
// Read a row as a sentence: "a domain that ... is graded ...". A row that
// fails is a verdict that changed, which is a rule set version (R22) and a
// section in docs/policy-changes.md.

func TestTheMailVerdictMatrix(t *testing.T) {
	sound := func() MailFacts {
		f := exchangerFacts(good("mx1.example.net"))
		f.DMARCReporting = true
		return f
	}

	for _, row := range []struct {
		situation string
		facts     func() MailFacts
		want      Verdict
		rule      string
	}{
		{"publishes SPF -all, DMARC p=reject, and its exchanger encrypts",
			sound, Strong, ""},

		{"publishes no mail record of any kind",
			func() MailFacts { return MailFacts{MXRead: true} }, Weak, "mail.dmarc-absent"},

		{"has no DMARC record here or above",
			func() MailFacts { f := sound(); f.DMARCRecords, f.DMARCPolicy = 0, ""; return f }, Weak, "mail.dmarc-absent"},

		{"is covered by a parent's DMARC record at p=reject",
			func() MailFacts { f := sound(); f.DMARCFrom = "example.net"; return f }, Strong, ""},

		{"is at p=none",
			func() MailFacts { f := sound(); f.DMARCPolicy = "none"; return f }, Weak, "mail.dmarc-not-enforcing"},

		{"names a policy DMARC does not define",
			func() MailFacts { f := sound(); f.DMARCPolicy = "rejet"; return f }, Weak, "mail.dmarc-no-policy"},

		{"could not have its DMARC record read",
			func() MailFacts { f := sound(); f.DMARCRecords, f.DMARCPolicy = 0, ""; f.DMARCReason = "x"; return f }, Ungraded, ""},

		{"has an exchanger that offers no STARTTLS",
			func() MailFacts {
				f := sound()
				f.Exchangers[0].Offered, f.Exchangers[0].Upgraded = false, false
				return f
			}, Weak, "mail.exchanger-no-starttls"},

		{"has exchangers that were never contacted",
			func() MailFacts { f := sound(); f.ExchangersContacted, f.Exchangers = false, nil; return f }, Ungraded, ""},

		{"has an exchanger that timed out",
			func() MailFacts {
				f := sound()
				f.Exchangers[0] = ExchangerTLS{Host: "mx1.example.net"}
				return f
			}, Ungraded, ""},

		{"has an exchanger that offered STARTTLS and did not complete it",
			func() MailFacts { f := sound(); f.Exchangers[0].Upgraded = false; return f }, Ungraded, ""},

		// Since v6: a rule that reads a record cannot pass a record nobody read.
		{"could not have its MTA-STS record read",
			func() MailFacts { f := sound(); f.MTASTSReason = "x"; return f }, Ungraded, ""},

		{"announces an MTA-STS policy that was not read",
			func() MailFacts { f := sound(); f.MTASTSRecords = 1; f.MTASTSPolicyReason = "x"; return f }, Ungraded, ""},

		{"announces an MTA-STS policy that was read and covers its exchanger",
			func() MailFacts {
				f := sound()
				f.MTASTSRecords, f.MTASTSPolicyRead, f.MTASTSMode = 1, true, "enforce"
				f.MTASTSPolicyMX = []string{"mx1.example.net"}
				return f
			}, Strong, ""},

		{"sends reports somewhere whose consent could not be read",
			func() MailFacts {
				f := sound()
				f.DMARCReportTo = dmarcreports.Found{Asked: true, Destinations: []dmarcreports.Destination{
					{Domain: "reports.example.org", External: true, Reason: "x"}}}
				return f
			}, Ungraded, ""},

		// TLS-RPT is described and never graded, so an unread one changes no
		// verdict; it changes the sentence (TestAnUnreadRecordIsNotAnAbsentOne).
		{"could not have its TLS-RPT record read",
			func() MailFacts { f := sound(); f.TLSReportingReason = "x"; return f }, Strong, ""},
	} {
		t.Run(row.situation, func(t *testing.T) {
			got := GradeMail(row.facts())
			observationsObserved(t, got.Notes)
			if got.Verdict != row.want {
				t.Errorf("a domain that %s is graded %q with %v, want %q", row.situation, got.Verdict, mailRuleIDs(got), row.want)
			}
			if row.rule != "" && !mailHas(got, row.rule) {
				t.Errorf("a domain that %s is graded without %s: %v", row.situation, row.rule, mailRuleIDs(got))
			}
		})
	}
}

func TestTheDNSVerdictMatrix(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	served := func() DNSFacts {
		return DNSFacts{
			Apex: true,
			NameServers: []NameServer{
				{Name: "a.ns.example", Addresses: []string{"192.0.2.1"}},
				{Name: "b.ns.example", Addresses: []string{"198.51.100.1"}},
			},
			Networks: 2,
		}
	}
	signed := func() DNSFacts {
		f := served()
		f.Signed, f.ChainMatched = true, true
		f.Keys = []KeyDigest{{KeyTag: 2371, Algorithm: 13, KeySigning: true}}
		f.Signers = []DelegationSigner{{KeyTag: 2371, Algorithm: 13, DigestType: 2, Matched: true}}
		f.SignatureRead, f.SignaturesVerified = true, true
		f.SignatureInception, f.SignatureExpires = now.Add(-24*time.Hour), now.Add(14*24*time.Hour)
		return f
	}

	for _, row := range []struct {
		situation string
		facts     func() DNSFacts
		want      Verdict
		rule      string
	}{
		{"is served by two networks and signed", signed, Strong, ""},

		{"is served by two networks and not signed", served, Weak, "dns.unsigned"},

		{"could not have its delegation read",
			func() DNSFacts { f := signed(); f.NameServers, f.Networks, f.NSReason = nil, 0, "x"; return f }, Ungraded, ""},

		{"could not have its delegation signer asked for",
			func() DNSFacts { f := served(); f.ChainReason = "x"; return f }, Ungraded, ""},

		{"is signed and its signatures could not be checked",
			func() DNSFacts { f := signed(); f.SignaturesVerified, f.SignatureCheckReason = false, "x"; return f }, Ungraded, ""},

		{"has a registration that ran out yesterday",
			func() DNSFacts {
				f := signed()
				f.Registration = &RegistrationFacts{Asked: true, Expires: now.Add(-24 * time.Hour)}
				return f
			}, Insecure, "dns.registration-expired"},

		{"has a registration that runs out tomorrow",
			func() DNSFacts {
				f := signed()
				f.Registration = &RegistrationFacts{Asked: true, Expires: now.Add(24 * time.Hour)}
				return f
			}, Strong, ""},

		// Since v5: dns.registration-expired reads the registration, so one
		// asked about and not read is not passing. A registry that publishes
		// no RDAP service at all is not a question that went unanswered: no
		// scan can put it, and the report says so instead.
		{"could not have its registration read",
			func() DNSFacts {
				f := signed()
				f.Registration = &RegistrationFacts{Asked: true, Reason: "x"}
				return f
			}, Ungraded, ""},

		{"is under a registry that publishes no RDAP service",
			func() DNSFacts {
				f := signed()
				f.Registration = &RegistrationFacts{Asked: true, Reason: "x", NoService: true}
				return f
			}, Strong, ""},

		// Since v5: the rules about each server, and about the parent, read
		// answers to questions put directly; one that went unanswered is not
		// passing.
		{"has a server that did not answer when asked directly",
			func() DNSFacts { f := signed(); f.NameServers[1].AskedReason = "x"; return f }, Ungraded, ""},

		{"has a parent that did not answer",
			func() DNSFacts { f := signed(); f.ParentReason = "x"; return f }, Ungraded, ""},
	} {
		t.Run(row.situation, func(t *testing.T) {
			got := GradeDNS(row.facts(), now)
			observationsObserved(t, got.Notes)
			if got.Verdict != row.want {
				t.Errorf("a zone that %s is graded %q with %v, want %q", row.situation, got.Verdict, got.Findings, row.want)
			}
			if row.rule != "" && !hasRule(got.Findings, row.rule, got.Verdict) {
				t.Errorf("a zone that %s is graded without %s: %v", row.situation, row.rule, got.Findings)
			}
		})
	}
}

func TestTheHSTSVerdictMatrix(t *testing.T) {
	for _, row := range []struct {
		situation string
		secure    []string
		answered  bool
		want      Verdict
		rule      string
	}{
		{"sends two years with subdomains", []string{"max-age=63072000; includeSubDomains"}, true, Strong, ""},
		{"sends exactly six months", []string{"max-age=15768000"}, true, Strong, ""},
		{"sends one day", []string{"max-age=86400"}, true, Weak, "hsts.short-max-age"},
		{"withdraws its policy", []string{"max-age=0"}, true, Weak, "hsts.disabled"},
		{"sends no policy", nil, true, Weak, "hsts.absent"},
		{"did not answer over TLS", nil, false, Ungraded, ""},
	} {
		t.Run(row.situation, func(t *testing.T) {
			got := GradeHSTS(row.secure, nil, row.answered)
			observationsObserved(t, got.Notes)
			if got.Verdict != row.want {
				t.Errorf("a site that %s is graded %q with %v, want %q", row.situation, got.Verdict, webRuleIDs(got), row.want)
			}
			if row.rule != "" && !webHas(got, row.rule) {
				t.Errorf("a site that %s is graded without %s: %v", row.situation, row.rule, webRuleIDs(got))
			}
		})
	}
}

// observationsObserved fails a set of notes that files something it could not
// settle among what it established. Every row of every matrix passes through
// it: an observation is counted as measured on the report's face, and a
// sentence saying something was not established is the one thing it cannot be.
// Two such notes were found on 2026-10-25, one in the DNS check and one in the
// web check.
func observationsObserved(t *testing.T, notes []Note) {
	t.Helper()
	for _, n := range notes {
		if n.Kind == KindObserved && unsettledWording.MatchString(n.Text) {
			t.Errorf("an observation says something was not established: %q", n.Text)
		}
	}
}

var unsettledWording = regexp.MustCompile(`not established|was not read|were not read|could not be read|did not complete`)
