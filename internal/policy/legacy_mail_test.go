package policy

import (
	"strings"
	"testing"
)

// An exchanger that offers nothing newer than TLS 1.1 is insecure; one that
// speaks TLS 1.2 or 1.3 and still answers an old hello with an old version is
// weak, and says why it is not insecure; one that refused, or was not asked,
// or did not answer, is neither.
func TestOldTLSOnAnExchangerIsGradedByWhatItStillSpeaks(t *testing.T) {
	base := MailFacts{MXRead: true, MXHosts: []string{"a", "b", "c", "d"}, ExchangersContacted: true}

	only := base
	only.Exchangers = []ExchangerTLS{{Host: "a", Measured: true, Offered: true, Upgraded: true, Version: "TLS 1.0"}}
	got := GradeMail(only)
	if !hasRule(got.Findings, "mail.exchanger-only-legacy-tls", Insecure) {
		t.Errorf("only TLS 1.0: %+v", got.Findings)
	}

	also := base
	also.Exchangers = []ExchangerTLS{{Host: "b", Measured: true, Offered: true, Upgraded: true, Version: "TLS 1.3",
		LegacyAsked: true, LegacyAccepted: true, LegacyVersion: "TLS 1.1"}}
	got = GradeMail(also)
	if !hasRule(got.Findings, "mail.exchanger-legacy-tls", Weak) || hasRule(got.Findings, "mail.exchanger-only-legacy-tls", Insecure) {
		t.Errorf("TLS 1.3 and 1.1: %+v", got.Findings)
	}
	for _, f := range got.Findings {
		if f.RuleID == "mail.exchanger-legacy-tls" && (!strings.Contains(f.Rationale, "b (TLS 1.1)") || !strings.Contains(f.Rationale, "plain text")) {
			t.Errorf("the rationale does not name the exchanger or say why weak: %s", f.Rationale)
		}
	}

	none := base
	none.Exchangers = []ExchangerTLS{
		{Host: "c", Measured: true, Offered: true, Upgraded: true, Version: "TLS 1.3", LegacyAsked: true},
		{Host: "d", Measured: true, Offered: true, Upgraded: true, Version: "TLS 1.2", LegacyAsked: true, LegacyReason: "closed without answering"},
		{Host: "e", Measured: true, Offered: true, Upgraded: true, Version: "TLS 1.2"},
	}
	for _, f := range GradeMail(none).Findings {
		if strings.Contains(f.RuleID, "legacy-tls") {
			t.Errorf("graded %s on an exchanger that refused, was silent or was not asked", f.RuleID)
		}
	}
}

func hasRule(findings []Finding, id string, v Verdict) bool {
	for _, f := range findings {
		if f.RuleID == id && f.Verdict == v {
			return true
		}
	}
	return false
}
