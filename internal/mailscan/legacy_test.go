package mailscan

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/denyfirst/porch/internal/smtptls"
)

// oldVersions answers the first conversation as each exchanger is set up to,
// and records which were asked the old-version question.
type oldVersions struct {
	fixedExchangers
	accepts map[string]string
	silent  map[string]bool

	lmu    sync.Mutex
	legacy []string
}

func (o *oldVersions) ProbeLegacy(_ context.Context, host string) smtptls.Legacy {
	o.lmu.Lock()
	o.legacy = append(o.legacy, host)
	o.lmu.Unlock()
	switch {
	case o.silent[host]:
		return smtptls.Legacy{Asked: true, Reason: "the server closed the connection without answering"}
	case o.accepts[host] != "":
		return smtptls.Legacy{Asked: true, Accepted: true, Version: o.accepts[host]}
	default:
		return smtptls.Legacy{Asked: true, Refused: true}
	}
}

// The old-version question is put only to an exchanger whose first
// conversation negotiated TLS 1.2 or 1.3: one that negotiated something older
// has answered it already, and one that did not encrypt has nothing to ask.
func TestTheOldVersionQuestionIsAskedOnlyWhereItAddsSomething(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net", "mx3.example.net", "mx4.example.net", "mx5.example.net")
	versions := map[string]string{
		"mx1.example.net": "TLS 1.3", "mx2.example.net": "TLS 1.2", "mx3.example.net": "TLS 1.0", "mx5.example.net": "TLS 1.3",
	}
	x := &oldVersions{
		accepts: map[string]string{"mx1.example.net": "TLS 1.0"},
		silent:  map[string]bool{"mx5.example.net": true},
	}
	x.answer = func(host string) smtptls.Result {
		v := versions[host]
		return smtptls.Result{Host: host, Connected: true, Measured: true, Offered: v != "", Upgraded: v != "", Version: v,
			Trusted: true, NameMatches: true}
	}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	slices.Sort(x.legacy)
	if want := []string{"mx1.example.net", "mx2.example.net", "mx5.example.net"}; !slices.Equal(x.legacy, want) {
		t.Errorf("asked %v, want %v", x.legacy, want)
	}

	by := map[string]bool{}
	for _, f := range got.Findings {
		by[f.RuleID] = true
	}
	if !by["mail.exchanger-legacy-tls"] || !by["mail.exchanger-only-legacy-tls"] {
		t.Errorf("findings %v", findingIDs(got))
	}
	for _, e := range got.Observed.Exchangers {
		switch e.Host {
		case "mx1.example.net":
			if !e.LegacyAsked || !e.LegacyAccepted || e.LegacyVersion != "TLS 1.0" {
				t.Errorf("mx1: %+v", e)
			}
		case "mx2.example.net":
			if !e.LegacyAsked || e.LegacyAccepted || e.LegacyReason != "" {
				t.Errorf("mx2: %+v", e)
			}
		case "mx5.example.net":
			if !e.LegacyAsked || e.LegacyAccepted || e.LegacyReason == "" {
				t.Errorf("a silent exchanger was read as refusing: %+v", e)
			}
		default:
			if e.LegacyAsked {
				t.Errorf("%s was asked: %+v", e.Host, e)
			}
		}
	}
}
