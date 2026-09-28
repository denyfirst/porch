package mailscan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// The records themselves reach the report where its reader is the person the
// domain belongs to, and nowhere else.
//
// The rows are sentences this program writes from what it parsed, and a
// stranger's report prints only those: a record's text is the zone's, and a
// DMARC or TLS-RPT record carries mailboxes. The owner is owed the record, which
// is what they would edit.
func TestTheRecordsReachTheirOwnerAndNobodyElse(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone()
	z.records["example.com"] = []string{"v=spf1 include:_spf.provider.example -all"}
	z.records["_smtp._tls.example.com"] = []string{"v=TLSRPTv1; rua=mailto:tls-reports@example.com"}
	z.records["_spf.provider.example"] = []string{"v=spf1 -all"}

	own, err := (&Scanner{Resolver: z, ShowRecords: true}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	f := own.Observed
	for got, want := range map[string]string{
		f.SPFRecord:    "v=spf1 include:_spf.provider.example -all",
		f.DMARCRecord:  "v=DMARC1; p=reject; rua=mailto:r@example.com",
		f.TLSRPTRecord: "v=TLSRPTv1; rua=mailto:tls-reports@example.com",
	} {
		if got != want {
			t.Errorf("the owner's report carries %q, want %q", got, want)
		}
	}

	stranger, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if g := stranger.Observed; g.SPFRecord != "" || g.DMARCRecord != "" || g.TLSRPTRecord != "" {
		t.Errorf("a stranger's report carries the zone's text: %q / %q / %q", g.SPFRecord, g.DMARCRecord, g.TLSRPTRecord)
	}
	if !stranger.Observed.TLSReporting {
		t.Error("withholding the record withheld the fact that there is one")
	}
}

// A record cannot act on the display that shows it (R10).
func TestARecordCannotActOnTheDisplay(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone()
	z.records["example.com"] = []string{"v=spf1 include:\x1b[2Kforged.example \u202e-all"}

	got, err := (&Scanner{Resolver: z, ShowRecords: true}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, s := range append([]string{got.Observed.SPFRecord}, got.Observed.SPFIncludes...) {
		if strings.ContainsAny(s, "\x1b\u202e") {
			t.Errorf("the zone's text reaches the report able to act on it: %q", s)
		}
	}
	if !strings.Contains(got.Observed.SPFRecord, "\ufffd") {
		t.Errorf("what was replaced is not marked: %q", got.Observed.SPFRecord)
	}
}

// Which SPF lookups answered nothing, and which could not be read, are named
// rather than counted.
//
// The counts told an operator that two of their lookups return nothing and not
// which two, and the fix is taking out the include that points nowhere.
func TestTheSPFLookupsThatFailAreNamed(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone()
	z.records["example.com"] = []string{"v=spf1 include:gone.example include:broken.example include:ok.example -all"}
	z.records["ok.example"] = []string{"v=spf1 -all"}
	z.fail = map[string]error{"broken.example": errors.New("the resolver did not answer")}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !slices.Equal(got.Observed.SPFVoidNames, []string{"gone.example"}) {
		t.Errorf("the void lookups are named %v", got.Observed.SPFVoidNames)
	}
	if !slices.Equal(got.Observed.SPFUnreadNames, []string{"broken.example"}) {
		t.Errorf("the unread policies are named %v", got.Observed.SPFUnreadNames)
	}

	// Each named in the sentence about it, not merely somewhere: the
	// includes are listed in the lookup count's note whatever happened to
	// them, so a name appearing in the notes proves nothing.
	said := func(about, name string) bool {
		for _, n := range got.Notes {
			if strings.Contains(n.Text, about) && strings.Contains(n.Text, name) {
				return true
			}
		}
		return false
	}
	if !said("return nothing", "gone.example") {
		t.Errorf("no note says gone.example returns nothing: %+v", got.Notes)
	}
	if !said("could not be read", "broken.example") {
		t.Errorf("no note says broken.example could not be read: %+v", got.Notes)
	}
}

// The subdomain policy is read and said where it asks less than the domain's.
func TestAWeakerSubdomainPolicyIsSaid(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone()
	z.records["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; sp=none"}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.DMARCSubdomainPolicy != "none" {
		t.Errorf("sp= was read as %q", got.Observed.DMARCSubdomainPolicy)
	}
	found := false
	for _, n := range got.Notes {
		if strings.Contains(n.Text, "sp=none") && n.Kind == policy.KindObserved {
			found = true
		}
	}
	if !found {
		t.Errorf("no note says subdomains are covered by sp=none: %+v", got.Notes)
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Rationale, "sp=") {
			t.Errorf("the subdomain policy was graded, and nothing here can see whether a subdomain sends mail: %+v", f)
		}
	}
}
