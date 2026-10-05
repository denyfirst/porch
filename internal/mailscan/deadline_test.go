package mailscan

import (
	"context"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/smtptls"
)

// stalledExchangers answer only when the check stops waiting for them, as
// exchangers do from a network that drops port 25.
type stalledExchangers struct{}

func (stalledExchangers) Probe(ctx context.Context, host string) smtptls.Result {
	<-ctx.Done()
	return smtptls.Result{Host: host, Reason: "port 25 could not be reached from here", ConnectTimedOut: true}
}

// Exchangers that never answer do not cost the mail report.
//
// The exchangers are the slowest thing the mail check asks, and they were
// asked up to the caller's deadline. From a network that drops port 25 they
// used all of it, the check returned after the deadline, and the service
// answered with a timeout in place of the report (audit 2026-10-05, F11).
func TestExchangersThatNeverAnswerDoNotCostTheReport(t *testing.T) {
	skipUnderDemo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := (&Scanner{
		Resolver:       stsZone("mx1.example.net", "mx2.example.net"),
		ReadExchangers: true,
		Exchangers:     stalledExchangers{},
	}).Scan(ctx, "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the check returned after the caller's deadline, so the service would answer " +
			"with a timeout and drop the report")
	}
	if got.Observed == nil || len(got.Observed.Exchangers) != 2 {
		t.Fatalf("the exchangers were not reported: %+v", got.Observed)
	}
	for _, x := range got.Observed.Exchangers {
		if x.Measured || x.Reason == "" {
			t.Errorf("an exchanger that never answered is not said to be unmeasured: %+v", x)
		}
	}
}
