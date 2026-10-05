package scan

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// stalledLogs answers only when the scan stops waiting for it, as a log
// search does on a day the monitor is slow.
type stalledLogs struct{}

func (stalledLogs) Search(ctx context.Context, _ string) ctsearch.Result {
	<-ctx.Done()
	return ctsearch.Result{Reason: "the monitor did not answer in time"}
}

// A slow log search does not cost the report the handshakes it follows.
//
// The lookups after the handshakes were asked up to the caller's deadline. A
// log search that used all of it returned after the deadline had passed, the
// service saw that and answered with a timeout, and the transport that had
// been measured in full was thrown away with it. On the demonstration that was
// the first Transport check after a restart (audit 2026-10-05, F10). They now
// stop short of the deadline, and the report says what they did not establish.
func TestASlowLogSearchDoesNotCostTheReport(t *testing.T) {
	host, port := revocationServer(t, "")

	var asked atomic.Bool
	d := &net.Dialer{Timeout: 5 * time.Second}
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, net.JoinHostPort(host, port))
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort:   true,
		AllowIPTargets: true,
		Revocation:     watchingFetcher(&asked),
		Logs:           stalledLogs{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := s.Scan(ctx, "denyfirst.dev:443")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the scan returned after the caller's deadline, so the service would answer " +
			"with a timeout and drop the handshakes it measured")
	}
	if out.TLS == nil || len(out.TLS.Certificates) == 0 {
		t.Fatal("the handshakes were not measured")
	}
	if out.LoggedLine == "" || strings.Contains(out.LoggedLine, "found in") {
		t.Errorf("the log line does not say the search established nothing: %q", out.LoggedLine)
	}
}
