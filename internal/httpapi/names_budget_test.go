package httpapi

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/certnames"
	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/dnsnames"
	"github.com/denyfirst/porch/internal/inventory"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// stalledMonitor never answers: it holds the question until it is told to
// stop, which is what crt.sh did to the demonstration on 2026-10-05.
type stalledMonitor struct {
	given atomic.Int64 // how long it was given, in nanoseconds
}

func (m *stalledMonitor) SearchEstate(ctx context.Context, domain string) ctsearch.Estate {
	if deadline, ok := ctx.Deadline(); ok {
		m.given.Store(int64(time.Until(deadline)))
	}
	<-ctx.Done()
	return ctsearch.Estate{Asked: true, Domain: domain,
		Reason: "the certificate transparency monitor could not be reached"}
}

// timelyRecords answers as a resolver does: only while there is time.
type timelyRecords struct{ found dnsnames.Found }

func (r *timelyRecords) Under(ctx context.Context, _ string) dnsnames.Found {
	if ctx.Err() != nil {
		return dnsnames.Found{Asked: true, Reason: "the domain's own records could not be read"}
	}
	return r.found
}

// A monitor that never answers does not cost the domain's own records.
//
// The inventory asked the monitor first, with the request's whole deadline,
// and the records after it. On 2026-10-05 crt.sh did not answer the
// demonstration, the records were then asked with no time left, and the page
// said the domain had no names at all (audit F12). The records are read first
// now, and the monitor has half of what is left.
func TestAMonitorThatNeverAnswersDoesNotCostTheRecords(t *testing.T) {
	scope, _ := scopeProving("proven.example")
	const budget = 2 * time.Second
	s := New(&scan.Scanner{
		Prober: &tlsprobe.Prober{Dial: recordingDial(new(atomic.Bool))},
		Verify: scope,
	}, Limits{Burst: 1000, Refill: time.Nanosecond, RequestTimeout: budget}, nil)

	monitor := &stalledMonitor{}
	s.SearchNames(monitor)
	s.records = &timelyRecords{found: dnsnames.Found{Asked: true, Names: []dnsnames.Name{
		{Name: "mail.proven.example", Sources: []dnsnames.Source{dnsnames.FromMX}},
	}}}

	start := time.Now()
	w := postTo(t, s, "/api/v1/names/scan", `{"target":"proven.example"}`, "203.0.113.71:5000")
	took := time.Since(start)

	if w.Code != 200 {
		t.Fatalf("answered %d after %v: %s", w.Code, took, w.Body.String())
	}
	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Records.Established() || got.Distinct != 1 {
		t.Errorf("the records came back as %+v with %d names; a silent monitor cost them", got.Records, got.Distinct)
	}
	if got.Logs.Established() {
		t.Error("a monitor that never answered is reported as having answered")
	}
	if given := time.Duration(monitor.given.Load()); given <= 0 || given > budget*6/10 {
		t.Errorf("the monitor was given %v of %v; a third party asked first gets half", given, budget)
	}
}

// An inventory nobody could read is not kept because the hosts were asked.
//
// The certificates the hosts present are read from the hosts the other sources
// named. With those failed there is nobody to ask, the reader says so
// truthfully, and that answer made the whole inventory "established": kept for
// an hour and served to every visitor with no names in it (audit F12).
func TestAnInventoryOnlyTheEmptyHostListAnsweredIsNotKept(t *testing.T) {
	kept := keepInventories(time.Hour, nil)
	var asks atomic.Int64
	produce := func() inventory.Inventory {
		asks.Add(1)
		return inventory.Merge("example.test", inventory.Sources{
			Logs: ctsearch.Estate{Asked: true, Domain: "example.test",
				Reason: "the certificate transparency monitor could not be reached"},
			Records:   dnsnames.Found{Asked: true, Reason: "the domain's own records could not be read"},
			Presented: (&certnames.Reader{}).Under(context.Background(), "example.test", nil),
		})
	}
	kept.serve("example.test", produce)
	kept.serve("example.test", produce)
	if asks.Load() != 2 {
		t.Errorf("%d asks were made, want 2: an inventory that read nothing was kept", asks.Load())
	}
}
