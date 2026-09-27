//go:build demo

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/inventory"
)

// The demonstration lists its own estate, asks a monitor to do it, and refuses
// every other domain.
//
// It refused everything until 2026-09-27, on the ground that this deployment
// queries no transparency log. That promise protected a visitor's domain back
// when the demonstration scanned whatever it was given; the hosts this build
// may touch are compiled in, so there is no visitor's domain left to protect,
// and the refusal was costing the demonstration of the one mode that reads
// several sources and says which named what.
//
// What still holds is the boundary: the monitor is asked about this project's
// domain and about nothing else, whoever asks.
func TestTheDemonstrationListsItsOwnEstate(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	monitor := &stubMonitor{estate: ctsearch.Estate{
		Asked: true, Certificates: 1,
		Names: []ctsearch.Name{{Name: "porch.denyfirst.dev"}},
	}}
	s.SearchNames(monitor)

	// Somebody else's domain: refused before anything is asked of anybody.
	if got := errorCode(t, postTo(t, s, "/api/v1/names/scan",
		`{"target":"example.com"}`, "203.0.113.100:5000")); got != "not_demonstrated" {
		t.Errorf("a domain this deployment does not own was answered %q", got)
	}
	if was := monitor.was(); was != "" {
		t.Errorf("the monitor was asked about %q, which this deployment does not own", was)
	}

	// And its own, which needs no proof of control: a boundary compiled into
	// the binary already answers the question proof would ask, and a visitor
	// cannot prove control of our domain anyway.
	domain := demo.Targets()[0]
	w := postTo(t, s, "/api/v1/names/scan", `{"target":"`+domain+`"}`, "203.0.113.101:5000")
	if w.Code != http.StatusOK {
		t.Fatalf("this deployment's own domain answered %d: %s", w.Code, w.Body.String())
	}
	if monitor.was() != domain {
		t.Errorf("the monitor was asked about %q, want %q", monitor.was(), domain)
	}

	var got inventory.Inventory
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.Distinct == 0 {
		t.Errorf("the demonstration produced an empty inventory: %+v", got)
	}
}

// A visit causes no request. The answer is produced once and handed to
// everybody.
//
// This is what makes the privacy page's sentence true under a refresh: without
// it, a page anybody can reload is a way for a stranger to make this
// installation ask a third party as often as they like, and the third party
// would rate-limit us rather than them.
func TestTheDemonstrationKeepsTheInventoryItProduced(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	var searches atomic.Int64
	s.SearchNames(&countingMonitor{searches: &searches})
	s.KeepInventoryFor(time.Hour)

	domain := demo.Targets()[0]
	body := `{"target":"` + domain + `"}`

	first := postTo(t, s, "/api/v1/names/scan", body, "203.0.113.102:5000")
	second := postTo(t, s, "/api/v1/names/scan", body, "203.0.113.103:5000")

	for i, w := range []*http.Response{first.Result(), second.Result()} {
		if w.StatusCode != http.StatusOK {
			t.Fatalf("request %d answered %d", i+1, w.StatusCode)
		}
	}
	if n := searches.Load(); n != 1 {
		t.Errorf("%d searches were made for two visits, want 1", n)
	}

	// And the copy says when it was made, because a kept answer that read as
	// current whatever its age would be the one claim this mode has to get
	// right (R4).
	var got inventory.Inventory
	if err := json.Unmarshal(second.Body.Bytes(), &got); err != nil {
		t.Fatalf("the inventory did not decode: %v", err)
	}
	if got.ProducedAt.IsZero() {
		t.Error("a kept inventory does not say when it was produced")
	}
}

// countingMonitor answers the same estate every time and counts the asking.
type countingMonitor struct{ searches *atomic.Int64 }

func (m *countingMonitor) SearchEstate(_ context.Context, domain string) ctsearch.Estate {
	m.searches.Add(1)
	return ctsearch.Estate{
		Asked: true, Domain: domain, Certificates: 1,
		Names: []ctsearch.Name{{Name: strings.ToLower(domain)}},
	}
}
