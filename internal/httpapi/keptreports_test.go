package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// countingScanner counts the connections a scan opens and refuses each, which
// is a report that says so rather than a failure.
func countingScanner(dialled *atomic.Int32) *scan.Scanner {
	return &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialled.Add(1)
				return nil, errors.New("no network in tests")
			},
		},
		Resolver: offlineScanner().Resolver,
	}
}

// A deployment that keeps reports scans a host once an interval, however many
// ask, and says how old the copy is.
//
// The demonstration shows the whole report of its own estate, which means a
// scan there asks a transparency monitor, an authority's revocation list, the
// mail exchangers and the servers of the zone above as well as the host. A
// page anybody can refresh would otherwise be a way to make it press on all of
// them.
func TestAKeptReportIsScannedOnceAnIntervalAndSaysItsAge(t *testing.T) {
	var dialled atomic.Int32
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	s := New(countingScanner(&dialled), Limits{Burst: 1000, Refill: time.Nanosecond},
		func() time.Time { return now })
	s.KeepReportsFor(time.Hour)

	first := postFrom(t, s, `{"target":"kept.test"}`, "203.0.113.230:5000")
	if first.Code != 200 {
		t.Fatalf("the first scan answered %d: %s", first.Code, first.Body.String())
	}
	scanned := dialled.Load()
	if scanned == 0 {
		t.Fatal("the first request did not scan")
	}
	var fresh map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &fresh); err != nil {
		t.Fatalf("the first answer is not JSON: %v", err)
	}
	if _, ok := fresh["producedAt"]; ok {
		t.Error("a report made for this caller says it is a kept copy")
	}

	// Later callers inside the hour: the same report, no connection, and its
	// age.
	now = now.Add(20 * time.Minute)
	for i := range 3 {
		w := postFrom(t, s, `{"target":"kept.test"}`, "203.0.113.23"+string(rune('1'+i))+":5000")
		if w.Code != 200 {
			t.Fatalf("a kept copy answered %d: %s", w.Code, w.Body.String())
		}
		var kept map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &kept); err != nil {
			t.Fatalf("the kept copy is not JSON: %v\n%s", err, w.Body.String())
		}
		if kept["producedAt"] != "2026-09-28T12:00:00Z" {
			t.Errorf("the kept copy says it was made at %v", kept["producedAt"])
		}
		if kept["target"] != fresh["target"] || kept["verdict"] != fresh["verdict"] {
			t.Errorf("the kept copy differs from the report: %v / %v", kept, fresh)
		}
	}
	if got := dialled.Load(); got != scanned {
		t.Errorf("a kept copy opened %d connections", got-scanned)
	}
	if got := s.Stats().Total; got != 1 {
		t.Errorf("%d scans were counted, and one was made", got)
	}

	// Past the hour, a new scan.
	now = now.Add(time.Hour)
	postFrom(t, s, `{"target":"kept.test"}`, "203.0.113.240:5000")
	if dialled.Load() == scanned {
		t.Error("a copy older than its interval was served instead of a new scan")
	}
}

// A refusal is not kept, and another check or another host is another copy.
func TestOnlyAnAnsweredReportIsKept(t *testing.T) {
	var dialled atomic.Int32
	s := New(countingScanner(&dialled), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.KeepReportsFor(time.Hour)

	// A destination refused after the scan began is answered as a refusal,
	// and the next caller is scanned again rather than handed the refusal.
	var blocked atomic.Int32
	refusing := New(&scan.Scanner{
		Prober: &tlsprobe.Prober{Dial: func(context.Context, string, string) (net.Conn, error) {
			blocked.Add(1)
			return nil, fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)
		}},
		Resolver: offlineScanner().Resolver,
	}, Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	refusing.KeepReportsFor(time.Hour)
	if w := postFrom(t, refusing, `{"target":"inside.test"}`, "203.0.113.241:5000"); errorCode(t, w) != "blocked_destination" {
		t.Fatalf("a blocked destination was answered %d: %s", w.Code, w.Body.String())
	}
	once := blocked.Load()
	if w := postFrom(t, refusing, `{"target":"inside.test"}`, "203.0.113.246:5000"); errorCode(t, w) != "blocked_destination" || blocked.Load() == once {
		t.Errorf("a refusal was kept and handed to the next caller: %d %s", w.Code, w.Body.String())
	}

	postFrom(t, s, `{"target":"one.test"}`, "203.0.113.242:5000")
	after := dialled.Load()
	postFrom(t, s, `{"target":"two.test"}`, "203.0.113.243:5000")
	if dialled.Load() == after {
		t.Error("a second host was answered with the first host's copy")
	}
}

// An installation that keeps nothing scans for every caller, which is every
// installation an operator runs for themselves.
func TestWithoutAnIntervalEveryCallerIsScanned(t *testing.T) {
	var dialled atomic.Int32
	s := New(countingScanner(&dialled), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	postFrom(t, s, `{"target":"each.test"}`, "203.0.113.244:5000")
	first := dialled.Load()
	postFrom(t, s, `{"target":"each.test"}`, "203.0.113.245:5000")
	if dialled.Load() == first {
		t.Error("an installation keeping nothing answered a second caller from a copy")
	}
}

// A check kept for longer is kept for longer, and the rest are made again
// after the shorter interval.
//
// The demonstration shows its own hosts as they are now and does not ask
// somebody else's servers again every time a page is refreshed: the mail and
// DNS checks knock on a provider's mail exchangers and on name servers that
// are not ours, and they keep their reports for longer than the rest.
func TestACheckKeptForLongerIsKeptForLonger(t *testing.T) {
	var dialled atomic.Int32
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := New(countingScanner(&dialled), Limits{Burst: 1000, Refill: time.Nanosecond},
		func() time.Time { return now })
	s.KeepReportsFor(time.Minute)

	postFrom(t, s, `{"target":"fresh.test"}`, "203.0.113.150:5000")
	scanned := dialled.Load()
	now = now.Add(2 * time.Minute)
	postFrom(t, s, `{"target":"fresh.test"}`, "203.0.113.151:5000")
	if dialled.Load() == scanned {
		t.Error("a report past a minute was handed out instead of measured again")
	}

	s.KeepCheckFor(checkTLS, time.Hour)
	postFrom(t, s, `{"target":"longer.test"}`, "203.0.113.152:5000")
	scanned = dialled.Load()
	now = now.Add(20 * time.Minute)
	postFrom(t, s, `{"target":"longer.test"}`, "203.0.113.153:5000")
	if got := dialled.Load(); got != scanned {
		t.Errorf("a check kept for an hour was scanned again after twenty minutes (%d connections)", got-scanned)
	}
}

// Asked to keep one check for longer with nothing kept at all, the service
// keeps nothing, rather than starting to keep one check on its own.
func TestKeepingOneCheckLongerKeepsNothingOnItsOwn(t *testing.T) {
	var dialled atomic.Int32
	s := New(countingScanner(&dialled), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.KeepCheckFor(checkTLS, time.Hour)

	postFrom(t, s, `{"target":"own.test"}`, "203.0.113.160:5000")
	scanned := dialled.Load()
	postFrom(t, s, `{"target":"own.test"}`, "203.0.113.161:5000")
	if dialled.Load() == scanned {
		t.Error("an installation that keeps nothing kept a report")
	}
}

// A check that does not exist stops the program that names it, rather than
// becoming a rule that never applies.
func TestKeepingACheckThatDoesNotExistStops(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	s.KeepReportsFor(time.Minute)
	defer func() {
		if recover() == nil {
			t.Error("a misspelt check was accepted")
		}
	}()
	s.KeepCheckFor("mial", time.Hour)
}
