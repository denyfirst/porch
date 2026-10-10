package ctsearch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubMonitor answers from fields and counts what it was asked.
type stubMonitor struct {
	name     string
	fail     bool
	searches atomic.Int32
	estates  atomic.Int32
	wait     chan struct{}
}

func (s *stubMonitor) Search(ctx context.Context, name string) Result {
	s.searches.Add(1)
	if s.wait != nil {
		<-s.wait
	}
	if s.fail {
		return Result{Reason: s.name + " failed", Monitor: s.name}
	}
	return Result{Distinct: 1, Monitor: s.name}
}

func (s *stubMonitor) SearchEstate(ctx context.Context, domain string) Estate {
	s.estates.Add(1)
	if s.fail {
		return Estate{Asked: true, Domain: domain, Reason: s.name + " failed", Monitor: s.name}
	}
	return Estate{Asked: true, Domain: domain, Distinct: 1, Monitor: s.name}
}

// A kept answer is handed out until it is due, and then the monitor is asked
// again.
func TestAKeptAnswerIsHandedOutUntilItIsDue(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m := &stubMonitor{name: "m"}
	c := &Cached{Monitor: m, For: 15 * time.Minute, Now: func() time.Time { return now }}

	first := c.Search(context.Background(), "example.com")
	now = now.Add(14 * time.Minute)
	again := c.Search(context.Background(), "EXAMPLE.com.")
	if n := m.searches.Load(); n != 1 {
		t.Errorf("the monitor was asked %d times inside the interval", n)
	}
	if !again.Checked.Equal(first.Checked) || again.Checked.IsZero() {
		t.Errorf("the kept answer says it was checked at %v, the first at %v", again.Checked, first.Checked)
	}

	now = now.Add(2 * time.Minute)
	if c.Search(context.Background(), "example.com"); m.searches.Load() != 2 {
		t.Error("the monitor was not asked again once the answer was due")
	}

	// The estate is kept apart from the search: they are different questions.
	c.SearchEstate(context.Background(), "example.com")
	c.SearchEstate(context.Background(), "example.com")
	if n := m.estates.Load(); n != 1 {
		t.Errorf("the estate was asked for %d times inside the interval", n)
	}
}

// A monitor that stops answering is stood in for by its last good answer, for
// a day, and the answer says how old it is.
//
// The alternative on the day of an outage is a report with nothing in it.
func TestTheLastGoodAnswerStandsInForADayAndSaysItsAge(t *testing.T) {
	start := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	now := start
	m := &stubMonitor{name: "m"}
	c := &Cached{Monitor: m, For: 15 * time.Minute, Now: func() time.Time { return now }}

	c.Search(context.Background(), "example.com")
	c.SearchEstate(context.Background(), "example.com")
	m.fail = true

	now = start.Add(3 * time.Hour)
	got := c.Search(context.Background(), "example.com")
	if got.Reason != "" || got.Distinct != 1 || !got.Checked.Equal(start) {
		t.Errorf("three hours into an outage: %+v", got)
	}
	estate := c.SearchEstate(context.Background(), "example.com")
	if estate.Reason != "" || !estate.Checked.Equal(start) {
		t.Errorf("three hours into an outage, the estate: %+v", estate)
	}

	now = start.Add(25 * time.Hour)
	got = c.Search(context.Background(), "example.com")
	if got.Reason == "" {
		t.Errorf("an answer a day old was handed out as current: %+v", got)
	}
}

// A refusal is never kept, so the next caller asks again.
func TestAFailureIsNotKept(t *testing.T) {
	m := &stubMonitor{name: "m", fail: true}
	c := &Cached{Monitor: m, For: time.Hour}

	c.Search(context.Background(), "example.com")
	c.Search(context.Background(), "example.com")
	if n := m.searches.Load(); n != 2 {
		t.Errorf("the monitor was asked %d times after failing; a failure was kept", n)
	}
}

// Ten callers arriving on a cold entry make one request, not ten.
func TestCallersOnAColdEntryShareOneRequest(t *testing.T) {
	m := &stubMonitor{name: "m", wait: make(chan struct{})}
	c := &Cached{Monitor: m, For: time.Hour}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Search(context.Background(), "example.com")
		}()
	}
	// Let the first through once the others are queued behind it.
	time.Sleep(50 * time.Millisecond)
	close(m.wait)
	wg.Wait()

	if n := m.searches.Load(); n != 1 {
		t.Errorf("ten callers made %d requests", n)
	}
}
