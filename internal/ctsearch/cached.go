package ctsearch

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Monitor is a monitor that answers both questions this project asks of one:
// what the logs hold for a name, and what names a domain's certificates carry.
type Monitor interface {
	Searcher
	EstateSearcher
}

// Cached keeps a monitor's answer for a while, and its last good answer for
// longer.
//
// For the demonstration, whose reports are made again every minute while the
// question to a monitor is the same one every time: a page anybody can refresh
// must not be a way to make this installation press on a third party, and the
// anonymous rate a monitor allows is a few questions an hour.
//
// The last good answer is the other half. A monitor that stops answering —
// rate limiting, an outage — would leave a report with nothing in it, and an
// answer an hour old is the better of the two: it says how old it is in
// Checked. Past a day it is not handed out: an answer that old is history, and
// "not established" is the honest report of now.
type Cached struct {
	Monitor Monitor

	// For is how long an answer is handed out before the monitor is asked
	// again.
	For time.Duration

	// Now is the clock; nil means the real one.
	Now func() time.Time

	mu       sync.Mutex
	searches map[string]*kept[Result]
	estates  map[string]*kept[Estate]
}

// keepGood is how long a last good answer stands in for a monitor that is not
// answering.
const keepGood = 24 * time.Hour

// maxKept bounds how many names an instance remembers. The demonstration asks
// about a handful; a bound keeps a mistake elsewhere from becoming memory.
const maxKept = 256

// kept is one name's answer, and the lock that stops two callers asking the
// monitor at once on a cold entry — which is the burst this exists to prevent.
type kept[T any] struct {
	mu   sync.Mutex
	good bool
	at   time.Time
	last T
}

func (c *Cached) Search(ctx context.Context, name string) Result {
	k := entryFor(&c.mu, &c.searches, fold(name))
	return answer(c, k, func() (Result, bool) {
		r := c.Monitor.Search(ctx, name)
		return r, r.Reason == ""
	}, func(r Result, at time.Time) Result {
		r.Checked = at
		return r
	})
}

func (c *Cached) SearchEstate(ctx context.Context, domain string) Estate {
	k := entryFor(&c.mu, &c.estates, fold(domain))
	return answer(c, k, func() (Estate, bool) {
		e := c.Monitor.SearchEstate(ctx, domain)
		return e, e.Reason == ""
	}, func(e Estate, at time.Time) Estate {
		e.Checked = at
		return e
	})
}

// answer hands out the kept answer while it is fresh, asks the monitor when it
// is not, and falls back to the last good answer while that is under a day old.
func answer[T any](c *Cached, k *kept[T], ask func() (T, bool), dated func(T, time.Time) T) T {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := c.now()
	if k.good && now.Sub(k.at) < c.For {
		return dated(k.last, k.at)
	}

	got, ok := ask()
	if ok {
		k.good, k.at, k.last = true, now, got
		return dated(got, now)
	}
	if k.good && now.Sub(k.at) < keepGood {
		return dated(k.last, k.at)
	}
	return got
}

func entryFor[T any](mu *sync.Mutex, m *map[string]*kept[T], key string) *kept[T] {
	mu.Lock()
	defer mu.Unlock()
	if *m == nil || len(*m) >= maxKept {
		*m = map[string]*kept[T]{}
	}
	k, ok := (*m)[key]
	if !ok {
		k = &kept[T]{}
		(*m)[key] = k
	}
	return k
}

func (c *Cached) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// fold is the key a name is kept under: the same name however it was written.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
