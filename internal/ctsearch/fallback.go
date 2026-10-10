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

// Fallback asks one monitor, and another only when the first established
// nothing.
//
// The second exists for the day the first is down, and it is asked only then:
// a question a monitor answered is not asked again elsewhere, so a domain is
// named to the second only when the first could not take it. Which one
// answered travels with the answer, because the two can differ — on
// 2026-10-09 crt.sh listed one of this project's four valid certificates and
// Cert Spotter all four — and an answer whose source is not given cannot be
// weighed.
type Fallback struct {
	First, Then Monitor
}

// neither is the reason when both monitors failed. The first one's reason is
// not reused: it would describe one failure where there were two.
const neither = "neither certificate transparency monitor answered the search"

func (f *Fallback) Search(ctx context.Context, name string) Result {
	r := f.First.Search(ctx, name)
	if r.Reason == "" {
		return r
	}
	if t := f.Then.Search(ctx, name); t.Reason == "" {
		return t
	}
	return Result{Reason: neither}
}

func (f *Fallback) SearchEstate(ctx context.Context, domain string) Estate {
	e := f.First.SearchEstate(ctx, domain)
	if e.Reason == "" {
		return e
	}
	if t := f.Then.SearchEstate(ctx, domain); t.Reason == "" {
		return t
	}
	return Estate{Asked: true, Domain: e.Domain, Reason: neither}
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
// rate limiting, an outage — leaves a report with nothing in it or, worse,
// with the second monitor's answer, which may be a day behind. An answer an
// hour old from the monitor that is up to date is the better of those, and it
// says how old it is in Checked. Past a day it is not handed out: an answer
// that old is history, and "not established" is the honest report of now.
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
