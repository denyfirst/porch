package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"
)

// keptReports holds the last report each check produced for a host and hands
// it to everybody who asks until it is older than the interval.
//
// It is keptInventories for the checks, and for the same reason. Where the
// hosts are fixed — a deployment that demonstrates the tool on its own estate —
// every visitor asks the same question. Once that deployment shows the whole
// report, a scan asks several parties besides the host: a transparency monitor,
// the authority's revocation list, the mail exchangers on port 25, the servers
// of the zone above. A page anybody can refresh would then be a way for a
// stranger to make this installation press on each of them, and they would
// answer by refusing us rather than the stranger. Kept, a scan happens at most
// once an interval for each check and host, and a visit between those causes
// no request at all.
//
// # And the age travels with it
//
// A kept copy is not a measurement of now, and the answer says when it was
// made, in the field the kept inventory already uses. The first caller in an
// interval is answered with a report made for them, which needs no date.
//
// # What is not kept
//
// A refusal, a timeout, a destination that was blocked: only a report that was
// answered. And a request carrying its own DKIM selectors is somebody else's
// question and is scanned for them, as the inventory does with a list.
type keptReports struct {
	interval time.Duration
	now      func() time.Time

	// longer holds the checks kept for longer than interval, by name. See
	// KeepCheckFor.
	longer map[string]time.Duration

	mu      sync.Mutex
	entries map[string]*keptCopy
}

// keptCopy is one check's copy for one host, and the lock that stops two
// callers producing it at once. Without the lock, ten visitors arriving on a
// cold copy would be ten scans, which is the burst this exists to prevent.
type keptCopy struct {
	mu   sync.Mutex
	body []byte
	at   time.Time
}

func keepReports(interval time.Duration, now func() time.Time) *keptReports {
	if now == nil {
		now = time.Now
	}
	return &keptReports{interval: interval, now: now, entries: map[string]*keptCopy{}}
}

// intervalFor is how long one check's report is kept.
func (k *keptReports) intervalFor(check string) time.Duration {
	if d, ok := k.longer[check]; ok {
		return d
	}
	return k.interval
}

func (k *keptReports) enabled() bool {
	return k != nil && k.interval > 0
}

// KeepReportsFor tells this service to run each check against a host at most
// once in the interval given, and to hand the report to everybody else.
//
// Called before serving, like every other piece of configuration here. The
// demonstration uses it; zero, the default, keeps nothing, which is what an
// operator running their own copy gets — their scans are their own questions.
func (s *Server) KeepReportsFor(interval time.Duration) {
	s.keptReports = keepReports(interval, s.clock)
}

// KeepCheckFor keeps one check's reports for longer than the rest.
//
// For the checks that knock on somebody else's door to answer: the mail check
// connects to the domain's mail exchangers on port 25, which on the
// demonstration are a provider's, and the DNS check asks the zone's name
// servers and the registry directly, a transfer included. Their own hosts'
// answers a report can show as they are now; somebody else's servers are not
// asked again every time a stranger refreshes a page.
//
// Called after KeepReportsFor, which it refines; on its own it keeps nothing.
// A check that does not exist is a mistake in the program that calls this,
// and it stops here rather than becoming a rule that silently never applies.
func (s *Server) KeepCheckFor(check string, interval time.Duration) {
	if !slices.Contains(checkNames, check) {
		panic(fmt.Sprintf("httpapi: KeepCheckFor names no check: %q", check))
	}
	k := s.keptReports
	if k == nil {
		return
	}
	if k.longer == nil {
		k.longer = map[string]time.Duration{}
	}
	k.longer[check] = interval
}

// serveKept answers from the copy where it is fresh, and otherwise runs the
// check and keeps what it answered.
func (s *Server) serveKept(ctx context.Context, w http.ResponseWriter, c check, t target, host string) {
	k := s.keptReports

	key := c.name + "\x00" + t.historyName()
	k.mu.Lock()
	entry, seen := k.entries[key]
	if !seen {
		entry = &keptCopy{}
		k.entries[key] = entry
	}
	k.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.at.IsZero() && k.now().Sub(entry.at) < k.intervalFor(c.name) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(withProducedAt(entry.body, entry.at))
		return
	}

	rec := &captured{header: http.Header{}}
	s.runCheck(ctx, rec, c, t, host)

	for name, values := range rec.header {
		w.Header()[name] = values
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(rec.body.Bytes())

	if status == http.StatusOK {
		entry.body = append([]byte(nil), rec.body.Bytes()...)
		entry.at = k.now()
	}
}

// withProducedAt puts the time a copy was made at the front of the report.
//
// Spliced rather than decoded and encoded again: the bytes are the ones the
// first caller was answered with, and a second encoding is a second chance for
// the two to differ.
func withProducedAt(body []byte, at time.Time) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return body
	}
	stamp := []byte(`{"producedAt":"` + at.UTC().Format(time.RFC3339) + `"`)
	rest := bytes.TrimSpace(trimmed[1:])
	if len(rest) > 0 && rest[0] != '}' {
		stamp = append(stamp, ',')
	}
	out := append(stamp, rest...)
	return append(out, '\n')
}

// captured is a response held back until it is known whether it may be kept.
type captured struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captured) Header() http.Header { return c.header }

func (c *captured) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *captured) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(p)
}
