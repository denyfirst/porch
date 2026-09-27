package httpapi

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
	"github.com/denyfirst/porch/internal/inventory"
)

// anInventory is one that established something, so it is worth keeping.
func anInventory(domain string) inventory.Inventory {
	return inventory.Merge(domain, inventory.Sources{
		Logs: ctsearch.Estate{Asked: true, Domain: domain, Certificates: 1,
			Names: []ctsearch.Name{{Name: domain}}},
	})
}

// A kept copy is served until it ages out, and then it is made again.
//
// The interval is the whole of the arrangement: too short and a page anybody
// can refresh is a way to make this installation ask a third party as often as
// they like; forever and the freshest thing on the page — what each name is
// doing — is a year old while reading as now (R4).
func TestAKeptInventoryIsProducedAgainWhenItAgesOut(t *testing.T) {
	at := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	kept := keepInventories(time.Hour, func() time.Time { return at })

	var made atomic.Int64
	produce := func() inventory.Inventory {
		made.Add(1)
		return anInventory("example.test")
	}

	first := kept.serve("example.test", produce)
	if made.Load() != 1 {
		t.Fatalf("the first ask produced %d inventories, want 1", made.Load())
	}
	if !first.ProducedAt.Equal(at) {
		t.Errorf("the copy says it was produced at %s, want %s", first.ProducedAt, at)
	}

	// Inside the interval: the same copy, and nothing is asked of anybody.
	at = at.Add(59 * time.Minute)
	again := kept.serve("example.test", produce)
	if made.Load() != 1 {
		t.Errorf("a copy inside the interval was produced again")
	}
	if !again.ProducedAt.Equal(first.ProducedAt) {
		t.Errorf("the copy served inside the interval is dated %s", again.ProducedAt)
	}

	// Past it: made again, and dated again.
	at = at.Add(2 * time.Minute)
	fresh := kept.serve("example.test", produce)
	if made.Load() != 2 {
		t.Errorf("a copy past the interval was served again, %d productions", made.Load())
	}
	if !fresh.ProducedAt.Equal(at) {
		t.Errorf("the fresh copy is dated %s, want %s", fresh.ProducedAt, at)
	}

	// And another domain is its own answer rather than the first one's: one
	// entry per domain, so a deployment that grew a second estate would not
	// serve the first one's names under the second one's name.
	other := kept.serve("other.test", func() inventory.Inventory {
		made.Add(1)
		return anInventory("other.test")
	})
	if made.Load() != 3 || other.Domain != "other.test" {
		t.Errorf("a second domain was served %q after %d productions", other.Domain, made.Load())
	}
}

// A failure is not kept.
//
// An unreachable monitor for one minute would otherwise be an hour of telling
// every visitor that nothing was established — and the next visitor is the
// cheapest retry there is. Keeping it would also mean the page's worst state
// is its stickiest.
func TestAFailedSearchIsNotKept(t *testing.T) {
	kept := keepInventories(time.Hour, nil)

	var asks atomic.Int64
	produce := func() inventory.Inventory {
		if asks.Add(1) == 1 {
			return inventory.Merge("example.test", inventory.Sources{
				Logs: ctsearch.Estate{Asked: true, Domain: "example.test",
					Reason: "the certificate transparency monitor could not be reached"},
			})
		}
		return anInventory("example.test")
	}

	if failed := kept.serve("example.test", produce); failed.Established() {
		t.Fatal("the fixture established something on the first ask")
	}

	got := kept.serve("example.test", produce)
	if !got.Established() {
		t.Error("a failure was kept and served again instead of being retried")
	}
	if asks.Load() != 2 {
		t.Errorf("%d asks were made, want 2: the failure must not have been kept", asks.Load())
	}
}

// Ten visitors arriving together ask one question.
//
// The per-domain lock is what makes the promise true under load. Without it a
// cold cache and a busy minute are ten searches at a monitor, which is the
// burst this exists to prevent — and the race detector in CI is what proves
// the lock is a lock.
func TestVisitorsArrivingTogetherAskOneQuestion(t *testing.T) {
	kept := keepInventories(time.Hour, nil)

	var made atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			kept.serve("example.test", func() inventory.Inventory {
				made.Add(1)
				time.Sleep(5 * time.Millisecond)
				return anInventory("example.test")
			})
		}()
	}
	close(start)
	wg.Wait()

	if n := made.Load(); n != 1 {
		t.Errorf("%d inventories were produced for ten visitors at once, want 1", n)
	}
}

// Keeping nothing is the ordinary installation, and it produces for everybody.
//
// An operator running their own copy asks about their own estate when they ask,
// and a kept answer would be a report older than the change they are checking
// for.
func TestKeepingNothingProducesAnInventoryForEveryCaller(t *testing.T) {
	var made atomic.Int64
	produce := func() inventory.Inventory {
		made.Add(1)
		return anInventory("example.test")
	}

	for _, kept := range []*keptInventories{nil, keepInventories(0, nil)} {
		made.Store(0)
		got := kept.serve("example.test", produce)
		_ = kept.serve("example.test", produce)

		if made.Load() != 2 {
			t.Errorf("%d inventories were produced for two callers, want 2", made.Load())
		}
		// And nothing claims to be a copy of anything.
		if !got.ProducedAt.IsZero() {
			t.Errorf("an inventory produced for this caller is dated %s", got.ProducedAt)
		}
	}
}
