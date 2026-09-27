package httpapi

import (
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/inventory"
)

// keptInventories holds the last inventory produced for a domain and serves it
// again until it is older than the interval.
//
// # Why a service would keep one at all
//
// An inventory is several questions to a monitor this project does not run.
// Where the domain being asked about is fixed — a deployment that demonstrates
// the tool on its own estate — every visitor asks the same question, and asking
// it again per visitor spends somebody else's service on an answer that has not
// changed. A page that anybody can refresh would be a way for a stranger to
// make this installation hammer a third party, and the third party would
// rate-limit us rather than them.
//
// So the answer is produced at most once an interval and handed to everyone who
// asks. A visit then causes no request at all, which is a stronger thing to be
// able to say than "we ask, but politely".
//
// # And the age travels with it
//
// A kept copy is not a measurement of now, and the report says when it was
// made. Without that the freshest thing on the page — what each name is doing —
// would read as current whatever its age, which is the one claim this whole
// mode exists to get right (R4).
type keptInventories struct {
	// interval is how long a copy is served for. Zero keeps nothing, which is
	// what an installation producing an inventory per caller does.
	interval time.Duration

	// now is the clock, so a test does not wait an hour.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*keptInventory
}

// keptInventory is one domain's copy, and the lock that stops two callers
// producing it at once.
//
// The per-domain lock is what makes the promise true under load: without it,
// ten visitors arriving together on a cold cache would send ten searches to the
// monitor, which is the burst this exists to prevent. They queue instead, and
// the nine that waited are served the copy the first one made.
type keptInventory struct {
	mu  sync.Mutex
	inv inventory.Inventory
	at  time.Time
}

func keepInventories(interval time.Duration, now func() time.Time) *keptInventories {
	if now == nil {
		now = time.Now
	}
	return &keptInventories{interval: interval, now: now, entries: map[string]*keptInventory{}}
}

// serve hands back the copy for a domain, producing one where there is none or
// where the one there is has aged out.
//
// produce is called with no lock this type holds except the domain's own, so
// two domains are never serialised against each other.
func (k *keptInventories) serve(domain string, produce func() inventory.Inventory) inventory.Inventory {
	if k == nil || k.interval <= 0 {
		return produce()
	}

	k.mu.Lock()
	entry, seen := k.entries[domain]
	if !seen {
		entry = &keptInventory{}
		k.entries[domain] = entry
	}
	k.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.at.IsZero() && k.now().Sub(entry.at) < k.interval {
		return entry.inv
	}

	made := produce()

	// A failure is not kept. An unreachable monitor for one minute would
	// otherwise be an hour of telling every visitor that nothing was
	// established, and the next visitor is the cheapest possible retry.
	if !made.Established() {
		return made
	}

	at := k.now()
	made.ProducedAt = at
	entry.inv, entry.at = made, at
	return made
}
