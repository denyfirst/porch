//go:build demo

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A demonstration build asks no monitor for an estate's names.
//
// The demonstration promises it queries no transparency log, and this mode is
// the largest question this project knows how to put to one: not "what exists
// for this host" but "what exists under this whole domain". A build that
// answered it would be breaking the promise in the loudest available way, and
// on the deployment where the person asking is a stranger.
//
// It refuses before the searcher is built, so there is nothing to reach the
// network with, and the refusal is the exit status rather than an empty
// inventory — a demonstration printing "0 names found" would be answering the
// question with the most reassuring wrong answer there is.
func TestTheDemonstrationInventoriesNoEstate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if code := runNames(ctx, []string{"example.test"}, time.Second, "", false); code == 0 {
		t.Error("a demonstration build ran an estate inventory and reported success")
	}
}

// And the mode is still named, so somebody reading -h on a demonstration build
// learns it exists and is refused here, rather than that it does not exist.
func TestTheDemonstrationStillNamesTheInventoryMode(t *testing.T) {
	if err := checkKnown(checkNames); err != nil {
		t.Errorf("the inventory mode is unknown on a demonstration build: %v", err)
	}
	if !strings.Contains(checkNames, "names") {
		t.Errorf("the mode is called %q", checkNames)
	}
}
