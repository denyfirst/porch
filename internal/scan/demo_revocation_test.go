//go:build demo

package scan

import (
	"net"
	"sync/atomic"
	"testing"
)

// The demonstration reads its own certificate's revocation list.
//
// It asked no authority anything until 2026-09-28, a promise written when a
// visitor chose the host and the list fetched would have been for somebody
// else's certificate. The hosts it reaches are compiled in now (N6), so the
// list is ours, and leaving it out made the demonstration say "revocation not
// established" about a certificate any copy somebody runs would have checked.
//
// Driven under the tag because the question is whether the tag still turns it
// off. The ordinary build's side is TestTheOrdinaryBuildReadsTheRevocationList.
func TestTheDemonstrationReadsItsOwnRevocationList(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var asked atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked), nil)

	if !asked.Load() {
		t.Error("the demonstration build did not read the revocation list its own certificate " +
			"names, and its report then says less about our certificate than any copy you run " +
			"says about yours")
	}
}

// And it searches the logs for its own name, where one was configured — which
// porchd does for the demonstration, whose question can only ever name this
// project's domain.
func TestTheDemonstrationSearchesTheLogsForItsOwnName(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched, searched atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), watchingSearcher{asked: &searched})

	if !searched.Load() {
		t.Error("the demonstration build was given a searcher and did not ask it which " +
			"certificates exist for its own name")
	}
}
