//go:build demo

package scan

import (
	"net"
	"sync/atomic"
	"testing"
)

// The demonstration asks no certificate authority anything.
//
// Its privacy page says so in those words. The promise is kept by the guard in
// Scan, and until this test a sabotage removing that guard changed nothing any
// test could see — the page would have gone on making a claim the code had
// stopped honouring, which is the one failure this project treats as worse
// than a bug.
//
// Driven under the tag because that is the only build where the question
// exists. The ordinary build's opposite is asserted in revocation_off_test.go,
// so neither direction rests on the other being remembered.
func TestTheDemonstrationAsksNoAuthorityAnything(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var asked atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked), nil)

	if asked.Load() {
		t.Error("the demonstration build tried to fetch a revocation list. Its privacy page " +
			"promises that no certificate authority is asked anything, and that promise is " +
			"this deployment's whole argument for existing in public")
	}
}

// And a check queries no certificate transparency log either.
//
// The same promise, about a different third party — and the disclosure here is
// the larger one: a revocation list names no certificate, while asking which
// certificates exist for a name contains the name. A check that made that
// request while the page said it made none would be the worst of the failures
// this project guards against, and until this test a sabotage removing the
// guard changed nothing anybody could see.
//
// The name inventory does ask a monitor on this deployment, since 2026-09-27,
// and only about this project's own domain — which is a mode a visitor types
// rather than something a check does, and the privacy page says so in as many
// words. A check is still a check: it describes what the server sent and asks
// nobody anything.
func TestTheDemonstrationQueriesNoTransparencyLog(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched, searched atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), watchingSearcher{asked: &searched})

	if searched.Load() {
		t.Error("the demonstration build asked a monitor which certificates exist for the " +
			"name. Its privacy page promises it queries no log, and the question carries " +
			"the domain to a service this project does not run")
	}
}
