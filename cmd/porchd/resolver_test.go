package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/verify"
)

// -resolver reaches every lookup the service makes itself: the scanner's, which
// httpapi hands to the mail check, and the proof-of-control challenge's.
//
// Asserted on what run() builds from, because a flag parsed and never assigned
// compiles, runs and does nothing — porch-scan's -resolver did exactly that.
func TestTheResolverFlagReachesEveryLookup(t *testing.T) {
	const named = "192.0.2.53:53"

	scanner := serviceScanner(nil, nil, named, false, time.Second)
	if scanner.Resolver == nil || scanner.Resolver.Server != named {
		t.Errorf("the scanner asks %+v; -resolver named %s", scanner.Resolver, named)
	}

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(secret, named)
	if err != nil {
		t.Fatalf("reading the scope: %v", err)
	}
	client, ok := scope.Resolver.(*dnsclient.Client)
	if !ok || client.Server != named {
		t.Errorf("the challenge is read through %+v; -resolver named %s", scope.Resolver, named)
	}

	// And run() passes the flag to both, rather than the empty string.
	source := repoFile(t, "cmd/porchd/main.go")
	for _, call := range []string{"serviceScanner(roots, scope, *resolver, *askResponder, *requestTimeout)", "verificationScope(*verifySecretFile, *resolver)"} {
		if !strings.Contains(source, call) {
			t.Errorf("run() does not call %s, so -resolver may not reach it", call)
		}
	}
}

// Without the flag nothing is set, so the mail check builds its own default
// rather than receiving a nil pointer inside an interface.
func TestNoResolverFlagLeavesTheScannerUnset(t *testing.T) {
	if r := serviceScanner(nil, nil, "", false, time.Second).Resolver; r != nil {
		t.Errorf("with no -resolver the scanner holds %+v", r)
	}
}

// What a service may find out about a certificate beyond the handshake, and
// on what condition.
//
// Both were settled in docs/invariants.md long before anything here did them:
// N12's table gives the transparency logs to a service that requires proof of
// control with no switch, because what is published is public and the name
// belongs to whoever proved it. R3a refused the responder to a service on the
// ground that its operator had not chosen it scan by scan — and a flag at start
// is that choice, made once for every scan the installation will run.
//
// Without a scope, neither: the names are not the operator's to disclose.
func TestWhatAServiceAsksBeyondTheHandshake(t *testing.T) {
	scope := testScope(t)

	if s := serviceScanner(nil, nil, "", false, time.Second); s.Logs != nil || s.Responder != nil {
		t.Errorf("a service with no proof of control holds %+v / %+v", s.Logs, s.Responder)
	}
	if s := serviceScanner(nil, nil, "", true, time.Second); s.Responder != nil {
		t.Errorf("a service with no proof of control was given a responder: %+v", s.Responder)
	}

	if s := serviceScanner(nil, scope, "", false, time.Second); s.Logs == nil {
		t.Error("a service with proof of control does not search the logs, which N12 gives it")
	} else if s.Responder != nil {
		t.Errorf("a responder was asked without the operator saying so: %+v", s.Responder)
	}

	if s := serviceScanner(nil, scope, "", true, time.Second); s.Responder == nil {
		t.Error("the operator asked for the responder and it was not wired")
	}
}

// testScope is a verification scope, which is what stands for proof of control
// in the tests above.
func testScope(t *testing.T) *verify.Scope {
	t.Helper()

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(secret, "")
	if err != nil {
		t.Fatalf("reading the scope: %v", err)
	}
	return scope
}

// A resolver must be an address and a port. A name would be looked up through
// the machine's resolver, which is the one the flag exists to step around.
func TestAResolverThatIsNotAnAddressAndPortIsRefused(t *testing.T) {
	for _, bad := range []string{"1.1.1.1", "dns.example:53", "1.1.1.1:0", "[fe80::1%eth0]:53", "1.1.1.1:99999", ":5353"} {
		if err := resolverAddress(bad); err == nil {
			t.Errorf("-resolver %q was accepted", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Errorf("the refusal repeats the value back: %v", err)
		}
	}
	for _, good := range []string{"", "1.1.1.1:53", "[2606:4700:4700::1111]:53", "192.168.1.1:5353"} {
		if err := resolverAddress(good); err != nil {
			t.Errorf("-resolver %q was refused: %v", good, err)
		}
	}

	// And run() asks before the flag reaches anything. A check nothing calls
	// passes every assertion above and refuses nothing.
	source := repoFile(t, "cmd/porchd/main.go")
	check := strings.Index(source, "resolverAddress(*resolver)")
	use := strings.Index(source, "verificationScope(*verifySecretFile, *resolver)")
	if check < 0 || use < 0 || check > use {
		t.Error("run() does not check -resolver before the first thing that uses it")
	}
}

// -ask-responder without proof of control is refused at start, not ignored.
//
// A flag that looks applied and does nothing is the failure the comment on
// -trusted-proxy-hops describes, and here it would be worse than useless: an
// operator would believe revocation was being checked.
func TestAskingTheResponderWithoutProofIsRefused(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")

	if !strings.Contains(source, "if *askResponder && scope == nil {") {
		t.Error("run() accepts -ask-responder with no scope, where it can do nothing")
	}
	// And the flag is read where the scanner is built, rather than parsed and
	// left behind.
	if !strings.Contains(source, "serviceScanner(roots, scope, *resolver, *askResponder, *requestTimeout)") {
		t.Error("-ask-responder does not reach the scanner")
	}
}
