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

	scanner := serviceScanner(nil, nil, named, time.Second)
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
	for _, call := range []string{"serviceScanner(roots, scope, *resolver, *requestTimeout)", "verificationScope(*verifySecretFile, *resolver)"} {
		if !strings.Contains(source, call) {
			t.Errorf("run() does not call %s, so -resolver may not reach it", call)
		}
	}
}

// Without the flag the scanner still holds a resolver, and it is never a nil
// pointer inside an interface.
//
// This test said the opposite until 2026-09-28: nothing was set, so the mail
// check would build its own default rather than receive a typed nil. The trap
// is real and internal/mailscan refuses a typed nil of its own accord now —
// but the condition that avoided it cost three of the inventory's four
// sources, because the records, what each name is doing, and the certificates
// its hosts present all hang off this field. A copy started without the flag
// read one source while its page described four.
//
// An empty Server is this machine's own configuration, which is what the
// default would have been. What matters is that it is a real client.
func TestEveryInstallationHasAResolver(t *testing.T) {
	r := serviceScanner(nil, nil, "", time.Second).Resolver
	if r == nil {
		t.Fatal("with no -resolver the scanner holds nothing, so three of the inventory's four sources are off")
	}
	if r.Server != "" {
		t.Errorf("with no -resolver the scanner asks %q rather than this machine's own configuration", r.Server)
	}

	// And the flag still reaches it, so an operator who named one is asking
	// the resolver they named.
	named := serviceScanner(nil, nil, "192.0.2.53:53", time.Second).Resolver
	if named == nil || named.Server != "192.0.2.53:53" {
		t.Errorf("with -resolver the scanner holds %+v", named)
	}
}

// What a service asks beyond the handshake: the transparency monitor which
// certificates exist for a name, and the certificate's own authority whether
// it has been revoked.
//
// Both, wherever a scan may reach a name at all: a proven domain on an
// installation, and the demonstration's own. Neither without one, because a
// service with no scope and no compiled-in estate scans nothing.
func TestWhatAServiceAsksBeyondTheHandshake(t *testing.T) {
	scope := testScope(t)

	if s := serviceScanner(nil, nil, "", time.Second); (s.Logs != nil) != demoBuild() || (s.Responder != nil) != demoBuild() {
		t.Errorf("a service with no proof of control holds %+v / %+v", s.Logs, s.Responder)
	}

	s := serviceScanner(nil, scope, "", time.Second)
	if s.Logs == nil {
		t.Error("a service with proof of control does not search the logs")
	}
	if s.Responder == nil {
		t.Error("a service with proof of control does not ask the certificate's authority")
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

// A flag that was removed is refused at start, with the reason it went.
//
// The flag package would refuse it too, saying only that it was never defined;
// an operator upgrading with -ask-responder in a unit file deserves to learn
// that the authority is now always asked, not to go looking for a typo.
func TestARemovedFlagIsRefusedWithItsReason(t *testing.T) {
	for flag, says := range map[string]string{
		"-ask-responder":        "asks a certificate's own authority",
		"-names-monitor=crtsh":  "every installation asks Cert Spotter",
		"--names-monitor-url=x": "every installation asks Cert Spotter",
	} {
		err := removedFlags([]string{"-listen", "127.0.0.1:0", flag})
		if err == nil {
			t.Errorf("%s was accepted", flag)
			continue
		}
		if !strings.Contains(err.Error(), says) {
			t.Errorf("%s was refused as %q", flag, err)
		}
	}
	if err := removedFlags([]string{"--", "-ask-responder"}); err != nil {
		t.Errorf("an argument after -- was read as a flag: %v", err)
	}
}
