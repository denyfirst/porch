package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// A secret file that does not exist is created, once, and then used.
//
// Turning proof on used to take a flag and a separate command to make the
// secret; a container starting against an empty volume had neither.
func TestAMissingSecretIsCreatedAndThenKept(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	path := filepath.Join(t.TempDir(), "secret")
	if err := createSecret(path); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(path, "")
	if err != nil || scope == nil {
		t.Fatalf("a missing secret was not created: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(first)))
	if err != nil || len(raw) != 32 {
		t.Errorf("the secret is not 32 random bytes in base64: %q", first)
	}
	if !strings.Contains(said.String(), "new verification secret") || strings.Contains(said.String(), string(first[:8])) {
		t.Errorf("the creation was not said, or the secret was: %q", said.String())
	}
	// Windows keeps no Unix mode to read, so this half runs where CI runs, on
	// Linux; a sabotage widening the mode escapes a Windows run and nothing else.
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("the secret is readable beyond its owner: %v", info.Mode().Perm())
		}
	}

	// Started again, the same secret, and nothing announced.
	said.Reset()
	if err := createSecret(path); err != nil {
		t.Fatal(err)
	}
	again, err := verificationScope(path, "")
	if err != nil || string(again.Secret) != string(scope.Secret) {
		t.Errorf("a second start did not keep the secret: %v", err)
	}
	if said.Len() != 0 {
		t.Errorf("an existing secret was announced as new: %q", said.String())
	}

	// A file that exists and is too short is still refused, not replaced.
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createSecret(short); err != nil {
		t.Fatal(err)
	}
	if _, err := verificationScope(short, ""); err == nil {
		t.Error("a short secret was accepted")
	}
	if b, _ := os.ReadFile(short); string(b) != "tiny" {
		t.Error("an existing secret was overwritten")
	}

	// And a directory that cannot hold one stops the start.
	if err := createSecret(filepath.Join(t.TempDir(), "missing", "secret")); err == nil {
		t.Error("a secret that could not be created was not an error")
	}
}

// The secret is created where the service starts, and not by -version, which
// is a question.
func TestTheSecretIsCreatedByStartingAndNotByAsking(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	create := strings.Index(source, "createSecret(*verifySecretFile)")
	version := strings.Index(source, `reach(scope != nil))`)
	scope := strings.LastIndex(source, "verificationScope(*verifySecretFile, *resolver)")
	if create < 0 || scope < 0 || create > scope {
		t.Error("the service reads its secret before creating it")
	}
	if version < 0 || create < version {
		t.Error("-version can create a secret")
	}
}

// A service that scans anything does not start, on loopback or anywhere else.
//
// Loopback was the one place porchd served without proof, on the ground that
// only this machine can reach it. Another user on the machine, another
// container, a web application with an SSRF in it and a reverse proxy set up
// in a hurry reach loopback too, and on 2026-09-29 that was reason enough.
func TestAServiceWithoutProofDoesNotStart(t *testing.T) {
	if err := proofRequired(false); err == nil {
		t.Error("a service with no proof required was allowed")
	}
	if err := proofRequired(true); err != nil {
		t.Errorf("a service with proof required was refused: %v", err)
	}
	// The demonstration starts with no secret by design: its hosts are
	// compiled in, a narrower boundary than any proof, and the call below
	// passes demo.Enabled for exactly that.
	for _, listen := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0", "0.0.0.0:0"} {
		if demoBuild() {
			break
		}
		code, said := start(t, "-listen", listen)
		if code != 2 || !strings.Contains(said, "shown control of") {
			t.Errorf("%s with no secret: exit %d, %q", listen, code, said)
		}
	}

	// Asked before anything listens.
	source := repoFile(t, "cmd/porchd/main.go")
	check := strings.Index(source, "proofRequired(scope != nil || demo.Enabled)")
	serve := strings.Index(source, `net.Listen("tcp", *listen)`)
	if check < 0 || serve < 0 || check > serve {
		t.Error("the open-service check is not made before listening")
	}
}

// What counts as an address somebody else could reach.
//
// Two things read it now — whether this service may start at all without proof,
// and whether a capability meant for the operator's own machine is offered — so
// it is one function and this says what it answers. An address that cannot be
// parsed counts as reachable: guessing in the direction of "nobody else can see
// this" is the guess that costs something, and the one that would be made
// silently.
func TestWhatCountsAsReachableByAnybodyElse(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "127.1.2.3:9"} {
		if beyondLoopback(listen) {
			t.Errorf("%s was read as reachable by others", listen)
		}
	}
	for _, listen := range []string{
		"0.0.0.0:8443", ":8443", "[::]:8443", "192.0.2.10:443", "scanner.example:443",
		// Unparseable, and therefore assumed reachable.
		"", "not an address", "1.2.3.4",
	} {
		if !beyondLoopback(listen) {
			t.Errorf("%s was read as reachable by nobody", listen)
		}
	}

	// And the service tells the API the same answer it decided to start on,
	// rather than working it out a second time somewhere else. One answer,
	// read once: the API refuses an address range to a caller who is not the
	// operator, and the page draws the field for one, and both of those follow
	// from this line.
	source := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"exposed := beyondLoopback(*listen)\n",
		"api.ReachableByOthers(exposed)",
		"api.BehindPassword(gate != nil)",
		"OperatorOnly:      !exposed || gate != nil,",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("the service does not tell the API and the pages %q, so whether "+
				"anybody else can reach it is worked out somewhere else", want)
		}
	}
}

// The scope porchd builds reads the challenge from the zone's own servers, and
// keeps the resolver only for the signed bit.
//
// A scope that read it through the resolver would work in every test here and
// accept whatever a resolver on the machine, or one it was pointed at, chose
// to answer — which is how a domain nobody controlled was scanned on
// 2026-09-29.
func TestTheServiceReadsTheChallengeFromTheZone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := createSecret(path); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(path, "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	walk, ok := scope.Authority.(*dnsclient.Authority)
	if !ok || walk == nil || walk.Client == nil {
		t.Fatalf("the scope reads the challenge from %T, not from the zone's own servers", scope.Authority)
	}
	if walk.Client.Server != "" {
		t.Errorf("the walk was handed a resolver (%q) to ask", walk.Client.Server)
	}
	if len(walk.Roots) != 0 {
		t.Errorf("the walk starts somewhere other than the root servers carried: %v", walk.Roots)
	}
}
