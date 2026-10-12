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

// Only the password makes a caller the operator.
//
// Until 2026-10-11 an address on loopback did too: a copy nobody else could
// reach was offered an address range without a password, and told the pages
// to draw the field for one. Loopback is reached by another user on the
// machine, another container, and a web application with an SSRF in it, so it
// says nothing about who is calling; porchd now refuses to start without a
// password anywhere, and the one thing it tells the API is whether one is in
// front.
func TestOnlyThePasswordMakesACallerTheOperator(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	if !strings.Contains(source, "api.BehindPassword(gate != nil)") {
		t.Error("the service does not tell the API whether a password is in front")
	}
	for _, gone := range []string{"beyondLoopback", "ReachableByOthers", "OperatorOnly", "passwordAllowed"} {
		if strings.Contains(source, gone) {
			t.Errorf("main.go still reads %s, and where it listens decides nothing about who calls", gone)
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
