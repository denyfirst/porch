package verify

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The records printed for a host are the ones Covers accepts for it: the host
// and every domain above it down to two labels, each with its own token.
//
// Round-tripped rather than compared with a list written here, because the
// failure worth catching is the two drifting apart — a record printed that
// the check would not accept sends somebody to publish something that proves
// nothing.
func TestTheRecordsCoverTheHostAndEveryDomainAbove(t *testing.T) {
	got := Records(secret, "WWW.Shop.Example.com.")
	want := []string{
		Label + ".www.shop.example.com",
		Label + ".shop.example.com",
		Label + ".example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("%d records, want %d: %v", len(got), len(want), got)
	}
	for i, r := range got {
		if r.Name != want[i] {
			t.Errorf("record %d is at %q, want %q", i, r.Name, want[i])
		}

		// Each one alone proves the host.
		s := scope(published{r.Name: {r.Value}})
		if err := s.Covers(context.Background(), "www.shop.example.com", AnyPort); err != nil {
			t.Errorf("the record at %s does not prove the host: %v", r.Name, err)
		}
	}

	// And one domain's value is not another's.
	if got[0].Value == got[2].Value {
		t.Error("the host and its parent were given the same token")
	}

	// A single label has no domain to publish in.
	if r := Records(secret, "localhost"); len(r) != 0 {
		t.Errorf("records were printed for a single label: %v", r)
	}
}

// A secret is made once, readable by its owner alone, and never replaced: a
// second call leaves what is there, because every record already published
// was derived from it.
func TestASecretIsMadeOnceAndKeptFromEverybodyElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")

	created, err := CreateSecret(path)
	if err != nil || !created {
		t.Fatalf("a missing secret was not made: %v, %v", created, err)
	}
	first, err := ReadSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < minSecret {
		t.Errorf("the secret is %d bytes", len(first))
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("the secret is readable beyond its owner: %v", info.Mode().Perm())
		}
	}

	created, err = CreateSecret(path)
	if err != nil || created {
		t.Errorf("an existing secret was made again: %v, %v", created, err)
	}
	again, err := ReadSecret(path)
	if err != nil || string(again) != string(first) {
		t.Errorf("an existing secret was replaced: %v", err)
	}
}

// A secret short enough to guess is refused rather than used: it would let
// anybody forge the token for any domain.
func TestAShortSecretIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcde\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(path); err == nil {
		t.Error("a 31-byte secret was accepted")
	}

	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(path); err != nil {
		t.Errorf("a 32-byte secret was refused: %v", err)
	}
}
