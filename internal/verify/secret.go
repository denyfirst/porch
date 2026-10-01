package verify

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// minSecret is the shortest secret accepted. Short enough to guess is short
// enough to forge every token a deployment will ever check, and a deployment
// whose tokens can be forged is one anyone can add a domain to.
const minSecret = 32

// CreateSecret writes 32 random bytes, base64-encoded, to path if nothing is
// there, and reports whether it did. An existing file is left alone, whatever
// it holds: reading and judging it is ReadSecret's job.
//
// Created exclusively and readable by its owner alone. One copy of this, for
// the service and the command line both: two ways of making the secret every
// proof is derived from are two things to keep in step.
func CreateSecret(path string) (bool, error) {
	raw := make([]byte, minSecret)
	if _, err := rand.Read(raw); err != nil {
		return false, fmt.Errorf("a verification secret could not be generated: %w", err)
	}

	// #nosec G304 -- a path the operator chose, never one a request carried
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("the verification secret could not be created: %w", err)
	}
	if _, err := f.Write([]byte(base64.StdEncoding.EncodeToString(raw) + "\n")); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error is the one worth reporting
		return false, fmt.Errorf("the verification secret could not be written: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("the verification secret could not be written: %w", err)
	}
	return true, nil
}

// ReadSecret reads the secret at path and refuses one too short to trust.
func ReadSecret(path string) ([]byte, error) {
	// #nosec G304 -- a path the operator chose, never one a request carried
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the verification secret could not be read: %w", err)
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	if len(secret) < minSecret {
		return nil, errors.New("the verification secret is shorter than 32 bytes; generate one with " +
			"head -c 32 /dev/urandom | base64 > the file")
	}
	return secret, nil
}

// Records are what a domain publishes to prove itself to this secret: for the
// host and each domain above it down to two labels, most specific first.
//
// All of them, because a record at any one proves the host and this cannot
// tell a public suffix from a registrable domain; a record under a suffix
// nobody runs is one nobody can publish, and saying so is the reader's job,
// not a guess made here.
func Records(secret []byte, host string) []Record {
	host = fold(host)
	labels := strings.Split(host, ".")
	var out []Record
	for i := 0; i+1 < len(labels); i++ {
		domain := strings.Join(labels[i:], ".")
		out = append(out, Record{Name: Label + "." + domain, Value: Token(secret, domain)})
	}
	return out
}

// Record is one TXT record that would prove a domain.
type Record struct {
	Name  string
	Value string
}
