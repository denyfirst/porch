package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/challenge"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/verify"
)

// The command line checks only what the person running it has shown control
// of, by the same record a service asks for.
//
// It checked any name it was given until 2026-09-29, on the argument that
// whoever runs it has the machine and answers for what it does. That is true,
// and it is not what this project undertakes: a tool for checking your own
// estate, which does not become a way of checking somebody else's. The checks
// are light — a handshake, one request, the records a mail server reads — and
// anybody determined can change a line of this source and build it again, or
// reach for a tool that asks no questions. What the release does is a
// promise about what denyfirst distributes, and that promise is now the same
// in a terminal as behind a password.
//
// The record is read from the zone's own servers, reached from the root, as
// the service reads it: a resolver on this machine is not asked.

// defaultSecretPath is where the command line keeps its secret when told
// nothing else: porch/secret under this user's configuration directory.
//
// Per user rather than per machine: the secret is what every record this user
// publishes is derived from, and another user on the same machine proving a
// domain to it would be proving it to somebody else.
func defaultSecretPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "porch", "secret")
}

// proofScope reads the secret at path, making it on the first run, and builds
// the scope every check here is held to.
func proofScope(path string) (scope *verify.Scope, created bool, err error) {
	if path == "" {
		return nil, false, errors.New("there is nowhere to keep the verification secret: " +
			"name a file with -verification-secret-file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("the directory for the verification secret could not be made: %w", err)
	}
	created, err = verify.CreateSecret(path)
	if err != nil {
		return nil, false, err
	}
	secret, err := verify.ReadSecret(path)
	if err != nil {
		return nil, false, err
	}
	return &verify.Scope{
		Secret: secret,
		Authority: &remembered{walk: &dnsclient.Authority{
			Client: &dnsclient.Client{Timeout: 3 * time.Second},
		}},
		// The file half, for a web check, as the service offers it.
		Fetcher: &challenge.Fetcher{},
	}, created, nil
}

// remembered is the walk, asked once per name for the length of one run.
//
// A run checks every target before scanning it, and each check asks again
// where the connection is made, so the same name is asked about twice within
// seconds. The service keeps nothing between requests — a record taken out
// ends the proof at the next one — and one run of a command is not a
// standing authorisation: it ends when the command does.
type remembered struct {
	walk verify.Resolver

	mu   sync.Mutex
	seen map[string]answer
}

type answer struct {
	values  []string
	existed bool
	err     error
}

func (r *remembered) LookupChallenge(ctx context.Context, name string) ([]string, bool, error) {
	r.mu.Lock()
	if a, ok := r.seen[name]; ok {
		r.mu.Unlock()
		return a.values, a.existed, a.err
	}
	r.mu.Unlock()

	values, existed, err := r.walk.LookupChallenge(ctx, name)

	r.mu.Lock()
	if r.seen == nil {
		r.seen = map[string]answer{}
	}
	r.seen[name] = answer{values, existed, err}
	r.mu.Unlock()
	return values, existed, err
}

// proveTargets checks every target before anything is scanned, and says what
// to publish for each that is not proven. It returns the exit status: zero
// when every target is proven.
//
// Before, rather than only where each check connects, so that the answer to
// "why did nothing happen" is the record to publish rather than a line of
// errors after a run. The checks still ask for themselves; this is the part a
// person reads.
func proveTargets(ctx context.Context, scope *verify.Scope, check string, targets []string, w io.Writer) int {
	surface := verify.AnyPort
	if check == checkWeb {
		// A web check reads a site the way a browser does, which a served
		// file proves as well as a record does.
		surface = verify.HTTPOnly
	}

	failed := false
	for _, target := range targets {
		host, err := targetHost(target)
		if err != nil {
			fmt.Fprintf(w, "%s: %v\n", target, err)
			failed = true
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			fmt.Fprintf(w, "%s: an address cannot be proven; name it by a domain you have shown control of\n", target)
			failed = true
			continue
		}
		// Refused before it is asked about: a single label has no zone above
		// it to publish in, and asking the root about it would send an
		// internal name to the root servers for nothing.
		if !strings.Contains(host, ".") {
			fmt.Fprintf(w, "%s: a name with no domain above it cannot be proven; name it by a domain you have shown control of\n", target)
			failed = true
			continue
		}

		err = scope.Covers(ctx, host, surface)
		switch {
		case err == nil:
		case errors.Is(err, verify.ErrNotVerified):
			failed = true
			fmt.Fprintf(w, "%s is not proven to this machine. Publish one of these TXT records at your DNS provider, then run again:\n", host)
			for _, r := range verify.Records(scope.Secret, host) {
				fmt.Fprintf(w, "  %s  TXT  %q\n", r.Name, r.Value)
			}
			fmt.Fprintln(w, "A record at a domain covers every name under it. It is read from the zone's own servers, so it counts as soon as they serve it.")
		default:
			failed = true
			fmt.Fprintf(w, "%s: the proof could not be looked up: %v\n", host, err)
		}
	}
	if failed {
		return exitError
	}
	return exitOK
}

// targetHost is the host a target names, however it was written: a name, a
// name and port, an address in brackets, or a URL.
func targetHost(target string) (string, error) {
	host := strings.TrimSpace(target)
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || u.Hostname() == "" {
			return "", errors.New("not a host this can check")
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "" {
		return "", errors.New("not a host this can check")
	}
	return host, nil
}

// printRecords writes the records that would prove domain, for
// -verification-token.
func printRecords(w io.Writer, secret []byte, domain string) {
	for _, r := range verify.Records(secret, domain) {
		fmt.Fprintf(w, "%s  TXT  %q\n", r.Name, r.Value)
	}
}
