package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/results"
	"github.com/denyfirst/porch/internal/verify"
)

// zone answers the proof lookup from a table and counts every question, so a
// test can tell a check that asked from one that never did.
type zone struct {
	mu      sync.Mutex
	records map[string][]string
	err     error
	asked   []string
}

func (z *zone) LookupChallenge(_ context.Context, name string) ([]string, bool, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.asked = append(z.asked, name)
	if z.err != nil {
		return nil, false, z.err
	}
	values, ok := z.records[name]
	return values, ok, nil
}

func (z *zone) questions() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return len(z.asked)
}

// servedFile serves the same body for every host, as a site serving the
// challenge file would.
type servedFile string

func (f servedFile) FetchChallenge(context.Context, string) (string, error) { return string(f), nil }

var testSecret = []byte("a secret for the command line's own tests")

// proven is a scope under which example.com has published its record.
func proven() (*verify.Scope, *zone) {
	z := &zone{records: map[string][]string{
		verify.Label + ".example.com": {verify.Token(testSecret, "example.com")},
	}}
	return &verify.Scope{Secret: testSecret, Authority: z}, z
}

// Every target is proven before anything is checked, however it was written,
// and a target that is not is refused with the record that would prove it.
func TestEveryTargetIsProvenBeforeAnythingIsChecked(t *testing.T) {
	scope, _ := proven()
	ctx := context.Background()

	var out bytes.Buffer
	for _, target := range []string{
		"example.com",
		"www.example.com:443",
		"https://shop.example.com/basket",
		"EXAMPLE.COM.",
	} {
		out.Reset()
		if code := proveTargets(ctx, scope, checkTLS, []string{target}, &out); code != exitOK {
			t.Errorf("%s, under a proven domain, was refused: %s", target, out.String())
		}
	}

	out.Reset()
	code := proveTargets(ctx, scope, checkTLS, []string{"example.com", "other.test"}, &out)
	if code == exitOK {
		t.Fatal("a run naming a domain nobody proved exited zero")
	}
	said := out.String()
	for _, want := range []string{
		verify.Label + ".other.test",
		verify.Token(testSecret, "other.test"),
		"other.test is not proven",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, said)
		}
	}
	// And the proven one beside it is not reported as a fault.
	if strings.Contains(said, "example.com is not proven") {
		t.Errorf("a proven domain was reported as unproven:\n%s", said)
	}
}

// An address is refused before anything is asked. A domain is proven by a
// record in its zone; an address has no zone anybody here can check, and a
// reverse zone is published by whoever holds the range, not whoever types it.
func TestAnAddressIsNotCheckedFromTheCommandLine(t *testing.T) {
	scope, z := proven()
	for _, target := range []string{"192.0.2.10", "192.0.2.10:8443", "[2001:db8::1]:443", "https://[2001:db8::1]/", "https://192.0.2.10:8443/"} {
		var out bytes.Buffer
		if code := proveTargets(context.Background(), scope, checkTLS, []string{target}, &out); code == exitOK {
			t.Errorf("%s was checked", target)
		}
		if !strings.Contains(out.String(), "an address cannot be proven") {
			t.Errorf("%s was refused without saying why: %s", target, out.String())
		}
	}
	if n := z.questions(); n != 0 {
		t.Errorf("an address was looked up %d times", n)
	}

	// Nor is a single label, which has no zone above it to publish in; asked
	// about, it would be an internal name sent to the root servers.
	var out bytes.Buffer
	if code := proveTargets(context.Background(), scope, checkTLS, []string{"intranet:443"}, &out); code == exitOK {
		t.Error("a single-label name was checked")
	}
	if !strings.Contains(out.String(), "no domain above it") {
		t.Errorf("a single-label name was refused without saying why: %s", out.String())
	}
	if n := z.questions(); n != 0 {
		t.Errorf("a single-label name was looked up %d times", n)
	}
}

// A lookup that failed is not a pass, and it is not "publish a record" either:
// somebody who has published it would be sent to publish it again.
func TestAProofThatCouldNotBeReadIsNotAPass(t *testing.T) {
	z := &zone{err: errors.New("no route to the root")}
	scope := &verify.Scope{Secret: testSecret, Authority: z}

	var out bytes.Buffer
	if code := proveTargets(context.Background(), scope, checkTLS, []string{"example.com"}, &out); code == exitOK {
		t.Fatal("a proof that could not be read let the run through")
	}
	if !strings.Contains(out.String(), "could not be looked up") || strings.Contains(out.String(), "Publish") {
		t.Errorf("a failed lookup was reported as a missing record:\n%s", out.String())
	}
}

// The web check accepts the served file, as the service does, and nothing
// else does: the file proves what a browser reaches, not a zone or a port.
func TestOnlyTheWebCheckAcceptsTheServedFile(t *testing.T) {
	scope := &verify.Scope{
		Secret:    testSecret,
		Authority: &zone{},
		Fetcher:   servedFile(verify.Token(testSecret, "example.com")),
	}
	ctx := context.Background()

	var out bytes.Buffer
	if code := proveTargets(ctx, scope, checkWeb, []string{"example.com"}, &out); code != exitOK {
		t.Errorf("the web check refused a site serving its file:\n%s", out.String())
	}
	for _, check := range []string{checkTLS, checkMail, checkDNS, checkNames} {
		out.Reset()
		if code := proveTargets(ctx, scope, check, []string{"example.com"}, &out); code == exitOK {
			t.Errorf("the %s check accepted a served file as proof", check)
		}
	}
}

func TestATargetIsReadAsTheHostItNames(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":                    "example.com",
		"example.com.":                   "example.com",
		"www.example.com:8443":           "www.example.com",
		"https://www.example.com/x":      "www.example.com",
		"https://www.example.com:8443/x": "www.example.com",
		"[2001:db8::1]:443":              "2001:db8::1",
		"  example.com  ":                "example.com",
	} {
		got, err := targetHost(in)
		if err != nil || got != want {
			t.Errorf("targetHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "https://", ":443"} {
		if got, err := targetHost(in); err == nil {
			t.Errorf("targetHost(%q) = %q, want a refusal", in, got)
		}
	}
}

// The secret is made on the first run, readable by this user alone in a
// directory only they can enter, and kept after that. The record is read by
// the walk from the root and no resolver: this machine's resolver is exactly
// what a fake answer comes from.
func TestTheCommandLineKeepsItsOwnSecretAndAsksNoResolver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "porch", "secret")

	scope, created, err := proofScope(path)
	if err != nil || !created {
		t.Fatalf("the first run made no secret: %v, %v", created, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("the secret is readable beyond its owner: %v", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
			t.Errorf("the secret's directory is open beyond its owner: %v", info.Mode().Perm())
		}
	}

	again, created, err := proofScope(path)
	if err != nil || created || string(again.Secret) != string(scope.Secret) {
		t.Errorf("a second run did not keep the secret: created %v, %v", created, err)
	}

	if scope.Resolver != nil {
		t.Error("the proof is read through a resolver")
	}
	walk, ok := scope.Authority.(*remembered)
	if !ok {
		t.Fatalf("the proof is not read by the walk from the root: %T", scope.Authority)
	}
	if _, ok := walk.walk.(*dnsclient.Authority); !ok {
		t.Errorf("the proof is not read by the walk from the root: %T", walk.walk)
	}

	if _, _, err := proofScope(""); err == nil {
		t.Error("a run with nowhere to keep a secret went ahead")
	}
}

// Asked once per name for a run, because every target is proven before the
// run and again where each check connects.
func TestARunAsksTheZoneOncePerName(t *testing.T) {
	z := &zone{}
	r := &remembered{walk: z}
	ctx := context.Background()

	for range 3 {
		_, _, _ = r.LookupChallenge(ctx, "_porch-challenge.example.com")
	}
	_, _, _ = r.LookupChallenge(ctx, "_porch-challenge.example.net")
	if n := z.questions(); n != 2 {
		t.Errorf("%d questions for two names", n)
	}
}

// And the scope reaches every check, which asks again where it connects. A
// run that skipped proveTargets — a new mode, a rearranged run() — is still
// refused by the check itself.
//
// Driven with a scope nothing is proven under and a target in a reserved
// domain, so a check that did not ask would go on to the network and fail
// there instead: the question counted is what tells the two apart.
func TestEveryCheckAsksForProofWhereItConnects(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration's hosts are compiled in, and it asks for no proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := []string{"unproven.test"}
	store := &results.Store{}

	runs := map[string]func(*verify.Scope) int{
		checkWeb: func(s *verify.Scope) int {
			return runWeb(ctx, s, target, time.Second, false, true, store)
		},
		checkMail: func(s *verify.Scope) int {
			return runMail(ctx, s, target, time.Second, "", true, store, nil, "")
		},
		checkDNS: func(s *verify.Scope) int {
			return runDNS(ctx, s, target, time.Second, "", true, store)
		},
		checkNames: func(s *verify.Scope) int {
			return runNames(ctx, target, namesOptions{Proof: s, Timeout: time.Second})
		},
	}
	for check, run := range runs {
		z := &zone{}
		if code := run(&verify.Scope{Secret: testSecret, Authority: z}); code == exitOK {
			t.Errorf("the %s check went ahead for a domain nobody proved", check)
		}
		if z.questions() == 0 {
			t.Errorf("the %s check never asked for proof", check)
		}
	}
}

// The TLS check is handed its scanner rather than building one, so the
// hand-over is read from the source: proven before the checks are chosen, and
// the scope set on the scanner before it runs.
func TestTheCommandLineProvesBeforeItChoosesACheck(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	prove := strings.Index(src, "proveTargets(ctx, s, *check, targets")
	choose := strings.Index(src, "switch *check {")
	if prove < 0 || choose < 0 || prove > choose {
		t.Error("run() does not prove every target before choosing a check")
	}

	tls := strings.Index(src, "scanner := tlsScanner(")
	scoped := strings.Index(src, "scanner.Verify = scope")
	run := strings.Index(src, "return runTLS(ctx, scanner")
	if tls < 0 || scoped < tls || run < scoped {
		t.Error("the TLS check is not handed the scope")
	}

	for _, call := range []*regexp.Regexp{
		regexp.MustCompile(`runWeb\(ctx, scope,`),
		regexp.MustCompile(`runMail\(ctx, scope,`),
		regexp.MustCompile(`runDNS\(ctx, scope,`),
		regexp.MustCompile(`Proof:\s+scope,`),
	} {
		if !call.MatchString(src) {
			t.Errorf("run() does not hand the scope on: %s", call)
		}
	}
}
