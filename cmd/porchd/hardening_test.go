package main

import (
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/policy"
)

// -version names every rule set this binary grades by.
//
// It named three of four: the DNS check's rule set was never printed, so a
// reader holding a DNS report could not learn from the binary which rules had
// produced it. And the reach line stays last, because the deploy check reads
// the line that begins "demonstration: " and nothing else about the layout.
func TestTheServiceVersionNamesEveryRuleSet(t *testing.T) {
	out := versionLines(reach(false))
	for _, want := range []string{version, policy.TLSVersion, policy.WebVersion, policy.MailVersion, policy.DNSVersion} {
		if !strings.Contains(out, "\n"+want+"\n") && !strings.Contains(out, " "+want+"\n") {
			t.Errorf("-version does not name %q:\n%s", want, out)
		}
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if last := lines[len(lines)-1]; last != reach(false) {
		t.Errorf("the reach line is not last, so a check reading the end of -version reads a policy: %q", last)
	}
}

// Whether a password is required and whether proof is required read an address
// the same way.
//
// passwordAllowed had its own reading, and for an address it could not parse it
// answered "loopback" where beyondLoopback answers "reachable". Nothing
// reachable took that path today, because the listener refuses the same
// strings; two readings of one decision are still one reading too many.
func TestAPasswordIsAskedForOnTheSameReadingOfAnAddress(t *testing.T) {
	for _, listen := range []string{
		"0.0.0.0:8443", ":8443", "[::]:8443", "192.0.2.10:443", "scanner.example:443",
		"", "not an address", "1.2.3.4",
	} {
		if (passwordAllowed(listen, false) == nil) != !beyondLoopback(listen) {
			t.Errorf("%q: a password and the loopback reading disagree", listen)
		}
	}
}

// The host guard is in front of everything the service answers, the gate
// included, and it is what the server is handed.
//
// Read from the source for the reason TestTheVersionOutputCarriesTheReachLine
// is: run() binds a port. The order is the property — a guard wrapped inside
// the gate would let the sign-in page and its script answer a rebound name,
// and a guard built and not handed to the server guards nothing.
func TestTheHostGuardIsInFrontOfEverything(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	gate := strings.Index(source, "handler = gate.Wrap(handler)")
	guard := strings.Index(source, "handler = api.GuardHost(handler)")
	server := strings.Index(source, "Handler: handler,")
	if gate < 0 || guard < 0 || server < 0 {
		t.Fatal("the gate, the host guard or the server's handler is no longer where this test looks")
	}
	if guard < gate {
		t.Error("the host guard is wrapped before the gate, so the gate is in front of it")
	}
	if server < guard {
		t.Error("the server is handed its handler before the host guard is put in front of it")
	}
}

// A monitor or register the operator points elsewhere is asked over HTTPS, or
// not at all.
//
// The question names a domain, and a register or CertSpotter carries the
// operator's key with it. The dialler allows port 80 for both, so an http://
// address sent both across the network in the clear.
func TestAMonitorOrRegisterIsAskedOnlyOverHTTPS(t *testing.T) {
	t.Setenv("SECURITYTRAILS_TOKEN", "a key")
	for _, bad := range []string{
		"http://crt.example/?q=%s", "ftp://crt.example/%s", "crt.example/%s",
		"https://user:key@crt.example/?q=%s", "https:///?q=%s",
	} {
		if _, err := namesSearcher("crtsh", bad, time.Second); err == nil {
			t.Errorf("-names-monitor-url %q was accepted", bad)
		} else if strings.Contains(err.Error(), "key@") {
			t.Errorf("the refusal repeats the credentials it refused: %v", err)
		}
		if _, err := namesRegister("securitytrails", bad, time.Second); err == nil {
			t.Errorf("-names-passive-url %q was accepted", bad)
		}
	}
	for _, good := range []string{"", "https://crt.example/?q=%s", "https://crt.example/search/%s"} {
		if _, err := namesSearcher("crtsh", good, time.Second); err != nil {
			t.Errorf("-names-monitor-url %q was refused: %v", good, err)
		}
		if _, err := namesRegister("securitytrails", good, time.Second); err != nil {
			t.Errorf("-names-passive-url %q was refused: %v", good, err)
		}
	}
}

// The demonstration searches the logs for its own name and keeps each check's
// report for an hour.
//
// Both are wired here rather than decided in a package, because they are what
// this binary is when it is the demonstration. The first is what lets its TLS
// report say what a proven copy's says about its own domain; the second is what
// stops a page anybody can refresh from pressing the parties that report now
// asks. Read from the source, because run() binds a port.
func TestTheDemonstrationSearchesItsOwnNameAndKeepsItsReports(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"if demo.Enabled {\n\t\tscanner.Logs = &ctsearch.CRTSh{Timeout: timeout}\n\t}",
		"api.KeepReportsFor(time.Hour)",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("the demonstration is not wired with %q", want)
		}
	}
	if s := serviceScanner(nil, nil, "", false, time.Second); (s.Logs != nil) != demoBuild() {
		t.Errorf("a service with no scope searches the logs: %v, and this build is the demonstration: %v",
			s.Logs != nil, demoBuild())
	}
}

// demoBuild is whether this test binary is the demonstration build.
func demoBuild() bool { return demo.Enabled }
