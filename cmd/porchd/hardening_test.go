package main

import (
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
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

// The demonstration searches the logs for its own name, measures its own hosts
// again after a minute, and keeps for longer what it had to ask somebody else.
//
// All of it is wired here rather than decided in a package, because it is what
// this binary is when it is the demonstration. The search is what lets its TLS
// report say what a proven copy's says about its own domain; the intervals are
// what stop a page anybody can refresh from pressing the parties a report
// asks, without showing a visitor a quarter of an hour's history as the state
// of our own hosts. Read from the source, because run() binds a port.
func TestTheDemonstrationSearchesItsOwnNameAndKeepsItsReports(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"if demo.Enabled {\n\t\tscanner.Logs = demoMonitor(timeout)\n\t}",
		"api.KeepReportsFor(demoFresh)",
		`api.KeepCheckFor("mail", demoKeep)`,
		`api.KeepCheckFor("dns", demoKeep)`,
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

// The demonstration asks the monitor that keeps up first, and the other only
// when it does not answer, keeping each answer for demoAsk.
//
// On 2026-10-09 crt.sh listed one of the domain's four valid certificates and
// Cert Spotter all four, and the report built on crt.sh's answer told a
// visitor about a certificate the server was not presenting while leaving out
// the three it had issued since.
func TestTheDemonstrationAsksTheMonitorThatKeepsUpFirst(t *testing.T) {
	m := demoMonitor(time.Second)
	if m.For != demoAsk {
		t.Errorf("a monitor's answer is kept for %v, want %v", m.For, demoAsk)
	}
	f, ok := m.Monitor.(*ctsearch.Fallback)
	if !ok {
		t.Fatalf("the demonstration's monitor is a %T, with nothing to fall back on", m.Monitor)
	}
	if _, ok := f.First.(*ctsearch.CertSpotter); !ok {
		t.Errorf("the first monitor asked is a %T, want Cert Spotter", f.First)
	}
	if _, ok := f.Then.(*ctsearch.CRTSh); !ok {
		t.Errorf("the monitor asked when the first fails is a %T, want crt.sh", f.Then)
	}
	if demoAsk > time.Hour || demoFresh > 5*time.Minute {
		t.Errorf("the demonstration shows answers up to %v and reports up to %v old", demoAsk, demoFresh)
	}
}
