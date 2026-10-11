package main

import (
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/ctsearch"
)

// What each switch reaches.
//
// A flag parsed into a variable nobody reads compiles, runs, prints itself in
// the usage text, and does nothing. -resolver was exactly that for the length
// of one sabotage: declared, documented, never assigned. Nothing here scans
// anything; it asks what the scanner was built with.

// The command line lifts two restrictions the service keeps, by default.
func TestTheCommandLineLiftsWhatOnlyAServiceNeeds(t *testing.T) {
	s := tlsScanner(time.Second, false, "")

	if !s.AllowAnyPort {
		t.Error("the port allow list is enforced on the command line; a local operator " +
			"scanning their own service on 8444 is not the abuse that list guards against")
	}
	if !s.AllowIPTargets {
		t.Error("an address is refused on the command line; an operator checking their own " +
			"server before its name resolves is the case this one exists for")
	}
}

// A named resolver reaches the scanner.
func TestTheResolverFlagReachesTheScanner(t *testing.T) {
	s := tlsScanner(time.Second, false, "192.0.2.9:53")

	if s.Resolver == nil {
		t.Fatal("-resolver was given and the scanner has none, so the CAA lookup will read " +
			"this machine's configuration instead of the address the operator named")
	}
	if s.Resolver.Server != "192.0.2.9:53" {
		t.Errorf("the scanner asks %q, want the address that was named", s.Resolver.Server)
	}
}

// And no resolver leaves the machine's own configuration to be read.
//
// The other direction, and it is the one that matters most: a default that
// quietly pointed every scan at some fixed resolver would move who learns what
// is being scanned, which is not a decision to make on an operator's behalf.
func TestNoResolverFlagLeavesTheMachinesOwnConfiguration(t *testing.T) {
	s := tlsScanner(time.Second, false, "")

	if s.Resolver != nil {
		t.Errorf("no -resolver was given and the scanner was built with %+v; the machine's "+
			"own configuration is what an empty flag means", s.Resolver)
	}
}

// The private-address guard is off until it is asked for, and then it is off.
func TestPrivateAddressesAreReachedOnlyWhenAsked(t *testing.T) {
	if s := tlsScanner(time.Second, false, ""); s.Prober.Dial != nil {
		t.Error("the prober was given a dialler without -allow-private; the default has to be " +
			"safedial, or a mistyped name can be aimed at an internal host")
	}
	if s := tlsScanner(time.Second, true, ""); s.Prober.Dial == nil {
		t.Error("-allow-private was given and the prober still dials through safedial, so the " +
			"switch does nothing and an operator scanning their own network cannot")
	}
}

// Every scan asks the sources that hold the answer: the transparency monitor
// which certificates exist for the name, and the certificate's own authority
// whether it has been revoked.
//
// Each waited for a flag until 2026-10-10. Every name this command checks is
// one its operator proved, and those answers are held by those sources and
// nowhere else, so a report without them was a report with a hole in it.
func TestEveryScanAsksTheMonitorAndTheAuthority(t *testing.T) {
	t.Setenv("CERTSPOTTER_TOKEN", "a key")
	s := tlsScanner(time.Second, false, "")
	if c, ok := s.Logs.(*ctsearch.CertSpotter); !ok {
		t.Errorf("the scan asks %T, want Cert Spotter", s.Logs)
	} else if c.Token != "a key" {
		t.Error("the key in CERTSPOTTER_TOKEN does not reach the monitor")
	}
	if s.Responder == nil {
		t.Error("the scan does not ask the certificate's authority whether it was revoked")
	}
}

// A flag that was removed is refused with the reason it went, rather than
// with the flag package's "not defined".
func TestARemovedFlagIsRefusedWithItsReason(t *testing.T) {
	for _, flag := range []string{"-check-logs", "--ask-responder", "-monitor=crtsh", "-monitor-url=https://x/"} {
		err := removedFlags([]string{"-check", "tls", flag, "example.com"})
		if err == nil || !strings.Contains(err.Error(), "was removed") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	if err := removedFlags([]string{"-json", "--", "-check-logs"}); err != nil {
		t.Errorf("an argument after -- was read as a flag: %v", err)
	}
}

// The command line names the addresses a certificate gives for checking its
// own revocation.
//
// It runs on the operator's own machine, from their own address, and the
// report goes to whoever ran it — the argument AllowAnyPort and AllowIPTargets
// rest on here. The addresses are the issuing authority's, and on the
// operator's own terminal the authority is the one that issued their
// certificate: when revocation cannot be established, which address failed is
// the part they act on and a count cannot say it.
//
// Asserted because a field that is set, documented and handed to nothing has
// happened twice in this repository.
func TestTheCommandLineNamesTheRevocationAddresses(t *testing.T) {
	s := tlsScanner(5*time.Second, false, "")

	if !s.ShowRevocationURLs {
		t.Error("the command line withholds the revocation addresses from the operator running " +
			"it, so a list that could not be fetched is reported without saying from where")
	}
}
