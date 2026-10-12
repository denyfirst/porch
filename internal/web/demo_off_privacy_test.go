//go:build !demo

package web

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/httpapi"
)

// An installation somebody runs says what that installation does.
//
// Until the 2026-09-16 audit (A21) it served the demonstration's page, which
// described a rented server in Frankfurt, an abuse address at this project,
// and a scan that asks no authority anything — none of it true of a copy
// somebody else runs, and the last untrue of every one of them.
func TestASelfHostedCopySaysWhatItDoes(t *testing.T) {
	for _, page := range []string{privacyOf(t, Installation{})} {
		// The one link to the maker's own promises names their site in its
		// address, and the page names nothing about it.
		shown := strings.ReplaceAll(page, `href="https://denyfirst.dev/privacy"`, "")
		for _, never := range []string{"denyfirst.dev", "Hetzner", "Frankfurt", "no certificate authority is asked"} {
			if strings.Contains(shown, never) {
				t.Errorf("the self-hosted page says %q", never)
			}
		}
		for _, want := range []string{
			"What this installation keeps", "three minutes", "revocation list",
			"The DNS resolver", "No log of requests", "without warranty",
			"at least " + strconv.Itoa(httpapi.TargetThreshold()) + " scans",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("the self-hosted page does not say %q", want)
			}
		}
		for _, anchor := range []string{"promises", "kept", "scans", "stopping", "warranty"} {
			if !strings.Contains(page, `id="`+anchor+`"`) || !strings.Contains(page, `href="#`+anchor+`"`) {
				t.Errorf("the self-hosted page has no section #%s", anchor)
			}
		}
	}
}

// What it says follows how it was started: proof is always required, and the
// page says so, names the secret, and says nothing of a copy that checks any
// public name, which porchd does not start.
func TestTheSelfHostedPrivacyPageFollowsTheConfiguration(t *testing.T) {
	page := privacyOf(t, Installation{})
	for _, want := range []string{"Only names whose domain publishes", "A verification secret", "/.well-known/porch-challenge", "The domain's own name servers"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not say %q", want)
		}
	}
	for _, never := range []string{"checks any public name it is given", "Without proof", "No page body is read", "none."} {
		if strings.Contains(page, never) {
			t.Errorf("the page still says %q", never)
		}
	}
}

// The operator's own copy says it shows the operator the whole report.
//
// Every copy is behind its operator's password, so it reads what the command
// line reads (httpapi's operatorView), and its page says so. The stranger's
// report it once also described is not served by any installation porchd
// starts.
func TestTheOperatorsOwnCopySaysItShowsTheWholeReport(t *testing.T) {
	own := privacyOf(t, Installation{})
	for _, want := range []string{
		"The final page is read", "The contacts it names and its expiry date are shown to you",
		"asks each mail exchanger on port 25", "The mailboxes DMARC reports are sent to are shown to you",
		"Each of the zone's own name servers is also asked directly",
		"TLS-RPT records as the zone publishes them",
	} {
		if !strings.Contains(own, want) {
			t.Errorf("the operator's own copy does not say %q", want)
		}
	}
	for _, never := range []string{"No page body is read", "never an address", "No mail server is contacted", "crt.sh"} {
		if strings.Contains(own, never) {
			t.Errorf("the operator's own copy says %q", never)
		}
	}
}

// The retention the page states is the one the code holds.
func TestTheSelfHostedPageStatesTheRealRetentionPeriod(t *testing.T) {
	if got := httpapi.DefaultRetentionPeriod().Round(time.Minute); got != 3*time.Minute {
		t.Errorf("the page says three minutes and the defaults hold an address for %v", got)
	}
}

// The page says what is kept (audit 2026-09-18, D11). The history keeps
// every report as it was drawn, which includes the time it was measured, so
// the page does not say nothing records which name or when; and it names the
// addresses that try to sign in. Nothing is left of the two other modes it
// once described — a results directory, and a copy that kept nothing — since
// porchd starts neither.
func TestThePrivacyPageSaysWhatIsKept(t *testing.T) {
	guarded := flatten(guardedAs(t, "/privacy"))
	for _, want := range []string{"No log of requests.", "the time it was measured", "within six minutes of its last attempt", "What this page cannot speak for"} {
		if !strings.Contains(guarded, want) {
			t.Errorf("the page does not say %q", want)
		}
	}
	for _, never := range []string{
		"Nothing writes down which name was checked, by whom, or when.",
		"dated but not timed", "Which name was checked, and on which date, is kept",
		"kept on this machine", "not kept. Close the page", "No cookies",
	} {
		if strings.Contains(guarded, never) {
			t.Errorf("the page still says %q", never)
		}
	}
}

// privacyOf renders the served privacy page for one whole installation.
func privacyOf(t *testing.T, in Installation) string {
	t.Helper()
	configured(t, in)
	return flatten(get(t, "/privacy").Body.String())
}

// The page says which sources this installation asks, and never claims it
// asks none when it asks one.
//
// It claimed exactly that until 2026-09-27: "no certificate transparency log
// and no revocation responder is asked by this service", printed whatever the
// operator had configured. A page that tells somebody something untrue about
// their own installation is worse than a page that says nothing (N14).
func TestThePrivacyPageSaysWhichSourcesAreAsked(t *testing.T) {
	const none = "No certificate transparency monitor, no passive register and no revocation responder is asked"

	// A scope is what turns on the monitor and the authority's responder, and
	// every installation has one, so the page names both and never says it
	// asks nobody.
	proven := privacyOf(t, Installation{})
	if strings.Contains(proven, none) {
		t.Errorf("a proven installation says nobody is asked:\n%s", proven)
	}
	for _, want := range []string{
		"Cert Spotter",
		"which certificates exist for each name the TLS check reads",
		"which names under a domain appear in public certificates",
		"whether this certificate has been revoked",
	} {
		if !strings.Contains(proven, want) {
			t.Errorf("a proven installation does not say %q:\n%s", want, proven)
		}
	}
	if strings.Contains(proven, "crt.sh") || strings.Contains(proven, "-ask-responder") {
		t.Errorf("the page names a monitor or a flag that no longer exists:\n%s", proven)
	}

	// And each further source an operator can turn on.
	for _, tc := range []struct {
		what string
		in   Installation
		says string
	}{
		{"a register", Installation{Register: "securitytrails"},
			"passive register"},
		{"reading certificates", Installation{ReadsCertificates: true},
			"asked for the certificate it presents"},
	} {
		page := privacyOf(t, tc.in)
		if strings.Contains(page, none) {
			t.Errorf("with %s configured the page still says nobody is asked:\n%s", tc.what, page)
		}
		if !strings.Contains(page, tc.says) {
			t.Errorf("with %s configured the page does not say %q:\n%s", tc.what, tc.says, page)
		}
	}

	// The register is named, because which company was asked on the
	// operator's own account is the part they have to be able to check.
	named := privacyOf(t, Installation{Register: "virustotal"})
	if !strings.Contains(named, "virustotal") {
		t.Errorf("the page does not name the register:\n%s", named)
	}
}

// An installation that reads an address range says what that sends.
//
// Which is: nothing to the addresses. The questions are reverse lookups to the
// resolver the page already names, and the only new thing a reader learns is
// that this copy will do it — for whoever runs it, because no record can prove
// a range belongs to anybody the way one can prove a domain does.
func TestThePrivacyPageSaysWhatAnAddressRangeSends(t *testing.T) {
	page := privacyOf(t, Installation{})
	for _, want := range []string{
		"for an address range you name",
		"not one packet is sent to the addresses themselves",
		"only for whoever runs this installation",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not say %q:\n%s", want, page)
		}
	}
}
