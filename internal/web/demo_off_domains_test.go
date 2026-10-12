//go:build !demo

package web

import (
	"strings"
	"testing"
)

// Domains offers to add one, and to prove it: every installation requires
// proof.
func TestDomainsOffersAProof(t *testing.T) {
	proved := workspaceWith(t, "/domains")
	if !strings.Contains(proved, `id="domain-form"`) || !strings.Contains(proved, ">Add domain</button>") {
		t.Error("Domains offers no way to add a domain")
	}
}

// The privacy page says where the clipboard is written, because it is.
func TestThePrivacyPageSaysWhatIsCopied(t *testing.T) {
	page := workspaceWith(t, "/privacy")
	if strings.Contains(page, "Nothing is written to the clipboard") {
		t.Error("the privacy page says nothing is copied, and the Copy button beside a record copies it")
	}
	if !strings.Contains(page, "A report is never put there") {
		t.Error("the privacy page does not say a report stays out of the clipboard")
	}
}

// The privacy page names the servers a proof is read from, because they are
// asked directly now.
//
// Until 2026-09-29 the resolver asked them, and they saw the resolver's
// address. The proof is read from the root down since then, so the root, the
// top-level domain and the domain's own servers see this installation's — and
// a page listing who else is asked has to say so.
func TestThePrivacyPageSaysWhoAProofIsReadFrom(t *testing.T) {
	proved := workspaceWith(t, "/privacy")
	for _, want := range []string{"The domain's own name servers", "reached from the root", "this machine's address"} {
		if !strings.Contains(proved, want) {
			t.Errorf("the privacy page of an installation that requires proof does not say %q", want)
		}
	}
}
