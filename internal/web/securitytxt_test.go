package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// Our contacts, as an installation and the demonstration answer for them.
//
// Where to report a problem in this project, and the key to encrypt the
// report to, are denyfirst.dev's: security.txt and the key are served there by
// denyfirst/site, whose tests hold the file's fields, its expiry, where it
// sends a reporter and the key's fingerprint. The demonstration served them
// itself until v0.37.0, and still answers the addresses it served them at
// with the way to them. An installation answers none of them.

// An installation publishes no contact of ours, at any of the addresses the
// demonstration answers for one.
//
// Its Canonical would name another host, its reporter would be sent to people
// who cannot fix that host, its Expires date would lapse on an installation
// left on one release, and our name would answer anyone probing for copies of
// this tool. See contactsMoved.
func TestAnInstallationPublishesNoContactOfOurs(t *testing.T) {
	for _, path := range []string{SecurityTxtPath, "/security.txt", PGPKeyPath} {
		w := get(t, path)
		if demo.Enabled {
			if w.Code != http.StatusMovedPermanently {
				t.Errorf("GET %s on the demonstration returned %d, want 301", path, w.Code)
			}
			continue
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on an installation returned %d, want 404", path, w.Code)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "denyfirst") {
			t.Errorf("GET %s on an installation names us: %q", path, w.Body.String())
		}
	}
}

// The demonstration sends somebody looking for our contacts to denyfirst.dev,
// at the path RFC 9116 names, from both the path it names and the short one
// somebody tries first, and the key from where it was. Answering any of them
// with a 404 costs a report.
//
// Each answer carries the headers every other answer does: a route added to
// the table without them would be the first hole in a claim the rest of the
// file makes.
func TestTheDemonstrationSendsOurContactsToDenyfirstDev(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the demonstration's alone; TestAnInstallationPublishesNoContactOfOurs covers this build")
	}
	for path, want := range map[string]string{
		SecurityTxtPath: "https://denyfirst.dev/.well-known/security.txt",
		"/security.txt": "https://denyfirst.dev/.well-known/security.txt",
		PGPKeyPath:      "https://denyfirst.dev/pgp-key.txt",
	} {
		w := get(t, path)
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != want {
			t.Errorf("GET %s: %d to %q, want 301 to %s", path, w.Code, w.Header().Get("Location"), want)
		}
		for header, value := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
			"Cache-Control":          "no-store",
		} {
			if got := w.Header().Get(header); got != value {
				t.Errorf("GET %s: %s = %q, want %q", path, header, got, value)
			}
		}
	}
}
