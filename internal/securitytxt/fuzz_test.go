package securitytxt

import (
	"testing"

	"github.com/denyfirst/porch/internal/display/displaytest"
)

// A security.txt is whatever the site publishes, and its contacts reach the
// operator's report (audit 2026-10-05, F5). Read without panicking, kept or
// not, and nothing returned may act on a display.
func FuzzParseSecurityTxt(f *testing.F) {
	for _, seed := range []string{
		"Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n",
		"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nContact: https://example.test/\x1b[2J\n",
		"Contact: mailto:a\u202e@example.test\r\nExpires: not a date\r\nPolicy: https://example.test/p\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		displaytest.Clean(t, parse(body, true))
		displaytest.Clean(t, parse(body, false))
	})
}
