package mtasts

import (
	"testing"

	"github.com/denyfirst/porch/internal/display/displaytest"
)

// A policy file is whatever the domain's web server sends (audit 2026-10-05,
// F5). Read without panicking, and nothing returned may act on a display.
func FuzzParsePolicy(f *testing.F) {
	for _, seed := range []string{
		"version: STSv1\nmode: enforce\nmx: *.example.test\nmax_age: 86400\n",
		"version: STSv1\r\nmode: testing\r\nmx: mx\x1b[2J.example.test\r\nmax_age: 99999999999999999999\r\n",
		"mx: a\u202e.example\nmode: none\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		policy, reason := parse(body)
		displaytest.Clean(t, policy)
		displaytest.Clean(t, reason)
	})
}
