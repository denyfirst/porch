package dmarcreports

import (
	"testing"

	"github.com/denyfirst/porch/internal/display/displaytest"
)

// A DMARC reporting tag is whatever the domain publishes, and the places it
// names reach the operator's report (audit 2026-10-05, F5). Read without
// panicking, and nothing returned may act on a display.
func FuzzReportDestinations(f *testing.F) {
	for _, seed := range [][2]string{
		{"example.test", "mailto:dmarc@example.test,mailto:reports@vendor.test!10m"},
		{"example.test", "mailto:a\x1b[2J@vendor.test, https://x.test/\u202e"},
		{"EXAMPLE.test.", "mailto:,,,mailto:@,mailto:a@@b"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, domain, tag string) {
		displaytest.Clean(t, Read(domain, tag))
	})
}
