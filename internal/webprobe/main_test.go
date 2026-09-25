package webprobe

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// No test in this package sends a DNS query to anybody.
//
// The IPv6 measurement resolves the name it is given, and every test here
// probes a name — so without this, running the suite would put a query for
// each of them to whatever resolver the machine is configured with. The names
// are reserved ones that resolve to nothing, so nothing would have come back
// and nothing would have failed; the traffic would simply have been there,
// from a project whose whole argument is that it can be checked.
//
// A test that means to exercise the lookup sets LookupIPv6 on the Prober,
// which says what the name answers rather than hoping.
func TestMain(m *testing.M) {
	defaultLookupIPv6 = func(context.Context, string) ([]netip.Addr, error) {
		return nil, nil
	}
	os.Exit(m.Run())
}
