package mailscan

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// addressed is a zone that also answers for addresses, as the resolver every
// deployment uses does.
type addressed struct {
	*zone
	v6     map[string][]string
	broken map[string]bool
	asked  []string
}

func (a *addressed) LookupAddresses(_ context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	a.asked = append(a.asked, name)
	if qtype != dnsclient.TypeAAAA {
		return dnsclient.ZoneAnswer{}, errors.New("only AAAA is asked")
	}
	if a.broken[name] {
		return dnsclient.ZoneAnswer{}, dnsclient.ErrServerFail
	}
	var out []netip.Addr
	for _, text := range a.v6[name] {
		out = append(out, netip.MustParseAddr(text))
	}
	return dnsclient.ZoneAnswer{Addresses: out, Existed: true}, nil
}

// Whether each exchanger has an IPv6 address is asked of the resolver, one
// question each, and said in one line; one that could not be read is counted
// as such rather than as one without.
func TestWhetherTheExchangersHaveIPv6IsReadAndSaid(t *testing.T) {
	skipUnderDemo(t)
	z := &addressed{
		zone: &zone{records: map[string][]string{}, exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 10, Host: "mx1.example.net"}, {Preference: 20, Host: "mx2.example.net"}, {Preference: 30, Host: "mx3.example.net"}},
		}},
		v6:     map[string][]string{"mx1.example.net": {"2001:db8::25"}, "mx2.example.net": {"::ffff:192.0.2.25"}},
		broken: map[string]bool{"mx3.example.net": true},
	}
	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	f := got.Observed
	if len(f.MXIPv6) != 1 || f.MXIPv6[0] != "mx1.example.net" || f.MXIPv6Asked != 3 || f.MXIPv6Read != 2 {
		t.Errorf("read %v, %d asked, %d read; an IPv4 address written as IPv6 is not one", f.MXIPv6, f.MXIPv6Asked, f.MXIPv6Read)
	}
	if want := "1 of 2 exchangers have an IPv6 address; 1 not read"; f.MXIPv6Line != want {
		t.Errorf("the line reads %q, want %q", f.MXIPv6Line, want)
	}
	if len(z.asked) != 3 {
		t.Errorf("asked %v", z.asked)
	}

	// A resolver that cannot look up addresses asks nothing and says nothing.
	plain := &zone{records: map[string][]string{}, exchangers: z.exchangers}
	got, err = (&Scanner{Resolver: plain}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.MXIPv6Line != "" || got.Observed.MXIPv6Asked != 0 {
		t.Errorf("a resolver without addresses reads %+v", got.Observed)
	}
}
