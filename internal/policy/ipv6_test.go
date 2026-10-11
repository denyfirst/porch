package policy

import "testing"

// One line for whether the name and its name servers have IPv6 addresses,
// saying only what was read.
func TestTheIPv6LineSaysWhatWasRead(t *testing.T) {
	servers := []NameServer{
		{Name: "ns1.example.net", Addresses: []string{"192.0.2.53", "2001:db8::53"}},
		{Name: "ns2.example.org", Addresses: []string{"198.51.100.53"}},
		{Name: "ns3.example.org", Reason: "the lookup did not complete"},
	}
	for want, f := range map[string]DNSFacts{
		"the name has an IPv6 address; 1 of 2 name servers have one": {IPv6: []string{"2001:db8::1"}, NameServers: servers},
		"the name has no IPv6 address; 1 of 2 name servers have one": {IPv4: []string{"192.0.2.1"}, NameServers: servers},
		"the name has no IPv6 address; 0 of 1 name server has one":   {NameServers: servers[1:2]},
		"1 of 2 name servers have an IPv6 address":                   {AddressReason: "the lookup ran out of time", NameServers: servers},
		"the name has an IPv6 address":                               {IPv6: []string{"2001:db8::1"}, NSReason: "the resolver refused the query", NameServers: servers},
		"":                                                           {AddressReason: "the lookup ran out of time", NSReason: "the resolver refused the query"},
	} {
		if got := DNSIPv6Line(f); got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	}
}

// And for the exchangers, counting one that was not read as such.
func TestTheExchangersIPv6LineCountsWhatWasRead(t *testing.T) {
	for want, f := range map[string]MailFacts{
		"":                                       {},
		"1 of 1 exchanger has an IPv6 address":   {MXIPv6: []string{"mx.example.com"}, MXIPv6Asked: 1, MXIPv6Read: 1},
		"0 of 2 exchangers have an IPv6 address": {MXIPv6Asked: 2, MXIPv6Read: 2},
		"2 of 3 exchangers have an IPv6 address; 1 not read": {MXIPv6: []string{"a", "b"}, MXIPv6Asked: 4, MXIPv6Read: 3},
	} {
		if got := MailIPv6Line(f); got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	}
}
