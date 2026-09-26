package dnsnames

import (
	"context"
	"errors"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// stubResolver answers from a table, so no test here asks anybody anything.
type stubResolver struct {
	mx  dnsclient.MXAnswer
	txt dnsclient.TXTAnswer
	ns  dnsclient.ZoneAnswer

	failMX, failTXT, failNS bool
}

func (s *stubResolver) LookupMX(context.Context, string) (dnsclient.MXAnswer, error) {
	if s.failMX {
		return dnsclient.MXAnswer{}, errors.New("resolver detail nobody should see")
	}
	return s.mx, nil
}

func (s *stubResolver) LookupTXT(context.Context, string) (dnsclient.TXTAnswer, error) {
	if s.failTXT {
		return dnsclient.TXTAnswer{}, errors.New("resolver detail nobody should see")
	}
	return s.txt, nil
}

func (s *stubResolver) LookupNS(context.Context, string) (dnsclient.ZoneAnswer, error) {
	if s.failNS {
		return dnsclient.ZoneAnswer{}, errors.New("resolver detail nobody should see")
	}
	return s.ns, nil
}

// A domain's own records name hosts, and each name says which record named it.
//
// This is the cheapest source there is and the last one anybody thinks of: an
// MX names the machine that takes the mail, a sender policy names the hosts
// allowed to send it, a delegation names the servers that answer. None of it is
// guessed and none of it is hidden.
func TestWhatADomainsOwnRecordsName(t *testing.T) {
	r := &Reader{Resolver: &stubResolver{
		mx: dnsclient.MXAnswer{Existed: true, Records: []dnsclient.MX{
			{Preference: 10, Host: "mail.example.test"},
			{Preference: 20, Host: "backup-mail.example.test"},
			// Somebody else's infrastructure, which is not this estate.
			{Preference: 30, Host: "mx.provider.test"},
		}},
		txt: dnsclient.TXTAnswer{Existed: true, Values: []string{
			"google-site-verification=abc",
			"v=spf1 a:smtp.example.test include:_spf.provider.test mx:mail.example.test ip4:93.184.216.0/24 -all",
		}},
		ns: dnsclient.ZoneAnswer{NS: []string{"ns1.example.test.", "ns8451.hostgator.com."}},
	}}

	got := r.Under(context.Background(), "Example.TEST.")

	if got.Reason != "" {
		t.Fatalf("the records were read and this says %q", got.Reason)
	}

	want := map[string][]Source{
		"mail.example.test":        {FromMX, FromSPF},
		"backup-mail.example.test": {FromMX},
		"smtp.example.test":        {FromSPF},
		"ns1.example.test":         {FromNS},
	}
	if len(got.Names) != len(want) {
		t.Fatalf("named %d hosts, want %d: %+v", len(got.Names), len(want), got.Names)
	}
	for _, n := range got.Names {
		sources, ok := want[n.Name]
		if !ok {
			t.Errorf("%s is in the inventory and should not be", n.Name)
			continue
		}
		if len(n.Sources) != len(sources) {
			t.Errorf("%s is credited to %v, want %v", n.Name, n.Sources, sources)
			continue
		}
		for i, s := range sources {
			if n.Sources[i] != s {
				t.Errorf("%s is credited to %v, want %v", n.Name, n.Sources, sources)
				break
			}
		}
	}

	// Other people's names are counted and dropped: a mail provider's servers
	// are evidence about the answer rather than part of this estate.
	if got.Foreign != 3 {
		t.Errorf("%d foreign names, want 3: the provider's exchanger, the include in the "+
			"sender policy, and the name server", got.Foreign)
	}

	// Sorted, so two runs of one search read the same.
	for i := 1; i < len(got.Names); i++ {
		if got.Names[i-1].Name > got.Names[i].Name {
			t.Errorf("the names are not sorted: %q before %q", got.Names[i-1].Name, got.Names[i].Name)
		}
	}
}

// A sender policy is read for the mechanisms that carry a name, and no others.
//
// Most of a policy is not names. `ip4:` and `ip6:` carry addresses, `all` is a
// verdict, and a qualifier in front of any of them says what happens rather
// than where. Reading an address as a host name would put something in the
// inventory that no resolver can answer for.
func TestOnlyTheMechanismsThatCarryANameAreRead(t *testing.T) {
	for _, c := range []struct {
		record string
		want   []string
	}{
		{"v=spf1 -all", nil},
		{"v=spf1 ip4:93.184.216.0/24 ip6:2001:db8::/32 -all", nil},
		{"v=spf1 a:one.example.test mx:two.example.test -all", []string{"one.example.test", "two.example.test"}},
		{"v=spf1 include:_spf.provider.test ~all", []string{"_spf.provider.test"}},
		{"v=spf1 exists:%{i}.spf.example.test -all", []string{"%{i}.spf.example.test"}},
		{"v=spf1 redirect=other.example.test", []string{"other.example.test"}},
		// A qualifier in front of a mechanism does not change what it names.
		{"v=spf1 -a:blocked.example.test ?mx:maybe.example.test +include:yes.example.test -all",
			[]string{"blocked.example.test", "maybe.example.test", "yes.example.test"}},
		// A prefix length is about addresses, not about the name.
		{"v=spf1 a:net.example.test/24 -all", []string{"net.example.test"}},
		// Bare `a` and `mx` name the domain itself, which is not a discovery.
		{"v=spf1 a mx -all", nil},
		// Not a sender policy at all.
		{"google-site-verification=abc", nil},
		{"v=DMARC1; p=reject; rua=mailto:dmarc@example.test", nil},
	} {
		got := senderPolicyNames(c.record)
		if len(got) != len(c.want) {
			t.Errorf("%q named %v, want %v", c.record, got, c.want)
			continue
		}
		for i, w := range c.want {
			if got[i] != w {
				t.Errorf("%q named %v, want %v", c.record, got, c.want)
				break
			}
		}
	}
}

// A name belongs to the estate only on a label boundary.
func TestANameBelongsOnlyOnALabelBoundary(t *testing.T) {
	for _, c := range []struct {
		name, domain string
		want         bool
	}{
		{"example.test", "example.test", true},
		{"mail.example.test", "example.test", true},
		{"a.b.example.test", "example.test", true},
		{"notexample.test", "example.test", false},
		{"example.test.evil.test", "example.test", false},
		{"example.tes", "example.test", false},
	} {
		if got := under(c.name, c.domain); got != c.want {
			t.Errorf("under(%q, %q) = %v, want %v", c.name, c.domain, got, c.want)
		}
	}
}

// One lookup failing does not lose the other two.
//
// A domain with no MX still has a sender policy worth reading. Reporting
// nothing because one record type was unavailable would throw away what was
// established in order to report what was not (R4).
func TestOneLookupFailingDoesNotLoseTheOthers(t *testing.T) {
	r := &Reader{Resolver: &stubResolver{
		failMX: true,
		txt: dnsclient.TXTAnswer{Existed: true, Values: []string{
			"v=spf1 a:smtp.example.test -all",
		}},
		ns: dnsclient.ZoneAnswer{NS: []string{"ns1.example.test"}},
	}}

	got := r.Under(context.Background(), "example.test")
	if got.Reason != "" {
		t.Fatalf("two lookups answered and this says %q", got.Reason)
	}
	if len(got.Names) != 2 {
		t.Errorf("named %+v, want the two the working lookups gave", got.Names)
	}
}

// Every lookup failing is a fact about the resolver, not about the domain.
//
// Saying the records named nothing would be the reassuring wrong answer: an
// operator would read it as an estate with no mail and no delegation.
func TestEveryLookupFailingIsNotAnEmptyDomain(t *testing.T) {
	r := &Reader{Resolver: &stubResolver{failMX: true, failTXT: true, failNS: true}}

	got := r.Under(context.Background(), "example.test")
	if got.Reason == "" {
		t.Error("every lookup failed and the answer reads as a domain whose records name nothing")
	}
	if len(got.Names) != 0 {
		t.Errorf("a failed read produced names: %+v", got.Names)
	}
	if !got.Asked {
		t.Error("a read that was attempted reads as one that was not")
	}
	// And the resolver's own words never travel (I6).
	if got.Reason != "the domain's own records could not be read" {
		t.Errorf("the reason reads %q", got.Reason)
	}
}
