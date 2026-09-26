package ptrnames

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// stubResolver answers from a table, so no test here asks anybody anything.
//
// Safe for the goroutines the reader uses: it is asked from eight at once, and
// a stub that appended to a slice without a lock is how the race detector
// earned its place in CI.
type stubResolver struct {
	mu    sync.Mutex
	names map[string][]string
	asked []string
	fail  bool
}

func (s *stubResolver) LookupPTR(_ context.Context, name string) (dnsclient.ZoneAnswer, error) {
	s.mu.Lock()
	s.asked = append(s.asked, name)
	s.mu.Unlock()

	if s.fail {
		return dnsclient.ZoneAnswer{}, errors.New("resolver detail nobody should see")
	}
	return dnsclient.ZoneAnswer{PTR: s.names[name]}, nil
}

func (s *stubResolver) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.asked))
	copy(out, s.asked)
	return out
}

// An address answers to a name, and the names under the domain are kept.
//
// The source that starts from the estate's other half: a machine whose name is
// in no certificate, in no record the domain publishes and in no register, but
// whose reverse record its own network kept up to date.
func TestWhatTheAddressesAnswerTo(t *testing.T) {
	resolver := &stubResolver{names: map[string][]string{
		"1.113.0.203.in-addr.arpa": {"mail.example.test."},
		"2.113.0.203.in-addr.arpa": {"build.example.test"},
		"3.113.0.203.in-addr.arpa": {"host3.provider.test"},
	}}

	r := &Reader{Resolver: resolver}
	got := r.Under(context.Background(), "example.test",
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/30")})

	if got.Reason != "" {
		t.Fatalf("the walk failed: %s", got.Reason)
	}
	if got.Addresses != 4 {
		t.Errorf("%d addresses were asked, want 4", got.Addresses)
	}
	if got.Answered != 3 {
		t.Errorf("%d addresses answered, want 3", got.Answered)
	}
	if len(got.Names) != 2 || got.Names[0] != "build.example.test" || got.Names[1] != "mail.example.test" {
		t.Errorf("the names kept are %v", got.Names)
	}

	// The provider's own name for a leased address is counted, not listed.
	if got.Foreign != 1 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 1", got.Foreign)
	}

	// And every address in the range was asked about under its reverse name.
	if len(resolver.questions()) != 4 {
		t.Errorf("%d questions were asked", len(resolver.questions()))
	}
	for _, q := range resolver.questions() {
		if !strings.HasSuffix(q, ".in-addr.arpa") {
			t.Errorf("an address was asked about as %q", q)
		}
	}
}

// A range wider than the bound is refused rather than walked.
//
// A /16 is sixty-five thousand questions to somebody's resolver, which is how
// an operator gets rate-limited off their own DNS. A /64 is not slow, it is
// impossible, and a tool that took the flag and then ran for a week would be
// lying about what it does.
func TestARangeTooWideToWalkIsRefused(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   bool
	}{
		{"203.0.113.0/24", true},
		{"203.0.113.0/20", true},
		{"203.0.0.0/16", false},
		{"10.0.0.0/8", false},
		{"2001:db8::/116", true},
		{"2001:db8::/64", false},
		{"2001:db8::/32", false},
	} {
		_, err := Addresses([]netip.Prefix{netip.MustParsePrefix(tc.prefix)})
		if (err == nil) != tc.want {
			t.Errorf("%s: walked=%v, want %v (%v)", tc.prefix, err == nil, tc.want, err)
		}
	}

	// A range too wide says so in its own words, rather than in the words for
	// too many addresses. They send an operator to two different fixes: one
	// says make this range narrower, the other says name fewer of them, and a
	// walk of a /16 that reported the second would have somebody deleting
	// ranges that were never the problem (I6).
	if _, err := Addresses([]netip.Prefix{netip.MustParsePrefix("203.0.0.0/16")}); err == nil ||
		!strings.Contains(err.Error(), "name a narrower one") {
		t.Errorf("a range wider than the bound is refused with %v", err)
	}

	// Refused rather than cut: an answer that quietly stopped short is the one
	// thing an inventory must never produce.
	_, err := Addresses([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/20"),
		netip.MustParsePrefix("198.51.100.0/24"),
	})
	if err == nil {
		t.Error("ranges holding more addresses than the bound were walked anyway")
	}
	if err != nil && !strings.Contains(err.Error(), "refused rather than cut short") {
		t.Errorf("the refusal reads %q", err)
	}
}

// The reverse name is the one a resolver answers.
func TestTheReverseNameIsTheOneAResolverAnswers(t *testing.T) {
	if got := Reverse(netip.MustParseAddr("203.0.113.42")); got != "42.113.0.203.in-addr.arpa" {
		t.Errorf("an IPv4 address is asked about as %q", got)
	}

	// RFC 3596 §2.5: one nibble per label, reversed, under ip6.arpa.
	got := Reverse(netip.MustParseAddr("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if got != want {
		t.Errorf("an IPv6 address is asked about as %q, want %q", got, want)
	}
}

// A resolver that answers nothing is not a range of nameless addresses.
//
// Nothing found is the reassuring answer, so a resolver that refused every
// question must not render as an estate with no reverse records (R4).
func TestAResolverThatAnsweredNothingIsNotAnEmptyRange(t *testing.T) {
	r := &Reader{Resolver: &stubResolver{fail: true}}
	got := r.Under(context.Background(), "example.test",
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/30")})

	if got.Addresses != 4 {
		t.Errorf("%d addresses were asked, want 4", got.Addresses)
	}
	if got.Answered != 0 {
		t.Errorf("%d addresses answered, want 0", got.Answered)
	}
	if len(got.Names) != 0 {
		t.Errorf("a resolver that answered nothing produced %v", got.Names)
	}
}

// Naming no range asks nothing at all.
//
// The zero value is "not read", which is what the report says. A source that
// ran with no ranges and reported an empty answer would read as a range with
// nothing in it.
func TestNamingNoRangeAsksNothing(t *testing.T) {
	resolver := &stubResolver{}
	got := (&Reader{Resolver: resolver}).Under(context.Background(), "example.test", nil)

	if got.Asked {
		t.Errorf("naming no range reported a walk: %+v", got)
	}
	if len(resolver.questions()) != 0 {
		t.Errorf("naming no range asked %v", resolver.questions())
	}
}

// What a reverse record says is untrusted, and is cleaned before it is kept.
//
// In a leased range the reverse record is written by the provider, and in any
// range it is written by whoever holds the address rather than by the person
// reading the report.
func TestWhatAReverseRecordSaysIsCleanedBeforeItIsKept(t *testing.T) {
	resolver := &stubResolver{names: map[string][]string{
		"1.113.0.203.in-addr.arpa": {"esc\x1b[31mape.example.test"},
		"2.113.0.203.in-addr.arpa": {"  spaced.example.test.  "},
		"3.113.0.203.in-addr.arpa": {"NOTexample.test"},
	}}

	got := (&Reader{Resolver: resolver}).Under(context.Background(), "example.test",
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/30")})

	for _, name := range got.Names {
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%q carries a control character", name)
			}
		}
		if name != strings.ToLower(name) || strings.HasSuffix(name, ".") {
			t.Errorf("%q was kept unfolded, so one host could be listed twice", name)
		}
	}
	if len(got.Names) != 2 {
		t.Errorf("the names kept are %v", got.Names)
	}

	// The name that ends with the domain as text is somebody else's estate.
	if got.Foreign != 1 {
		t.Errorf("%d names were dropped for belonging to somebody else, want 1", got.Foreign)
	}
}
