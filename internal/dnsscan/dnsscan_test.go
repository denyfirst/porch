package dnsscan

import (
	"context"
	// #nosec G505 -- a test that reads a SHA-1 digest computes one
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/verify"
)

// zone answers from a table, so a test needs no network.
type zone struct {
	addresses map[string][]string
	ns        []string
	soa       *dnsclient.SOA
	ds        []dnsclient.DS
	keys      []dnsclient.DNSKEY
	text      []string
	alias     map[string][]string
	missing   map[string]bool

	validated bool

	// fail names the lookups that answer with an error rather than with
	// records, which is a different thing everywhere in this project.
	fail map[string]error
}

func (z *zone) LookupAddresses(_ context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["addresses:"+name]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	var out []netip.Addr
	for _, text := range z.addresses[name] {
		addr := netip.MustParseAddr(text)
		if (qtype == dnsclient.TypeA) == addr.Is4() {
			out = append(out, addr)
		}
	}
	return dnsclient.ZoneAnswer{Addresses: out, Existed: z.exists(name), Validated: z.validated}, nil
}

func (z *zone) LookupNS(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["ns"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{NS: z.ns, Existed: true, Validated: z.validated}, nil
}

func (z *zone) LookupSOA(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["soa"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	out := dnsclient.ZoneAnswer{Existed: true, Validated: z.validated}
	if z.soa != nil {
		out.SOA = []dnsclient.SOA{*z.soa}
	}
	return out, nil
}

func (z *zone) LookupDS(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["ds"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{DS: z.ds, Existed: true, Validated: z.validated}, nil
}

func (z *zone) LookupDNSKEY(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["dnskey"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{Keys: z.keys, Existed: true, Validated: z.validated}, nil
}

func (z *zone) LookupCNAME(_ context.Context, name string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["cname:"+name]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{Alias: z.alias[name], Existed: z.exists(name)}, nil
}

// exists is what the resolver says about a name: a name with no records of the
// type asked for still exists, and one that was deleted does not.
func (z *zone) exists(name string) bool { return !z.missing[name] }

func (z *zone) LookupTXT(_ context.Context, _ string) (dnsclient.TXTAnswer, error) {
	return dnsclient.TXTAnswer{Values: z.text, Existed: true}, nil
}

// served is a zone that is delegated properly and signed properly, which every
// test below then breaks in one way.
func served(t *testing.T) *zone {
	t.Helper()

	key := dnsclient.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, Key: []byte("a key, in the test's imagination")}
	return &zone{
		addresses: map[string][]string{
			"example.com":     {"192.0.2.10", "2001:db8:1::10"},
			"ns1.example.net": {"192.0.2.53"},
			"ns2.example.org": {"198.51.100.53"},
		},
		ns:      []string{"ns1.example.net", "ns2.example.org"},
		soa:     &dnsclient.SOA{Primary: "ns1.example.net", Mailbox: "noc.example.com", Serial: 7, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600},
		keys:    []dnsclient.DNSKEY{key},
		ds:      []dnsclient.DS{signerFor(t, "example.com", key)},
		text:    []string{"v=spf1 -all"},
		alias:   map[string][]string{},
		missing: map[string]bool{},
		fail:    map[string]error{},
	}
}

// signerFor is the digest a parent publishes for a key, computed the way the
// check computes it, so a test says the two agree rather than restating one.
func signerFor(t *testing.T, owner string, key dnsclient.DNSKEY) dnsclient.DS {
	t.Helper()

	wire, err := wireName(owner)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}
	sum := sha256.New()
	sum.Write(wire)
	sum.Write(keyRDATA(key))
	return dnsclient.DS{KeyTag: keyTag(key), Algorithm: key.Algorithm, DigestType: 2, Digest: sum.Sum(nil)}
}

func read(t *testing.T, z *zone) *Result {
	t.Helper()

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}

func ruleIDs(r *Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func has(r *Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// A zone delegated to two servers on two networks, signed, with a chain that
// checks out, is graded strong and carries what it published.
func TestAZoneThatIsServedAndSignedReadsStrong(t *testing.T) {
	got := read(t, served(t))

	if got.Verdict != policy.Strong || len(got.Findings) != 0 {
		t.Errorf("verdict %q with %v", got.Verdict, ruleIDs(got))
	}
	if got.Policy != policy.DNSVersion || got.Observed.Policy != policy.DNSVersion {
		t.Errorf("the rule set is %q / %q", got.Policy, got.Observed.Policy)
	}
	if len(got.Observed.IPv4) != 1 || got.Observed.IPv4[0] != "192.0.2.10" {
		t.Errorf("the IPv4 addresses read %v", got.Observed.IPv4)
	}
	if len(got.Observed.IPv6) != 1 || got.Observed.IPv6[0] != "2001:db8:1::10" {
		t.Errorf("the IPv6 addresses read %v, and both types are asked for separately", got.Observed.IPv6)
	}
	if len(got.Observed.NameServers) != 2 || got.Observed.NameServers[0].Name != "ns1.example.net" {
		t.Errorf("the servers read %+v", got.Observed.NameServers)
	}
	if got.Observed.Networks != 2 {
		t.Errorf("%d networks, and the two servers are on 192.0.2/24 and 198.51.100/24", got.Observed.Networks)
	}
	if !got.Observed.SOAFound || got.Observed.SOASerial != 7 {
		t.Errorf("the record at the top of the zone reads %+v", got.Observed)
	}
	if !got.Observed.Signed || !got.Observed.ChainMatched || len(got.Observed.Signers) != 1 || !got.Observed.Signers[0].Matched {
		t.Errorf("the chain reads signed %v matched %v %+v", got.Observed.Signed, got.Observed.ChainMatched, got.Observed.Signers)
	}
	if len(got.Observed.Text) != 1 || got.Observed.Text[0] != "v=spf1 -all" {
		t.Errorf("the text records read %v", got.Observed.Text)
	}
}

// The delegation is graded against what the standards require, and nothing
// else: two servers, on networks that do not fail together, each resolvable.
func TestTheDelegationIsGradedAgainstWhatIsRequired(t *testing.T) {
	one := served(t)
	one.ns = []string{"ns1.example.net"}
	if got := read(t, one); !has(got, "dns.one-name-server") || got.Verdict != policy.Weak {
		t.Errorf("one server: %q %v", got.Verdict, ruleIDs(got))
	}

	together := served(t)
	together.addresses["ns2.example.org"] = []string{"192.0.2.54"}
	if got := read(t, together); !has(got, "dns.name-servers-one-network") {
		t.Errorf("two servers on one network: %v", ruleIDs(got))
	}

	if got := read(t, served(t)); has(got, "dns.name-servers-one-network") {
		t.Errorf("two servers on two networks were graded: %v", ruleIDs(got))
	}

	lame := served(t)
	lame.addresses["ns2.example.org"] = nil
	got := read(t, lame)
	if !has(got, "dns.name-server-without-address") {
		t.Errorf("a server that resolves to nothing: %v", ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.name-server-without-address" && !strings.Contains(f.Rationale, "ns2.example.org") {
			t.Error("the finding does not say which server")
		}
	}

	// A lookup that failed is not a server without an address (R4).
	unread := served(t)
	unread.fail["addresses:ns2.example.org"] = errors.New("the network did not answer")
	if got := read(t, unread); has(got, "dns.name-server-without-address") {
		t.Errorf("a lookup that failed was graded as a lame delegation: %v", ruleIDs(got))
	}
}

// The chain is the finding this check exists for: a zone whose parent anchors
// DNSSEC and whose keys do not match is broken for everybody behind a
// validating resolver, and works for whoever set it up.
func TestABrokenChainIsTheFindingThisExistsFor(t *testing.T) {
	rotated := served(t)
	rotated.keys = []dnsclient.DNSKEY{{Flags: 257, Protocol: 3, Algorithm: 13, Key: []byte("a key nobody told the registrar about")}}
	got := read(t, rotated)
	if !has(got, "dns.dnssec-chain-broken") || got.Verdict != policy.Insecure {
		t.Errorf("a rotated key: %q %v", got.Verdict, ruleIDs(got))
	}

	none := served(t)
	none.keys = nil
	if got := read(t, none); !has(got, "dns.dnssec-no-keys") || got.Verdict != policy.Insecure {
		t.Errorf("no key at all: %q %v", got.Verdict, ruleIDs(got))
	}

	// An unsigned zone is a choice, not a fault.
	unsigned := served(t)
	unsigned.ds = nil
	got = read(t, unsigned)
	if len(got.Findings) != 0 || got.Verdict != policy.Strong {
		t.Errorf("an unsigned zone: %q %v", got.Verdict, ruleIDs(got))
	}
	if !noteSaying(got, "not signed") {
		t.Error("an unsigned zone is not said to be unsigned")
	}

	// A digest type this does not compute is neither matched nor ruled out.
	unknown := served(t)
	unknown.ds = []dnsclient.DS{{KeyTag: 1, Algorithm: 13, DigestType: 9, Digest: []byte("something else")}}
	got = read(t, unknown)
	if has(got, "dns.dnssec-chain-broken") {
		t.Errorf("a digest type nobody here computes was graded as a broken chain: %v", ruleIDs(got))
	}
	if !got.Observed.Signers[0].Unsupported || !noteSaying(got, "neither matched nor ruled out") {
		t.Errorf("an unsupported digest reads %+v", got.Observed.Signers)
	}

	// A lookup that failed is not a chain that does not check out.
	unread := served(t)
	unread.fail["dnskey"] = dnsclient.ErrServerFail
	got = read(t, unread)
	if len(got.Findings) != 0 || !noteSaying(got, "could not be checked") {
		t.Errorf("a failed key lookup: %v", ruleIDs(got))
	}
	if strings.Contains(strings.Join(noteTexts(got), " "), "resolver.invalid") {
		t.Error("a note carries the resolver's own error")
	}
}

// SHA-1 is graded where the chain works, because the finding is about the hash
// and not about the chain.
func TestASHA1DigestIsSaidWhereTheChainWorks(t *testing.T) {
	old := served(t)
	key := old.keys[0]
	signer := signerFor(t, "example.com", key)
	sum := sha1Digest(t, "example.com", key)
	old.ds = []dnsclient.DS{{KeyTag: signer.KeyTag, Algorithm: signer.Algorithm, DigestType: 1, Digest: sum}}

	got := read(t, old)
	if !got.Observed.ChainMatched {
		t.Fatalf("a SHA-1 digest that matches was read as not matching: %+v", got.Observed.Signers)
	}
	if !has(got, "dns.dnssec-sha1-digest") || got.Verdict != policy.Weak {
		t.Errorf("SHA-1: %q %v", got.Verdict, ruleIDs(got))
	}
}

// A name inside a zone is not a zone, and nothing about the zone above it is
// reported as though it described this name.
func TestANameInsideAZoneIsNotGradedAsOne(t *testing.T) {
	inside := served(t)
	inside.soa = nil

	got, err := (&Scanner{Resolver: inside}).Scan(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Verdict != "" || len(got.Findings) != 0 {
		t.Errorf("verdict %q with %v", got.Verdict, ruleIDs(got))
	}
	if len(got.Observed.NameServers) != 0 || got.Observed.Signed {
		t.Errorf("the zone above it was read as this name's: %+v", got.Observed)
	}
	if !noteSaying(got, "No zone begins at this name") {
		t.Errorf("the notes are %v", noteTexts(got))
	}
}

// The three boundaries every check asks, asked here too and before anything is
// looked up.
func TestTheBoundariesAreAskedBeforeAnythingIsLookedUp(t *testing.T) {
	asked := served(t)
	scope := &verify.Scope{Secret: []byte("a deployment secret"), Resolver: nothingPublished{}}
	if _, err := (&Scanner{Resolver: asked, Verify: scope}).Scan(context.Background(), "example.com"); !errors.Is(err, verify.ErrNotVerified) {
		t.Errorf("an unproven domain: %v", err)
	}

	for _, target := range []string{"", "localhost", "example.com/path", "example.com:53", "someone@example.com"} {
		if _, err := (&Scanner{Resolver: served(t)}).Scan(context.Background(), target); err == nil {
			t.Errorf("%q was scanned", target)
		} else if strings.Contains(err.Error(), target) && target != "" {
			t.Errorf("%q: the refusal repeats what was typed: %v", target, err)
		}
	}
}

type nothingPublished struct{}

func (nothingPublished) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, true, nil
}

func noteTexts(r *Result) []string {
	var out []string
	for _, n := range r.Notes {
		out = append(out, n.Text)
	}
	return out
}

func noteSaying(r *Result, phrase string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n.Text, phrase) {
			return true
		}
	}
	return false
}

// sha1Digest is the old digest a parent may still hold, computed here so the
// test says the check reads it rather than restating what the check computes.
func sha1Digest(t *testing.T, owner string, key dnsclient.DNSKEY) []byte {
	t.Helper()

	wire, err := wireName(owner)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}
	// #nosec G401 -- the same hash the record uses, in a test that reads one
	sum := sha1.New()
	sum.Write(wire)
	sum.Write(keyRDATA(key))
	return sum.Sum(nil)
}

// The digest is compared, and so is the tag the parent names the key by.
//
// Two sabotages escaped the test above: one that matched every digest and one
// that ignored the key tag. Neither could be seen, because the only unmatched
// case there is a key the parent never names, which the tag alone already
// rules out. These are the two cases that separate them: a parent naming the
// right key with the wrong digest, and one whose digest covers a key it names
// by another tag — which is contradictory data, and not a chain that checks
// out.
func TestTheDigestAndTheTagBothHaveToAgree(t *testing.T) {
	wrongDigest := served(t)
	signer := wrongDigest.ds[0]
	signer.Digest = make([]byte, len(signer.Digest))
	wrongDigest.ds = []dnsclient.DS{signer}
	got := read(t, wrongDigest)
	if got.Observed.ChainMatched || !has(got, "dns.dnssec-chain-broken") {
		t.Errorf("the right key with the wrong digest: matched %v, %v", got.Observed.ChainMatched, ruleIDs(got))
	}

	// And a digest that begins with the right bytes and carries more is not the
	// right digest: comparing only as far as the shorter one would accept it.
	longer := served(t)
	signer = longer.ds[0]
	signer.Digest = append(append([]byte{}, signer.Digest...), 0)
	longer.ds = []dnsclient.DS{signer}
	if got := read(t, longer); got.Observed.ChainMatched {
		t.Error("a digest with a byte added was read as matching")
	}

	wrongTag := served(t)
	signer = wrongTag.ds[0]
	signer.KeyTag++
	wrongTag.ds = []dnsclient.DS{signer}
	got = read(t, wrongTag)
	if got.Observed.ChainMatched || !has(got, "dns.dnssec-chain-broken") {
		t.Errorf("a digest under another tag: matched %v, %v", got.Observed.ChainMatched, ruleIDs(got))
	}
}

// An alias is read wherever the name is one, and what it points at is asked
// about: a target that is gone leaves the name resolving to nothing, and where
// the target is a name anybody can claim, whoever claims it answers for this
// one.
func TestAnAliasIsReadAndItsTargetIsAskedAbout(t *testing.T) {
	ctx := context.Background()

	living := served(t)
	living.soa = nil
	living.alias["www.example.com"] = []string{"pages.example.net"}
	got, err := (&Scanner{Resolver: living}).Scan(ctx, "www.example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.Alias != "pages.example.net" || !got.Observed.AliasTargetExists {
		t.Errorf("an alias to a name that exists reads %+v", got.Observed)
	}
	if !noteSaying(got, "alias for pages.example.net, so everything it answers comes from there") {
		t.Errorf("the notes are %v", noteTexts(got))
	}

	gone := served(t)
	gone.soa = nil
	gone.alias["www.example.com"] = []string{"deleted.example.net"}
	gone.missing["deleted.example.net"] = true
	got, err = (&Scanner{Resolver: gone}).Scan(ctx, "www.example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.AliasTargetExists {
		t.Error("a target that does not exist was read as existing")
	}
	if !noteSaying(got, "does not exist") || !noteSaying(got, "whoever claims it next") {
		t.Errorf("a dangling alias is not explained: %v", noteTexts(got))
	}

	// A lookup that failed is not an alias, and not a target that is gone.
	unread := served(t)
	unread.soa = nil
	unread.fail["cname:www.example.com"] = dnsclient.ErrServerFail
	got, err = (&Scanner{Resolver: unread}).Scan(ctx, "www.example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.Alias != "" || got.Observed.AliasReason == "" {
		t.Errorf("a failed lookup reads %+v", got.Observed)
	}
	if !noteSaying(got, "The alias could not be read") {
		t.Errorf("the notes are %v", noteTexts(got))
	}
}

// An alias at the top of a zone contradicts the records that make it a zone,
// and is the one alias that is graded.
func TestAnAliasAtTheTopOfAZoneIsGraded(t *testing.T) {
	both := served(t)
	both.alias["example.com"] = []string{"anywhere.example.net"}

	got := read(t, both)
	if !has(got, "dns.alias-at-zone-apex") || got.Verdict != policy.Insecure {
		t.Errorf("an alias beside a start of authority: %q %v", got.Verdict, ruleIDs(got))
	}

	// And a name inside a zone that is an alias is not graded for it.
	inside := served(t)
	inside.soa = nil
	inside.alias["www.example.com"] = []string{"pages.example.net"}
	other, err := (&Scanner{Resolver: inside}).Scan(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if has(other, "dns.alias-at-zone-apex") {
		t.Errorf("an ordinary alias was graded: %v", ruleIDs(other))
	}
}
