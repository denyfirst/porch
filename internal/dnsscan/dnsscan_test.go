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
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/verify"
)

// zone answers from a table, so a test needs no network.
type zone struct {
	addresses map[string][]string
	ns        []string
	above     map[string][]string
	soa       *dnsclient.SOA
	ds        []dnsclient.DS
	keys      []dnsclient.DNSKEY
	text      []string
	alias     map[string][]string
	missing   map[string]bool
	nsec3     []dnsclient.NSEC3PARAM

	validated bool

	// signatures are the RRSIG records the SOA answer carries, which is where
	// the date a signed zone stops being accepted comes from.
	signatures []dnsclient.RRSIG

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

// LookupNS answers by name, because two different zones are asked this: the
// one being scanned, and the one above it. A table that answered both from the
// same list would have every test agree with its parent by construction.
func (z *zone) LookupNS(_ context.Context, name string) (dnsclient.ZoneAnswer, error) {
	if hosts, ok := z.above[name]; ok {
		return dnsclient.ZoneAnswer{NS: hosts, Existed: true}, nil
	}
	if err := z.fail["ns"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{NS: z.ns, Existed: true, Validated: z.validated}, nil
}

func (z *zone) LookupSOA(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["soa"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	out := dnsclient.ZoneAnswer{Existed: true, Validated: z.validated, Signatures: z.signatures}
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

func (z *zone) LookupNSEC3PARAM(_ context.Context, _ string) (dnsclient.ZoneAnswer, error) {
	if err := z.fail["nsec3"]; err != nil {
		return dnsclient.ZoneAnswer{}, err
	}
	return dnsclient.ZoneAnswer{NSEC3: z.nsec3, Existed: true}, nil
}

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
	if len(got.Observed.Keys) != 1 || got.Observed.Keys[0].Name != "ECDSAP256SHA256" {
		t.Errorf("the key reads %+v, and an algorithm travels by the name an operator reads", got.Observed.Keys)
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

// The algorithms a zone signs with are read off its keys and sorted the way
// RFC 8624 sorts them: what must not be used, and what is no longer
// recommended. The difference is a zone validators are dropping and one they
// still accept while the advice moves.
func TestTheSigningAlgorithmsAreGradedAsRFC8624SortsThem(t *testing.T) {
	retired := served(t)
	retired.keys = []dnsclient.DNSKEY{{Flags: 257, Protocol: 3, Algorithm: 3, Key: []byte("an old key")}}
	retired.ds = []dnsclient.DS{signerFor(t, "example.com", retired.keys[0])}
	got := read(t, retired)
	if !has(got, "dns.dnssec-retired-algorithm") || got.Verdict != policy.Insecure {
		t.Errorf("DSA: %q %v", got.Verdict, ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.dnssec-retired-algorithm" && !strings.Contains(f.Rationale, "DSA") {
			t.Errorf("the finding names no algorithm: %s", f.Rationale)
		}
	}

	old := served(t)
	old.keys = []dnsclient.DNSKEY{{Flags: 257, Protocol: 3, Algorithm: 5, Key: []byte("an rsa key")}}
	old.ds = []dnsclient.DS{signerFor(t, "example.com", old.keys[0])}
	got = read(t, old)
	if !has(got, "dns.dnssec-weak-algorithm") || got.Verdict != policy.Weak {
		t.Errorf("RSASHA1: %q %v", got.Verdict, ruleIDs(got))
	}
	if has(got, "dns.dnssec-retired-algorithm") {
		t.Errorf("an algorithm that is merely not recommended was graded as retired: %v", ruleIDs(got))
	}

	// The ones RFC 8624 asks for are not graded at all.
	for _, algorithm := range []uint8{8, 13, 15} {
		fine := served(t)
		fine.keys = []dnsclient.DNSKEY{{Flags: 257, Protocol: 3, Algorithm: algorithm, Key: []byte("a key")}}
		fine.ds = []dnsclient.DS{signerFor(t, "example.com", fine.keys[0])}
		if got := read(t, fine); len(got.Findings) != 0 {
			t.Errorf("algorithm %d: %v", algorithm, ruleIDs(got))
		}
	}
}

// How a signed zone proves a name does not exist is read, and only the one
// thing a document settles is graded: RFC 9276 says the iteration count is
// zero. Which kind of proof a zone uses is reported, because nothing requires
// either.
func TestHowAbsentNamesAreProvedIsReadAndOnlyIterationsAreGraded(t *testing.T) {
	hashed := served(t)
	hashed.nsec3 = []dnsclient.NSEC3PARAM{{Hash: 1, Iterations: 0, SaltLength: 0}}
	got := read(t, hashed)
	if !got.Observed.NSEC3Read || !got.Observed.NSEC3 {
		t.Errorf("a zone with NSEC3 reads %+v", got.Observed)
	}
	if len(got.Findings) != 0 {
		t.Errorf("zero iterations were graded: %v", ruleIDs(got))
	}
	if !noteSaying(got, "hashed names") {
		t.Errorf("the notes are %v", noteTexts(got))
	}

	costly := served(t)
	costly.nsec3 = []dnsclient.NSEC3PARAM{{Hash: 1, Iterations: 10, SaltLength: 8}}
	got = read(t, costly)
	if !has(got, "dns.nsec3-iterations") || got.Verdict != policy.Weak {
		t.Errorf("ten iterations: %q %v", got.Verdict, ruleIDs(got))
	}

	// No NSEC3 record in a signed zone is the plain kind, which is reported
	// with what it means and never graded.
	plain := served(t)
	got = read(t, plain)
	if got.Observed.NSEC3 || !got.Observed.NSEC3Read {
		t.Errorf("a zone without NSEC3 reads %+v", got.Observed)
	}
	if !noteSaying(got, "list every name in this zone") || len(got.Findings) != 0 {
		t.Errorf("the plain kind: %v / %v", ruleIDs(got), noteTexts(got))
	}

	// An unsigned zone is never asked, and a lookup that failed is not an
	// answer about the zone.
	unsigned := served(t)
	unsigned.ds = nil
	if got := read(t, unsigned); got.Observed.NSEC3Read {
		t.Error("an unsigned zone was asked how it proves absence")
	}
	unread := served(t)
	unread.fail["nsec3"] = dnsclient.ErrServerFail
	got = read(t, unread)
	if got.Observed.NSEC3Read || got.Observed.NSEC3 {
		t.Errorf("a failed lookup reads %+v", got.Observed)
	}
	if noteSaying(got, "list every name in this zone") {
		t.Errorf("a failed lookup was read as the plain kind: %v", noteTexts(got))
	}
}

// A name server that is an alias is found by asking its own name, because a
// name that is an alias still resolves to an address and nothing else here
// would show it.
func TestANameServerThatIsAnAliasIsGraded(t *testing.T) {
	aliased := served(t)
	aliased.alias["ns2.example.org"] = []string{"ns2.provider.example"}

	got := read(t, aliased)
	if !has(got, "dns.name-server-is-an-alias") || got.Verdict != policy.Weak {
		t.Errorf("an alias in the delegation: %q %v", got.Verdict, ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.name-server-is-an-alias" && !strings.Contains(f.Rationale, "ns2.example.org") {
			t.Errorf("the finding does not say which server: %s", f.Rationale)
		}
	}
	if got.Observed.NameServers[1].Alias != "ns2.provider.example" {
		t.Errorf("the alias is not carried: %+v", got.Observed.NameServers[1])
	}

	if got := read(t, served(t)); has(got, "dns.name-server-is-an-alias") {
		t.Errorf("a delegation of plain names was graded: %v", ruleIDs(got))
	}
}

// servers answers the questions put to name servers directly, from a table.
type servers struct {
	// authoritative names the addresses that answer for the zone, and
	// recursing the ones that answer for anything.
	authoritative map[string]bool
	recursing     map[string]bool

	// claiming names the addresses that set the authority bit and answer with
	// no record, and refusing the ones that offer recursion and then refuse the
	// question.
	claiming map[string]bool
	refusing map[string]bool

	// fail names the addresses that answer with an error.
	fail map[string]error

	// serial is the zone serial each address answers with, for the question of
	// whether the servers hold the same copy of the zone. An address missing
	// from it answers with the zone's own.
	serial map[string]uint32

	// referral is what a server of the zone above hands out when it is asked
	// about the domain being scanned. Nil is a server that delegates nothing
	// here, which is not the same as one that delegates a different list.
	referral []string

	// answering makes that server hold both zones, so it answers from the
	// answer section instead of pointing. The same claim, the other shape.
	answering bool

	// handing names the addresses that begin a transfer for anybody who asks,
	// and failTransfer the ones where the question itself did not complete. A
	// server in neither refuses, which is the ordinary answer.
	handing      map[string]bool
	failTransfer map[string]error

	// asked records what was put to whom, so a test can say which servers
	// were asked the second question and which were not.
	asked []string
}

func (s *servers) AskServer(_ context.Context, address, name string, qtype uint16, recursion bool) (dnsclient.ServerAnswer, error) {
	s.asked = append(s.asked, address+" "+name)
	if err := s.fail[address]; err != nil {
		return dnsclient.ServerAnswer{}, err
	}
	if qtype == dnsclient.TypeNS {
		if recursion {
			// Asked to go and find the answer, a server hands back whatever
			// the search produced — the zone's own list, or something it held
			// from earlier — and not the delegation it publishes. The question
			// this asks is the second one, so the fake answers the first with
			// nothing.
			return dnsclient.ServerAnswer{Answered: true, Existed: true}, nil
		}
		if s.answering {
			return dnsclient.ServerAnswer{Answered: true, Authoritative: true, Existed: true, NS: s.referral}, nil
		}
		// The zone above, pointing rather than answering: the authority bit is
		// clear and the list arrives as a referral.
		return dnsclient.ServerAnswer{Answered: true, Existed: true, Referral: s.referral}, nil
	}
	if recursion {
		switch {
		case s.refusing[address]:
			// Offers the service and refuses this question, which is a server
			// that did not answer for a stranger.
			return dnsclient.ServerAnswer{RecursionOffered: true}, nil
		case !s.recursing[address]:
			return dnsclient.ServerAnswer{Answered: true, Existed: false}, nil
		}
		return dnsclient.ServerAnswer{Answered: true, RecursionOffered: true, Existed: true}, nil
	}
	if s.claiming[address] {
		// The flag without a record, which is not an answer for the zone.
		return dnsclient.ServerAnswer{Answered: true, Authoritative: true, Existed: true}, nil
	}
	if !s.authoritative[address] {
		return dnsclient.ServerAnswer{Answered: true, Existed: true}, nil
	}
	soa := dnsclient.SOA{Primary: "ns1.example.net", Serial: 7}
	if n, ok := s.serial[address]; ok {
		soa.Serial = n
	}
	return dnsclient.ServerAnswer{
		Answered: true, Authoritative: true, Existed: true,
		SOA: []dnsclient.SOA{soa},
	}, nil
}

func asking(t *testing.T, z *zone, s *servers) *Result {
	t.Helper()

	got, err := (&Scanner{Resolver: z, Servers: s, AskServers: true}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}

// A server that does not answer for the zone is found by asking it, which is
// the question a resolver cannot answer: one that reached a working server
// reports a working zone and says nothing about the rest.
func TestAServerThatDoesNotAnswerForTheZoneIsFoundByAskingIt(t *testing.T) {
	z := served(t)
	s := &servers{
		authoritative: map[string]bool{"192.0.2.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
	}

	got := asking(t, z, s)
	if !has(got, "dns.name-server-not-authoritative") || got.Verdict != policy.Weak {
		t.Errorf("a lame delegation: %q %v", got.Verdict, ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.name-server-not-authoritative" {
			if !strings.Contains(f.Rationale, "ns2.example.org") || strings.Contains(f.Rationale, "ns1.example.net") {
				t.Errorf("the finding names the wrong servers: %s", f.Rationale)
			}
		}
	}
	if !got.Observed.NameServers[0].Asked || !got.Observed.NameServers[0].Authoritative {
		t.Errorf("the working server reads %+v", got.Observed.NameServers[0])
	}

	// Every server answering for the zone is not a finding.
	both := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
	}
	if got := asking(t, z, both); len(got.Findings) != 0 {
		t.Errorf("a zone whose servers all answer: %v", ruleIDs(got))
	}

	// A server that could not be asked is not a server that failed to answer
	// for the zone (R4).
	unreachable := &servers{
		authoritative: map[string]bool{"192.0.2.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{"198.51.100.53": errors.New("no route")},
	}
	got = asking(t, z, unreachable)
	if has(got, "dns.name-server-not-authoritative") {
		t.Errorf("a server that could not be asked was graded: %v", ruleIDs(got))
	}
	if got.Observed.NameServers[1].AskedReason == "" {
		t.Errorf("the reason is not carried: %+v", got.Observed.NameServers[1])
	}

	// And nothing is asked at all unless the caller allows it.
	quiet := &servers{authoritative: map[string]bool{}, claiming: map[string]bool{}, recursing: map[string]bool{}, refusing: map[string]bool{}, fail: map[string]error{}}
	if _, err := (&Scanner{Resolver: z, Servers: quiet}).Scan(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(quiet.asked) != 0 {
		t.Errorf("a scan that was not allowed to ask servers asked %v", quiet.asked)
	}
}

// A server that answers questions about other people's domains is asked about
// only where it is the domain's own, which is the rule the relay question
// follows: a provider's server is somebody else's to ask about.
func TestOnlyTheDomainsOwnServersAreAskedAboutOtherDomains(t *testing.T) {
	z := served(t)
	z.ns = []string{"ns1.example.com", "ns2.provider.net"}
	z.addresses["ns1.example.com"] = []string{"192.0.2.53"}
	z.addresses["ns2.provider.net"] = []string{"198.51.100.53"}

	s := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
	}

	got := asking(t, z, s)
	if !has(got, "dns.name-server-offers-recursion") || got.Verdict != policy.Weak {
		t.Errorf("an open recursive server: %q %v", got.Verdict, ruleIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID == "dns.name-server-offers-recursion" && strings.Contains(f.Rationale, "provider") {
			t.Errorf("the finding names a server that was never asked: %s", f.Rationale)
		}
	}

	var probes []string
	for _, q := range s.asked {
		if strings.Contains(q, recursionProbe) {
			probes = append(probes, q)
		}
	}
	if len(probes) != 1 || !strings.HasPrefix(probes[0], "192.0.2.53 ") {
		t.Errorf("the recursion question went to %v", probes)
	}
	if !strings.HasSuffix(recursionProbe, ".invalid") {
		t.Errorf("the probe %q is not a name that cannot exist", recursionProbe)
	}
}

// The three states a server can be in that look like answers and are not: the
// authority flag with no record behind it, a server that could not be asked,
// and one that offers recursion and then refuses the question.
func TestWhatLooksLikeAnAnswerFromAServerAndIsNot(t *testing.T) {
	z := served(t)
	z.ns = []string{"ns1.example.com"}
	z.addresses["ns1.example.com"] = []string{"192.0.2.53"}

	// The flag without a record.
	claiming := &servers{
		authoritative: map[string]bool{},
		claiming:      map[string]bool{"192.0.2.53": true},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
	}
	got := asking(t, z, claiming)
	if got.Observed.NameServers[0].Authoritative {
		t.Error("the authority flag alone was read as an answer for the zone")
	}
	if !has(got, "dns.name-server-not-authoritative") {
		t.Errorf("a server claiming the zone with no record: %v", ruleIDs(got))
	}

	// A server that could not be asked carries the reason and is not recorded
	// as asked, because a server that was asked and said nothing is a
	// different fact (R4).
	unreachable := &servers{
		authoritative: map[string]bool{},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{"192.0.2.53": errors.New("no route")},
	}
	got = asking(t, z, unreachable)
	server := got.Observed.NameServers[0]
	if server.Asked || server.AskedReason == "" {
		t.Errorf("a server that could not be asked reads %+v", server)
	}

	// A server that offers recursion and refuses the question has not
	// answered for a stranger.
	refusing := &servers{
		authoritative: map[string]bool{"192.0.2.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{"192.0.2.53": true},
		fail:          map[string]error{},
	}
	got = asking(t, z, refusing)
	if got.Observed.NameServers[0].Recursion || has(got, "dns.name-server-offers-recursion") {
		t.Errorf("a refused question was read as recursion: %+v / %v", got.Observed.NameServers[0], ruleIDs(got))
	}
}

// The zone above is asked which servers it hands out, and a list that differs
// from the zone's own is the finding.
//
// This is the second claim about one delegation, and the one a resolver
// starting at the root follows. A resolver cannot be asked it: it answers an NS
// question from the zone itself, so the parent's list never appears in any
// answer this check would otherwise see.
func TestTheZoneAboveIsAskedWhichServersItHandsOut(t *testing.T) {
	z := served(t)
	z.above = map[string][]string{"com": {"a.gtld.test"}}
	z.addresses["a.gtld.test"] = []string{"203.0.113.53"}

	s := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},

		// The zone names ns1.example.net and ns2.example.org; the parent hands
		// out the first and a third nobody here has heard of.
		referral: []string{"ns1.example.net", "ns9.example.net"},
	}

	got := asking(t, z, s)
	if !has(got, "dns.parent-and-zone-disagree") || got.Verdict != policy.Weak {
		t.Errorf("a delegation the parent disagrees with: %q %v", got.Verdict, ruleIDs(got))
	}

	f := got.Observed
	if !f.ParentAsked || f.ParentReason != "" || f.Parent != "com" || f.ParentServer != "a.gtld.test" {
		t.Errorf("what was asked reads %+v", f)
	}
	if strings.Join(f.OnlyAtParent, ",") != "ns9.example.net" {
		t.Errorf("what only the parent hands out reads %v", f.OnlyAtParent)
	}
	if strings.Join(f.OnlyAtZone, ",") != "ns2.example.org" {
		t.Errorf("what only the zone names reads %v", f.OnlyAtZone)
	}

	// The question went to the parent's server about this domain, and named
	// the domain rather than the parent: this reports on the zone being
	// scanned and never on the zone above it.
	var toParent []string
	for _, q := range s.asked {
		if strings.HasPrefix(q, "203.0.113.53 ") {
			toParent = append(toParent, q)
		}
	}
	if len(toParent) != 1 || toParent[0] != "203.0.113.53 example.com" {
		t.Errorf("the parent was asked %v", toParent)
	}

	// A server that holds both zones answers from the answer section instead of
	// pointing, and that is the same claim about the same delegation.
	both := *s
	both.answering = true
	if got := asking(t, z, &both); !has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a server holding both zones was read as saying nothing: %+v", got.Observed)
	}

	// The same lists in the same order agree, whatever case they are spelled
	// in: a name is a name.
	same := *s
	same.referral = []string{"NS2.example.ORG", "ns1.example.net."}
	if got := asking(t, z, &same); has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a delegation spelled differently was graded: %v", ruleIDs(got))
	}
}

// Nothing established is not agreement (R4): a parent that was not asked, one
// that could not be reached, and one that delegates nothing here are three
// silences, and none of them is graded.
func TestAParentThatWasNotAskedIsNotAgreement(t *testing.T) {
	z := served(t)
	z.above = map[string][]string{"com": {"a.gtld.test"}}
	z.addresses["a.gtld.test"] = []string{"203.0.113.53"}

	quiet := &servers{authoritative: map[string]bool{}, claiming: map[string]bool{}, recursing: map[string]bool{}, refusing: map[string]bool{}, fail: map[string]error{}}
	got, err := (&Scanner{Resolver: z, Servers: quiet}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Observed.ParentAsked || has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a parent nobody asked reads %+v", got.Observed)
	}
	for _, q := range quiet.asked {
		if strings.HasPrefix(q, "203.0.113.53 ") {
			t.Errorf("a scan that was not allowed to ask servers asked the parent: %v", quiet.asked)
		}
	}

	// Reached and refused: the reason is carried and nothing is graded.
	unreachable := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{"203.0.113.53": errors.New("dnsclient: reaching the name server: connection refused")},
	}
	got = asking(t, z, unreachable)
	if got.Observed.ParentAsked || got.Observed.ParentReason == "" || has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a parent that refused reads %+v", got.Observed)
	}

	// Answered, and delegates nothing here: not a disagreement either.
	empty := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
	}
	got = asking(t, z, empty)
	if got.Observed.ParentAsked || got.Observed.ParentReason == "" || has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a parent that delegates nothing reads %+v", got.Observed)
	}

	// And where the two agree, the question was asked and there is no finding:
	// a report that could not tell agreement from silence would be worth
	// nothing here.
	agreeing := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
		referral:      []string{"ns1.example.net", "ns2.example.org"},
	}
	got = asking(t, z, agreeing)
	if !got.Observed.ParentAsked || has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a delegation both agree on reads %+v %v", got.Observed, ruleIDs(got))
	}

	// A zone whose own delegation could not be read has nothing to compare, and
	// the parent's list is not that comparison: every name it hands out would
	// read as one this zone does not name.
	unread := served(t)
	unread.above = z.above
	unread.addresses["a.gtld.test"] = []string{"203.0.113.53"}
	unread.fail["ns"] = errors.New("dnsclient: the lookup did not complete")
	got = asking(t, unread, agreeing)
	if has(got, "dns.parent-and-zone-disagree") {
		t.Errorf("a delegation that was never read was compared: %v", ruleIDs(got))
	}

	// And a difference handed to the grade without the question having been put
	// is not graded either. The scan fills those two lists only after a server
	// of the zone above answered; a report from another version, or a caller
	// building facts by hand, must not turn a silence into a finding (R4).
	silent := policy.GradeDNS(policy.DNSFacts{
		Apex: true,
		NameServers: []policy.NameServer{
			{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}},
			{Name: "ns2.example.org", Addresses: []string{"198.51.100.53"}},
		},
		OnlyAtParent: []string{"ns9.example.net"},
		OnlyAtZone:   []string{"ns2.example.org"},
	}, time.Now())
	for _, f := range silent.Findings {
		if f.RuleID == "dns.parent-and-zone-disagree" {
			t.Error("a difference nobody asked about was graded")
		}
	}
}

// Whether the servers hold the same copy of the zone is read from the answers
// already in hand, and reported rather than graded.
//
// Reported, because R21 leaves it there: a zone changed a moment ago has its
// servers at two serials until the transfer finishes, no document says how
// long that may take, and a scan sees one instant. What can be said is which
// server answered with which number.
func TestWhetherTheServersHoldTheSameCopyIsReadAndNotGraded(t *testing.T) {
	z := served(t)

	// One server two changes behind the other.
	behind := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
		serial:        map[string]uint32{"198.51.100.53": 5},
	}

	got := asking(t, z, behind)
	if !noteSaying(got, "do not hold the same copy of the zone") ||
		!noteSaying(got, "ns1.example.net at 7") || !noteSaying(got, "ns2.example.org at 5") {
		t.Errorf("the disagreement is not reported: %v", noteTexts(got))
	}
	if got.Verdict != policy.Strong || len(got.Findings) != 0 {
		t.Errorf("a serial difference was graded: %q %v", got.Verdict, ruleIDs(got))
	}
	if !got.Observed.NameServers[1].SerialRead || got.Observed.NameServers[1].Serial != 5 {
		t.Errorf("the serial each server answered with is not carried: %+v", got.Observed.NameServers)
	}

	// The same servers holding one copy, which is the answer worth saying out
	// loud: silence here would read as a question nobody put.
	together := *behind
	together.serial = map[string]uint32{}
	got = asking(t, z, &together)
	if !noteSaying(got, "hold the same copy of the zone") || noteSaying(got, "do not hold the same copy") {
		t.Errorf("agreement is not reported: %v", noteTexts(got))
	}

	// A server nobody could ask holds no opinion, so one answer is not a
	// comparison and is not reported as one (R4).
	alone := *behind
	alone.fail = map[string]error{"198.51.100.53": errors.New("dnsclient: reaching the name server: connection refused")}
	got = asking(t, z, &alone)
	if noteSaying(got, "copy of the zone") {
		t.Errorf("one server was compared with itself: %v", noteTexts(got))
	}

	// A server that set the authority bit and answered with no record holds no
	// serial either. Counting its silence as serial zero would put it in the
	// comparison as a server two thousand changes behind (R4).
	silent := *behind
	silent.serial = map[string]uint32{}
	silent.authoritative = map[string]bool{"192.0.2.53": true}
	silent.claiming = map[string]bool{"198.51.100.53": true}
	got = asking(t, z, &silent)
	if noteSaying(got, "copy of the zone") {
		t.Errorf("a server that answered with no record was given a serial: %v", noteTexts(got))
	}
	if got.Observed.NameServers[1].SerialRead {
		t.Errorf("a server that answered with no record reads %+v", got.Observed.NameServers[1])
	}

	// And a scan that asked no server at all says nothing about it either.
	if quiet := read(t, z); noteSaying(quiet, "copy of the zone") {
		t.Errorf("servers nobody asked were compared: %v", noteTexts(quiet))
	}
}

// AskTransfer answers whether this address hands the zone to anybody.
//
// A boolean, like the real one: the fake could not hand back a zone if a test
// asked it to, because the interface gives a caller nowhere to put one.
func (s *servers) AskTransfer(_ context.Context, address, _ string) (bool, error) {
	s.asked = append(s.asked, address+" AXFR")
	if err := s.failTransfer[address]; err != nil {
		return false, err
	}
	if s.handing[address] {
		return true, nil
	}
	return false, dnsclient.ErrNoTransfer
}

// Whether the zone can be read whole is asked of every server the zone names,
// reported, and not graded.
//
// Not graded because RFC 5936 section 5 declines to call it a fault: it says a
// general-purpose implementation ought to let an operator open transfers to
// all, and that the arguments for concealing a zone have been argued to be
// questionable. R21 is what that leaves.
func TestWhetherTheZoneCanBeReadWholeIsAskedAndReported(t *testing.T) {
	z := served(t)

	open := &servers{
		authoritative: map[string]bool{"192.0.2.53": true, "198.51.100.53": true},
		claiming:      map[string]bool{},
		recursing:     map[string]bool{},
		refusing:      map[string]bool{},
		fail:          map[string]error{},
		handing:       map[string]bool{"198.51.100.53": true},
	}

	got := asking(t, z, open)
	if !noteSaying(got, "The zone can be read whole from ns2.example.org") {
		t.Errorf("an open transfer is not reported: %v", noteTexts(got))
	}
	if got.Verdict != policy.Strong || len(got.Findings) != 0 {
		t.Errorf("an open transfer was graded: %q %v", got.Verdict, ruleIDs(got))
	}
	if !got.Observed.NameServers[1].TransferAsked || !got.Observed.NameServers[1].Transfer {
		t.Errorf("the server that handed out the zone reads %+v", got.Observed.NameServers[1])
	}
	// The one that refused is not named, and refusing is not a reason either.
	if got.Observed.NameServers[0].Transfer || got.Observed.NameServers[0].TransferReason != "" {
		t.Errorf("a server that refused reads %+v", got.Observed.NameServers[0])
	}
	// Every server the zone names is asked, and asked about the zone: whose
	// server it is does not change whose zone is being handed out.
	var transfers []string
	for _, q := range open.asked {
		if strings.HasSuffix(q, " AXFR") {
			transfers = append(transfers, q)
		}
	}
	if len(transfers) != 2 {
		t.Errorf("the transfer question went to %v", transfers)
	}

	// A zone whose servers all refuse says nothing about transfers at all: the
	// report carries findings and facts, not a line for every question that
	// came back the ordinary way.
	closed := *open
	closed.handing = map[string]bool{}
	if got := asking(t, z, &closed); noteSaying(got, "read whole") {
		t.Errorf("a zone nobody can transfer was written about: %v", noteTexts(got))
	}

	// A question that did not complete is not a zone that refused one (R4).
	unknown := *open
	unknown.handing = map[string]bool{}
	unknown.failTransfer = map[string]error{"192.0.2.53": errors.New("dnsclient: reading the reply: connection reset")}
	got = asking(t, z, &unknown)
	if !noteSaying(got, "was not established for ns1.example.net") {
		t.Errorf("a transfer question that failed is not reported: %v", noteTexts(got))
	}
	if got.Observed.NameServers[0].TransferAsked {
		t.Errorf("a question that failed was recorded as asked: %+v", got.Observed.NameServers[0])
	}

	// And nothing is asked where the caller did not allow it.
	quiet := &servers{
		authoritative: map[string]bool{}, claiming: map[string]bool{}, recursing: map[string]bool{},
		refusing: map[string]bool{}, fail: map[string]error{}, handing: map[string]bool{"192.0.2.53": true},
	}
	if _, err := (&Scanner{Resolver: z, Servers: quiet}).Scan(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, q := range quiet.asked {
		if strings.HasSuffix(q, " AXFR") {
			t.Errorf("a scan that was not allowed to ask servers asked for a transfer: %v", quiet.asked)
		}
	}
}

// When the zone's signatures run out is reported, and a signature that has
// already run out is graded.
//
// The date is reported and not graded because no document says how much room
// to leave: a zone re-signed hourly with a two-day window is as correct as one
// re-signed weekly with a month (R21). Expiry itself is settled — RFC 4035
// §5.3.1 has a validator refuse a signature whose validity period does not
// contain the current time, so the zone is already gone for everybody behind
// one.
func TestWhenTheSignaturesRunOutIsReadAndOnlyExpiryIsGraded(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	at := func(z *zone) *Result {
		t.Helper()
		got, err := (&Scanner{Resolver: z, Now: func() time.Time { return now }}).Scan(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		return got
	}

	z := served(t)
	z.signatures = []dnsclient.RRSIG{
		{Covered: dnsclient.TypeSOA, KeyTag: 53731, Signer: "example.com",
			Inception: now.AddDate(0, 0, -7), Expiration: now.AddDate(0, 0, 21)},
		// A second key's signature, running out first: what decides the zone's
		// fate is whichever goes first, not whichever was read first.
		{Covered: dnsclient.TypeSOA, KeyTag: 111, Signer: "example.com",
			Inception: now.AddDate(0, 0, -7), Expiration: now.AddDate(0, 0, 6)},
	}

	got := at(z)
	if !got.Observed.SignatureRead || !got.Observed.SignatureExpires.Equal(now.AddDate(0, 0, 6)) {
		t.Errorf("the signature reads %+v, and the earliest is the one that decides", got.Observed.SignatureExpires)
	}
	if got.Observed.SignatureKeyTag != 111 {
		t.Errorf("the key that made it reads %d", got.Observed.SignatureKeyTag)
	}
	if !noteSaying(got, "runs out on 2026-09-30, in 6 days") {
		t.Errorf("the date is not reported: %v", noteTexts(got))
	}
	if got.Verdict != policy.Strong || len(got.Findings) != 0 {
		t.Errorf("a signature with time left was graded: %q %v", got.Verdict, ruleIDs(got))
	}

	// One that has run out, which every validator refuses.
	expired := served(t)
	expired.signatures = []dnsclient.RRSIG{
		{Covered: dnsclient.TypeSOA, KeyTag: 53731, Signer: "example.com",
			Inception: now.AddDate(0, 0, -40), Expiration: now.AddDate(0, 0, -2)},
	}
	got = at(expired)
	if !has(got, "dns.signature-expired") || got.Verdict != policy.Insecure {
		t.Errorf("an expired signature reads %q %v", got.Verdict, ruleIDs(got))
	}
	if noteSaying(got, "runs out on") {
		t.Errorf("a signature that has run out was also written about as one that will: %v", noteTexts(got))
	}

	// An answer that carried no signature says nothing about a date, and is
	// not a zone whose signatures ran out (R4).
	quiet := served(t)
	got = at(quiet)
	if got.Observed.SignatureRead || has(got, "dns.signature-expired") || noteSaying(got, "runs out on") {
		t.Errorf("a zone whose signature was not read reads %+v %v", got.Observed.SignatureExpires, ruleIDs(got))
	}

	// A date handed to the grade without the question having been answered is
	// not a date: the scan fills the two together, and a report from another
	// version must not turn a silence into a sentence (R4).
	unread := policy.GradeDNS(policy.DNSFacts{
		Apex: true, Signed: true, ChainMatched: true,
		SignatureExpires: now.AddDate(0, 0, 20),
		NameServers: []policy.NameServer{
			{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}},
			{Name: "ns2.example.org", Addresses: []string{"198.51.100.53"}},
		},
	}, now)
	for _, n := range unread.Notes {
		if strings.Contains(n.Text, "runs out on") {
			t.Errorf("a date nobody read was reported: %s", n.Text)
		}
	}

	// And an unsigned zone is not one with an expired signature either, even
	// if something put a date in front of the grade.
	unsigned := policy.GradeDNS(policy.DNSFacts{
		Apex: true, SignatureRead: true, SignatureExpires: now.AddDate(0, 0, -2),
		NameServers: []policy.NameServer{
			{Name: "ns1.example.net", Addresses: []string{"192.0.2.53"}},
			{Name: "ns2.example.org", Addresses: []string{"198.51.100.53"}},
		},
	}, now)
	for _, f := range unsigned.Findings {
		if f.RuleID == "dns.signature-expired" {
			t.Error("an unsigned zone was graded on a signature it does not have")
		}
	}
}
