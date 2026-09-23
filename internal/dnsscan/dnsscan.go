// Package dnsscan reads what a domain's own DNS publishes about itself, and
// grades the part of it a standard requires.
//
// The other three checks each read DNS for one purpose: CAA for the
// certificate, TXT and MX for the mail policy, TLSA for DANE. None of them
// looks at the zone itself — how many servers answer for it, whether they can
// be reached, whether the DNSSEC chain its parent anchors still checks out.
// That last one is the reason this exists. A chain that breaks takes the
// domain off the internet for everybody behind a validating resolver and
// leaves it working for whoever set it up, so nobody finds out from their own
// browser.
//
// # What it asks, and of whom
//
// Seven questions about the name, and three per name server: the addresses,
// the delegation, the record at the top of the zone, the text records, the
// alias, the digest the parent holds and the keys the zone publishes. All of
// those go to the same recursive resolver every other check uses.
//
// Two more are put to the servers the zone names, where the caller allows it,
// because a resolver cannot answer them: whether each server answers for the
// zone as its own, and — for a server inside the domain being checked only —
// whether it answers questions about domains it has nothing to do with. Those
// go over TCP on port 53, through the guard that refuses private, loopback and
// reserved destinations, because the addresses come out of the zone being
// measured. Nothing else is sent to them, and no zone transfer is attempted.
//
// # What it grades
//
// Only what a standard requires, which for DNS is very little: internal/policy
// says why at length. Everything else is reported, including the timers whose
// ranges RFC 1912 calls recommendations and which every other tool grades.
package dnsscan

import (
	"context"
	// #nosec G505 -- a delegation signer may be a SHA-1 digest, and a chain
	// that uses one works: refusing to compute it would report a working zone
	// as unverifiable rather than saying the hash is one nobody would choose now.
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/exclusion"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/verify"
)

// maxNameServers bounds how many servers are looked up, and with them the two
// address lookups each one costs. A zone published by whoever is being
// measured can name as many as it likes.
const maxNameServers = 8

// Resolver is what this check asks. internal/dnsclient satisfies it.
//
// An interface for the reason every other check has one: a test that could not
// answer without a network would exercise whichever zone the machine running
// the tests happens to reach.
type Resolver interface {
	LookupAddresses(ctx context.Context, name string, qtype uint16) (dnsclient.ZoneAnswer, error)
	LookupNS(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupSOA(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupDS(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupDNSKEY(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupCNAME(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupNSEC3PARAM(ctx context.Context, name string) (dnsclient.ZoneAnswer, error)
	LookupTXT(ctx context.Context, name string) (dnsclient.TXTAnswer, error)
}

// Scanner reads one domain's DNS.
type Scanner struct {
	// Resolver asks the questions. Nil means one reading this machine's own
	// configuration, which is what every other check here uses.
	Resolver Resolver

	// Verify is the proof of control this deployment requires before it will
	// scan a name. Nil means none is required, which is what the command line
	// wants and what a service must not have.
	Verify *verify.Scope

	// AskServers asks the servers the zone names directly, which is the only
	// way to learn whether each of them answers for the zone and whether any
	// answers for domains it has nothing to do with.
	//
	// False by default, and the default is the one that connects to nothing:
	// every other question here goes to a resolver, and this opens a connection
	// to an address the measured zone chose. A caller sets it where control of
	// the domain has been proven, or on the command line, where the scan runs
	// on the operator's own machine from their own address — the same condition
	// the mail check's two connections have.
	AskServers bool

	// Servers is what puts those questions. Nil means a client of this
	// package's own.
	Servers ServerAsker

	// Now is the clock, for a test that needs a fixed duration.
	Now func() time.Time
}

// Result is one domain's DNS as it was read.
type Result struct {
	Domain string `json:"domain"`

	// Policy names the rule set behind every verdict here, and is never the
	// TLS, web or mail one: these are different questions over different
	// evidence.
	Policy string `json:"policy"`

	// Verdict is the worst of everything below. Empty means nothing was
	// graded, which is not the same as nothing being wrong (R4).
	Verdict policy.Verdict `json:"verdict,omitempty"`

	Findings []policy.Finding `json:"findings,omitempty"`
	Notes    []policy.Note    `json:"notes,omitempty"`

	// Observed is what the lookups established, kept so a reader can check a
	// verdict against the evidence rather than taking it on trust.
	Observed *policy.DNSFacts `json:"observed,omitempty"`

	Duration time.Duration `json:"duration"`
}

// Scan reads one domain.
//
// An error means the domain was refused before anything was looked up. A zone
// that publishes little is not an error: it is a result saying what is not
// published, which is a different thing and is reported as one.
func (s *Scanner) Scan(ctx context.Context, domain string) (*Result, error) {
	started := s.now()

	domain = fold(domain)
	if err := CheckDomain(domain); err != nil {
		return nil, err
	}

	// The same three sources of authority the other checks ask, in the same
	// order and for the same reasons (N8, N6, N9).
	if exclusion.Covers(domain) {
		return nil, exclusion.ErrRefused
	}
	if demo.Refusal(domain) {
		return nil, demo.ErrNotATarget
	}
	if s.Verify != nil {
		// AnyPort, not HTTPOnly. A file served at /.well-known proves control
		// of one host's web surface and says nothing about the zone, and the
		// zone is the whole of what this reads.
		if err := s.Verify.Covers(ctx, domain, verify.AnyPort); err != nil {
			return nil, err
		}
	}

	resolver := s.Resolver
	if resolver == nil || isNilClient(resolver) {
		resolver = &dnsclient.Client{}
	}

	facts := policy.DNSFacts{Policy: policy.DNSVersion}
	s.readZone(ctx, resolver, domain, &facts)
	s.readAddresses(ctx, resolver, domain, &facts)
	s.readAlias(ctx, resolver, domain, &facts)
	s.readNameServers(ctx, resolver, domain, &facts)
	s.readChain(ctx, resolver, domain, &facts)
	s.readAbsence(ctx, resolver, domain, &facts)
	s.askServers(ctx, domain, &facts)

	graded := policy.GradeDNS(facts)

	return &Result{
		Domain:   domain,
		Policy:   policy.DNSVersion,
		Verdict:  graded.Verdict,
		Findings: graded.Findings,
		Notes:    graded.Notes,
		Observed: &facts,
		Duration: s.now().Sub(started),
	}, nil
}

// readZone reads the record at the top of the zone and the text records, and
// decides whether a zone begins here at all.
func (s *Scanner) readZone(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	answer, err := r.LookupSOA(ctx, domain)
	if err == nil && len(answer.SOA) > 0 {
		soa := answer.SOA[0]
		facts.Apex = true
		facts.SOAFound = true
		facts.SOAPrimary = soa.Primary
		facts.SOAMailbox = soa.Mailbox
		facts.SOASerial = soa.Serial
		facts.SOARefresh = soa.Refresh
		facts.SOARetry = soa.Retry
		facts.SOAExpire = soa.Expire
		facts.SOAMinimum = soa.Minimum
	}
	facts.ResolverValidated = facts.ResolverValidated || answer.Validated

	if text, err := r.LookupTXT(ctx, domain); err == nil {
		facts.Text = text.Values
	}
}

// readAddresses asks for both address types, because they are two questions
// and a name with one and not the other is ordinary.
func (s *Scanner) readAddresses(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	v4, v6, reason := addressesOf(ctx, r, domain)
	facts.IPv4, facts.IPv6 = v4, v6
	facts.AddressReason = reason
}

// readNameServers reads the delegation and resolves each server named, so that
// a name nobody can resolve is visible as what it is.
func (s *Scanner) readNameServers(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	if !facts.Apex {
		return
	}

	answer, err := r.LookupNS(ctx, domain)
	if err != nil {
		facts.NSReason = shape(err)
		return
	}
	facts.ResolverValidated = facts.ResolverValidated || answer.Validated

	hosts := answer.NS
	if len(hosts) > maxNameServers {
		hosts = hosts[:maxNameServers]
	}

	// In parallel, for the reason the mail check asks its exchangers in
	// parallel: they are independent lookups and a zone with eight servers
	// would otherwise be eight round trips end to end.
	servers := make([]policy.NameServer, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v4, v6, reason := addressesOf(ctx, r, host)
			server := policy.NameServer{Name: host, Addresses: append(v4, v6...), Reason: reason}

			// And whether the name is an alias, which RFC 2181 forbids in a
			// delegation. Asked of the server's own name rather than inferred
			// from the addresses: a name that is an alias still resolves to an
			// address, so nothing above this would show it.
			if alias, err := r.LookupCNAME(ctx, host); err == nil && len(alias.Alias) > 0 {
				server.Alias = alias.Alias[0]
			}
			servers[i] = server
		}()
	}
	wg.Wait()

	facts.NameServers = servers
	facts.Networks = networksOf(servers)
}

// readChain reads both ends of the DNSSEC link and works out whether they
// meet.
func (s *Scanner) readChain(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	if !facts.Apex {
		return
	}

	signers, err := r.LookupDS(ctx, domain)
	if err != nil {
		facts.ChainReason = shape(err)
		return
	}
	facts.ResolverValidated = facts.ResolverValidated || signers.Validated
	if len(signers.DS) == 0 {
		return
	}
	facts.Signed = true

	keys, err := r.LookupDNSKEY(ctx, domain)
	if err != nil {
		facts.ChainReason = shape(err)
		return
	}
	facts.ResolverValidated = facts.ResolverValidated || keys.Validated

	for _, k := range keys.Keys {
		facts.Keys = append(facts.Keys, policy.KeyDigest{
			KeyTag:     keyTag(k),
			Algorithm:  k.Algorithm,
			Name:       policy.AlgorithmName(k.Algorithm),
			KeySigning: k.Flags&0x0001 != 0,
		})
	}

	owner, err := wireName(domain)
	if err != nil {
		facts.ChainReason = "the name could not be written in the form a digest is taken over"
		return
	}

	for _, ds := range signers.DS {
		record := policy.DelegationSigner{
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
		}
		digest := digester(ds.DigestType)
		if digest == nil {
			record.Unsupported = true
			facts.Signers = append(facts.Signers, record)
			continue
		}
		for _, k := range keys.Keys {
			if k.Algorithm != ds.Algorithm || keyTag(k) != ds.KeyTag {
				continue
			}
			digest.Reset()
			digest.Write(owner)
			digest.Write(keyRDATA(k))
			if equalBytes(digest.Sum(nil), ds.Digest) {
				record.Matched = true
				facts.ChainMatched = true
				break
			}
		}
		facts.Signers = append(facts.Signers, record)
	}
}

// addressesOf asks for A and AAAA, and says which of the two failed rather
// than turning a failure into an absence.
func addressesOf(ctx context.Context, r Resolver, name string) (v4, v6 []string, reason string) {
	var reasons []string
	for _, qtype := range []uint16{dnsclient.TypeA, dnsclient.TypeAAAA} {
		answer, err := r.LookupAddresses(ctx, name, qtype)
		if err != nil {
			reasons = append(reasons, shape(err))
			continue
		}
		for _, addr := range answer.Addresses {
			if addr.Is4() {
				v4 = append(v4, addr.String())
				continue
			}
			v6 = append(v6, addr.String())
		}
	}
	return v4, v6, strings.Join(reasons, "; ")
}

// networksOf counts how many networks the servers answer from, an IPv4 /24 and
// an IPv6 /48 counting as one each.
//
// A prefix rather than an owner: which organisation an address belongs to
// cannot be read from the address, and answering it means asking a third party
// on every scan. A prefix is what this can establish by itself, and RFC 2182
// asks for servers that do not share a failure — which a shared /24 is the
// visible half of.
func networksOf(servers []policy.NameServer) int {
	seen := map[netip.Prefix]bool{}
	for _, ns := range servers {
		for _, text := range ns.Addresses {
			addr, err := netip.ParseAddr(text)
			if err != nil {
				continue
			}
			bits := 24
			if addr.Is6() {
				bits = 48
			}
			if prefix, err := addr.Prefix(bits); err == nil {
				seen[prefix] = true
			}
		}
	}
	return len(seen)
}

// keyTag is RFC 4034 Appendix B: the number a delegation signer names a key
// by. Algorithm 1 has a rule of its own, which is not implemented because RFC
// 8624 says that algorithm must not be used and a zone still on it will not
// match here.
func keyTag(k dnsclient.DNSKEY) uint16 {
	rdata := keyRDATA(k)
	var sum uint32
	for i, b := range rdata {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	sum += sum >> 16 & 0xFFFF
	return uint16(sum & 0xFFFF)
}

// keyRDATA writes a key back into the form its digest is taken over.
func keyRDATA(k dnsclient.DNSKEY) []byte {
	out := make([]byte, 4, 4+len(k.Key))
	binary.BigEndian.PutUint16(out[0:2], k.Flags)
	out[2] = k.Protocol
	out[3] = k.Algorithm
	return append(out, k.Key...)
}

// digester is the hash a digest type names, or nil for one this does not
// compute. A type nobody here implements is reported as unmatched-and-unknown
// rather than as a chain that fails (R4).
func digester(digestType uint8) hash.Hash {
	switch digestType {
	case 1:
		// SHA-1, which RFC 8624 retires for new delegations. Computed anyway:
		// a chain that still uses it works, and refusing to check it would
		// report a working zone as unverifiable.
		// #nosec G401 -- reading a digest somebody published, not making one
		return sha1.New()
	case 2:
		return sha256.New()
	case 4:
		return sha512.New384()
	default:
		return nil
	}
}

// wireName writes a name the way a digest is taken over it: lowercase labels,
// each one length-prefixed, ending in the root.
func wireName(name string) ([]byte, error) {
	name = strings.TrimSuffix(fold(name), ".")
	if name == "" {
		return nil, errors.New("dnsscan: an empty name has no wire form")
	}

	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("dnsscan: a label of %d bytes is not one", len(label))
		}
		out = append(out, byte(len(label))) // #nosec G115 -- refused above past 63
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// equalBytes compares two digests. Not constant time, and it does not need to
// be: both sides are public records anybody can read, and the answer is a line
// in a report rather than a decision about access.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// shape returns what an error is without what it says. A resolver's error can
// name the resolver, which is this machine's configuration and nobody else's
// business (I6).
func shape(err error) string {
	switch {
	case errors.Is(err, dnsclient.ErrServerFail):
		return "the resolver failed the query, which is also what it answers when DNSSEC does not check out"
	case errors.Is(err, dnsclient.ErrRefused):
		return "the resolver refused the query"
	case errors.Is(err, context.DeadlineExceeded):
		return "the lookup ran out of time"
	default:
		return "the lookup did not complete"
	}
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// errNotADomain says what a domain is without repeating what was typed (I6).
var errNotADomain = errors.New("the target must be a domain name, such as example.com")

// CheckDomain accepts what this check can ask about, the same shape the mail
// check accepts: a name with a dot in it, no port, no path, nothing unprintable.
func CheckDomain(domain string) error {
	switch {
	case domain == "":
		return errNotADomain
	case len(domain) > 253:
		return errNotADomain
	case strings.ContainsAny(domain, `/\ :@`):
		return errNotADomain
	case !strings.Contains(domain, "."):
		return errNotADomain
	}

	for _, r := range domain {
		if r < 0x20 || r == 0x7f {
			return errNotADomain
		}
	}
	return nil
}

// isNilClient catches a typed nil handed in as a Resolver, which is an
// interface holding something and a pointer to nothing.
func isNilClient(r Resolver) bool {
	c, ok := r.(*dnsclient.Client)
	return ok && c == nil
}

// readAlias reads the alias at the name, and whether what it points at exists.
//
// Both halves are needed and the second is the one worth having. A name
// pointing at something that was deleted resolves to nothing, and where the
// target is at a provider that hands out unclaimed names, whoever claims it
// next answers for this name — with a certificate they can obtain for it,
// because obtaining one only takes answering for the name.
func (s *Scanner) readAlias(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	answer, err := r.LookupCNAME(ctx, domain)
	if err != nil {
		facts.AliasReason = shape(err)
		return
	}
	if len(answer.Alias) == 0 {
		return
	}
	facts.Alias = answer.Alias[0]

	// Whether the target exists at all, which is a question about the target
	// and is asked of it. An address is not required — a name with only MX
	// records exists — so existence is what the resolver says about the name
	// rather than what it resolves to.
	for _, qtype := range []uint16{dnsclient.TypeA, dnsclient.TypeAAAA} {
		target, err := r.LookupAddresses(ctx, facts.Alias, qtype)
		if err != nil {
			facts.AliasReason = shape(err)
			return
		}
		if target.Existed {
			facts.AliasTargetExists = true
			return
		}
	}
}

// readAbsence reads how a signed zone proves a name does not exist.
//
// Only where the zone is signed, because the question is meaningless
// otherwise: an unsigned zone proves nothing at all, and asking would be one
// more lookup for an answer that could not mean anything.
func (s *Scanner) readAbsence(ctx context.Context, r Resolver, domain string, facts *policy.DNSFacts) {
	if !facts.Apex || !facts.Signed {
		return
	}

	answer, err := r.LookupNSEC3PARAM(ctx, domain)
	if err != nil {
		return
	}
	facts.NSEC3Read = true
	if len(answer.NSEC3) == 0 {
		return
	}

	facts.NSEC3 = true
	facts.NSEC3Iterations = answer.NSEC3[0].Iterations
	facts.NSEC3SaltLength = answer.NSEC3[0].SaltLength
}

// ServerAsker puts a question to one name server directly.
//
// An interface, and optional: a scan that cannot ask servers asks none rather
// than failing, and the report says the questions were not put. internal/dnsclient
// is the one implementation.
type ServerAsker interface {
	AskServer(ctx context.Context, address, name string, qtype uint16, recursion bool) (dnsclient.ServerAnswer, error)
}

// recursionProbe is the name a server is asked about to see whether it answers
// for domains it has nothing to do with.
//
// Under .invalid, which RFC 2606 reserves so that the name cannot exist. A
// server that goes looking for it asks the root and is told nothing is there,
// which is the whole of the traffic this causes; a server that refuses it, or
// answers without recursion, has said what it is.
const recursionProbe = "recursion-probe.porch.invalid"

// askServers puts two questions to the servers the zone names, where the
// caller allows it.
//
// The first is asked of every one of them: does this server answer for this
// zone as its own? That is the question a resolver cannot answer, because a
// resolver that reached one working server reports a working zone and says
// nothing about the rest.
//
// The second is asked only of a server inside the domain being checked: will
// it answer a question about a domain it has nothing to do with? That one is
// about the server's behaviour rather than about this zone, and a server run
// by a provider is somebody else's to ask about — the same rule the mail
// check's relay question follows.
func (s *Scanner) askServers(ctx context.Context, domain string, facts *policy.DNSFacts) {
	if !s.AskServers {
		return
	}

	asker := s.Servers
	if asker == nil {
		asker = &dnsclient.Client{}
	}

	for i := range facts.NameServers {
		server := &facts.NameServers[i]
		if len(server.Addresses) == 0 {
			continue
		}
		address := server.Addresses[0]

		server.Asked = true
		answer, err := asker.AskServer(ctx, address, domain, dnsclient.TypeSOA, false)
		switch {
		case err != nil:
			server.Asked = false
			server.AskedReason = shape(err)
		case !answer.Answered:
			server.Asked = false
			server.AskedReason = "the server did not answer the question"
		default:
			// Authority is the flag and the record together: a server may set
			// the bit and answer with nothing, which is not an answer for the
			// zone either.
			server.Authoritative = answer.Authoritative && len(answer.SOA) > 0
		}

		if !within(server.Name, domain) {
			continue
		}
		server.RecursionAsked = true
		probe, err := asker.AskServer(ctx, address, recursionProbe, dnsclient.TypeA, true)
		if err != nil {
			server.RecursionAsked = false
			continue
		}
		// Recursion offered and the question actually answered: a server that
		// refused said no, and one that offers the service but refused this
		// name is not answering for strangers either.
		server.Recursion = probe.RecursionOffered && probe.Answered
	}
}

// within says whether a host is the domain itself or a name beneath it, which
// is the test for whose server it is.
func within(host, domain string) bool {
	host, domain = fold(host), fold(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}
