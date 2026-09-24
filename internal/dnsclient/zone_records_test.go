package dnsclient

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// soaRecord builds a start of authority in wire form: two uncompressed names
// and five numbers.
func soaRecord(t *testing.T, primary, mailbox string, numbers ...uint32) []byte {
	t.Helper()

	out, err := encodeName(primary, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", primary, err)
	}
	box, err := encodeName(mailbox, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", mailbox, err)
	}
	out = append(out, box...)
	for _, n := range numbers {
		out = binary.BigEndian.AppendUint32(out, n)
	}
	return out
}

func nsRecord(t *testing.T, host string) []byte {
	t.Helper()

	encoded, err := encodeName(host, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", host, err)
	}
	return encoded
}

// What a zone publishes about itself, read as published: the addresses, the
// servers it is delegated to, the record at the top of it, and the two halves
// of the DNSSEC link.
func TestWhatAZonePublishesAboutItselfIsRead(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	v4 := answering(t, TypeA, "example.com",
		record{q, TypeA, []byte{192, 0, 2, 1}},
		record{q, TypeA, []byte{192, 0, 2, 2}},
	)
	got, err := v4.LookupAddresses(ctx, "example.com", TypeA)
	if err != nil || len(got.Addresses) != 2 {
		t.Fatalf("A: %+v, %v", got, err)
	}
	if got.Addresses[0] != netip.MustParseAddr("192.0.2.1") || got.Addresses[1] != netip.MustParseAddr("192.0.2.2") {
		t.Errorf("the addresses are %v", got.Addresses)
	}

	sixteen := make([]byte, 16)
	sixteen[0], sixteen[1], sixteen[15] = 0x20, 0x01, 0x01
	v6 := answering(t, TypeAAAA, "example.com", record{q, TypeAAAA, sixteen})
	got, err = v6.LookupAddresses(ctx, "example.com", TypeAAAA)
	if err != nil || len(got.Addresses) != 1 || got.Addresses[0] != netip.MustParseAddr("2001::1") {
		t.Fatalf("AAAA: %+v, %v", got, err)
	}

	ns := answering(t, TypeNS, "example.com",
		record{q, TypeNS, nsRecord(t, "a.iana-servers.net")},
		record{q, TypeNS, nsRecord(t, "B.IANA-SERVERS.NET")},
	)
	got, err = ns.LookupNS(ctx, "example.com")
	if err != nil || len(got.NS) != 2 {
		t.Fatalf("NS: %+v, %v", got, err)
	}
	if got.NS[0] != "a.iana-servers.net" || got.NS[1] != "b.iana-servers.net" {
		t.Errorf("the servers are %v, and a name is compared folded (I7)", got.NS)
	}

	soa := answering(t, TypeSOA, "example.com",
		record{q, TypeSOA, soaRecord(t, "ns.icann.org", "noc.dns.icann.org", 2026091801, 7200, 3600, 1209600, 3600)},
	)
	got, err = soa.LookupSOA(ctx, "example.com")
	if err != nil || len(got.SOA) != 1 {
		t.Fatalf("SOA: %+v, %v", got, err)
	}
	want := SOA{
		Primary: "ns.icann.org", Mailbox: "noc.dns.icann.org",
		Serial: 2026091801, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600,
	}
	if got.SOA[0] != want {
		t.Errorf("the record reads %+v, want %+v", got.SOA[0], want)
	}

	ds := answering(t, TypeDS, "example.com",
		record{q, TypeDS, append([]byte{0x9d, 0x0b, 13, 2}, make([]byte, 32)...)},
	)
	got, err = ds.LookupDS(ctx, "example.com")
	if err != nil || len(got.DS) != 1 {
		t.Fatalf("DS: %+v, %v", got, err)
	}
	if got.DS[0].KeyTag != 0x9d0b || got.DS[0].Algorithm != 13 || got.DS[0].DigestType != 2 || len(got.DS[0].Digest) != 32 {
		t.Errorf("the delegation signer reads %+v", got.DS[0])
	}

	keys := answering(t, TypeDNSKEY, "example.com",
		record{q, TypeDNSKEY, append([]byte{0x01, 0x01, 3, 13}, make([]byte, 64)...)},
	)
	got, err = keys.LookupDNSKEY(ctx, "example.com")
	if err != nil || len(got.Keys) != 1 {
		t.Fatalf("DNSKEY: %+v, %v", got, err)
	}
	if got.Keys[0].Flags != 257 || got.Keys[0].Protocol != 3 || got.Keys[0].Algorithm != 13 || len(got.Keys[0].Key) != 64 {
		t.Errorf("the key reads %+v", got.Keys[0])
	}
}

// A record that does not hold what its type says is refused rather than read
// as something else. Everything here is bytes chosen by whoever answered.
func TestAMalformedZoneRecordIsRefused(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	for _, c := range []struct {
		what   string
		qtype  uint16
		rdata  []byte
		lookup func(*Client) (ZoneAnswer, error)
	}{
		{"an A of the wrong length", TypeA, []byte{192, 0, 2},
			func(c *Client) (ZoneAnswer, error) { return c.LookupAddresses(ctx, "example.com", TypeA) }},
		{"an AAAA holding four bytes", TypeAAAA, []byte{192, 0, 2, 1},
			func(c *Client) (ZoneAnswer, error) { return c.LookupAddresses(ctx, "example.com", TypeAAAA) }},
		{"a start of authority without its timers", TypeSOA, soaRecord(t, "ns.example.com", "noc.example.com", 1),
			func(c *Client) (ZoneAnswer, error) { return c.LookupSOA(ctx, "example.com") }},
		{"a delegation signer without a digest", TypeDS, []byte{0, 1, 13, 2},
			func(c *Client) (ZoneAnswer, error) { return c.LookupDS(ctx, "example.com") }},
		{"a key record without a key", TypeDNSKEY, []byte{1, 1, 3, 13},
			func(c *Client) (ZoneAnswer, error) { return c.LookupDNSKEY(ctx, "example.com") }},
	} {
		client := answering(t, c.qtype, "example.com", record{q, c.qtype, c.rdata})
		if _, err := c.lookup(client); err == nil {
			t.Errorf("%s was read as a record", c.what)
		}
	}
}

// A name that does not exist is said to be missing rather than reported as a
// zone publishing nothing, which is the distinction every caller here turns
// into a different sentence (R4).
func TestAZoneThatDoesNotExistSaysSo(t *testing.T) {
	fake := &fakeResolver{missing: map[string]bool{"absent.example.com": true}}
	c := &Client{Server: "resolver.invalid:53", Dial: fake.connFor(t, TypeNS)}

	got, err := c.LookupNS(context.Background(), "absent.example.com")
	if err != nil {
		t.Fatalf("LookupNS: %v", err)
	}
	if got.Existed || len(got.NS) != 0 {
		t.Errorf("a name that does not exist reads as %+v", got)
	}
}

// The bytes a record keeps are its own.
//
// rdata is a window onto the whole reply, so a record that sliced it would
// keep every other byte of the message alive for as long as the record lived —
// a few hundred bytes per lookup held by a scan that asks a dozen. Sabotaging
// the copy escaped every test here, because the value read is identical either
// way; the capacity is what tells them apart, a clone having no room beyond
// its own length.
func TestARecordDoesNotHoldOnToTheReply(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	ds := answering(t, TypeDS, "example.com",
		record{q, TypeDS, append([]byte{0, 1, 13, 2}, make([]byte, 32)...)},
		record{q, TypeDS, append([]byte{0, 2, 13, 2}, make([]byte, 32)...)},
	)
	got, err := ds.LookupDS(ctx, "example.com")
	if err != nil || len(got.DS) != 2 {
		t.Fatalf("DS: %+v, %v", got, err)
	}
	for _, d := range got.DS {
		if cap(d.Digest) != len(d.Digest) {
			t.Errorf("a digest of %d bytes holds a buffer of %d, which is the reply it arrived in", len(d.Digest), cap(d.Digest))
		}
	}

	keys := answering(t, TypeDNSKEY, "example.com",
		record{q, TypeDNSKEY, append([]byte{1, 1, 3, 13}, make([]byte, 64)...)},
		record{q, TypeDNSKEY, append([]byte{1, 0, 3, 13}, make([]byte, 64)...)},
	)
	answer, err := keys.LookupDNSKEY(ctx, "example.com")
	if err != nil || len(answer.Keys) != 2 {
		t.Fatalf("DNSKEY: %+v, %v", answer, err)
	}
	for _, k := range answer.Keys {
		if cap(k.Key) != len(k.Key) {
			t.Errorf("a key of %d bytes holds a buffer of %d", len(k.Key), cap(k.Key))
		}
	}
}

// The alias at a name is read, and a name that is not an alias has none.
//
// Sabotaging the parser escaped every test in internal/dnsscan, which answers
// from a table rather than from bytes: the check reads what a resolver says,
// and this is where what a resolver says becomes records.
func TestTheAliasAtANameIsRead(t *testing.T) {
	ctx := context.Background()
	q := name(t, "www.example.com")

	c := answering(t, TypeCNAME, "www.example.com",
		record{q, TypeCNAME, nsRecord(t, "Pages.Example.NET")},
	)
	got, err := c.LookupCNAME(ctx, "www.example.com")
	if err != nil || len(got.Alias) != 1 {
		t.Fatalf("CNAME: %+v, %v", got, err)
	}
	if got.Alias[0] != "pages.example.net" {
		t.Errorf("the alias reads %q, and a name is compared folded (I7)", got.Alias[0])
	}

	plain := answering(t, TypeCNAME, "www.example.com")
	if got, err := plain.LookupCNAME(ctx, "www.example.com"); err != nil || len(got.Alias) != 0 {
		t.Errorf("a name that is not an alias: %+v, %v", got, err)
	}
}

// How a zone hashes the names it proves absent is read, and a record that does
// not hold what it says is refused.
func TestHowAZoneHashesAbsentNamesIsRead(t *testing.T) {
	ctx := context.Background()
	q := name(t, "example.com")

	c := answering(t, TypeNSEC3PARAM, "example.com",
		record{q, TypeNSEC3PARAM, []byte{1, 0, 0, 12, 4, 0xde, 0xad, 0xbe, 0xef}},
	)
	got, err := c.LookupNSEC3PARAM(ctx, "example.com")
	if err != nil || len(got.NSEC3) != 1 {
		t.Fatalf("NSEC3PARAM: %+v, %v", got, err)
	}
	if got.NSEC3[0].Hash != 1 || got.NSEC3[0].Iterations != 12 || got.NSEC3[0].SaltLength != 4 {
		t.Errorf("the record reads %+v", got.NSEC3[0])
	}

	short := answering(t, TypeNSEC3PARAM, "example.com", record{q, TypeNSEC3PARAM, []byte{1, 0, 0}})
	if _, err := short.LookupNSEC3PARAM(ctx, "example.com"); err == nil {
		t.Error("a record shorter than its own header was read as one")
	}

	lying := answering(t, TypeNSEC3PARAM, "example.com",
		record{q, TypeNSEC3PARAM, []byte{1, 0, 0, 0, 40, 1, 2}},
	)
	if _, err := lying.LookupNSEC3PARAM(ctx, "example.com"); err == nil {
		t.Error("a salt announcing more bytes than the record holds was read")
	}
}

// rrsigRecord builds a signature header in wire form: the fixed eighteen
// bytes, the signer's name uncompressed as RFC 4034 §3.1.7 requires, and a
// signature this package never looks at.
func rrsigRecord(t *testing.T, covered uint16, keyTag uint16, signer string, inception, expiration time.Time) []byte {
	t.Helper()

	name, err := encodeName(signer, false)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}

	out := make([]byte, 0, 18+len(name)+8)
	out = binary.BigEndian.AppendUint16(out, covered)
	out = append(out, 13) // algorithm
	out = append(out, 2)  // labels
	out = binary.BigEndian.AppendUint32(out, 3600)
	out = binary.BigEndian.AppendUint32(out, uint32(expiration.Unix()))
	out = binary.BigEndian.AppendUint32(out, uint32(inception.Unix()))
	out = binary.BigEndian.AppendUint16(out, keyTag)
	out = append(out, name...)
	return append(out, []byte("not a signature")...)
}

// The date a signature runs out is read from the answer it came with.
//
// No question asks for it. Every query this package sends sets the DNSSEC OK
// bit, so a signed zone's answers already carry the signature; what is new is
// reading the one field in it that a report can act on.
func TestWhenASignatureRunsOutIsReadFromTheAnswer(t *testing.T) {
	q := name(t, "example.com")
	inception := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expiration := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	got, err := parseReply(message(0x1234, flagsAnswerValidated, q, TypeSOA,
		record{q, TypeSOA, soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
		record{q, TypeRRSIG, rrsigRecord(t, TypeSOA, 53731, "example.com", inception, expiration)},
		// A signature over another type, which came with the answer and
		// answers nothing that was asked.
		record{q, TypeRRSIG, rrsigRecord(t, TypeDNSKEY, 111, "example.com", inception, expiration.AddDate(0, 0, 30))},
	), 0x1234, q, TypeSOA)
	if err != nil {
		t.Fatalf("a signed answer was refused: %v", err)
	}

	if len(got.soa) != 1 {
		t.Fatalf("the record itself was lost: %+v", got.soa)
	}
	if len(got.signatures) != 1 {
		t.Fatalf("the signatures read %+v, and only the one covering the question answers it", got.signatures)
	}
	s := got.signatures[0]
	if !s.Expiration.Equal(expiration) || !s.Inception.Equal(inception) {
		t.Errorf("the dates read %s to %s", s.Inception, s.Expiration)
	}
	if s.Covered != TypeSOA || s.KeyTag != 53731 || s.Signer != "example.com" {
		t.Errorf("the signature reads %+v", s)
	}
}

// A signature is read only where the records are: at a name in the chain the
// reply itself draws from the question, and long enough to hold its own header.
//
// A resolver is hostile (N5) and can put a record for any name in a reply. A
// signature taken from one would be another zone's date printed as this one's,
// which is the report saying a domain has three weeks when it has none.
func TestASignatureIsReadOnlyWhereTheRecordsAre(t *testing.T) {
	q := name(t, "example.com")
	other := name(t, "example.net")
	inception := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expiration := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	got, err := parseReply(message(0x1234, flagsAnswerValidated, q, TypeSOA,
		record{q, TypeSOA, soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
		record{other, TypeRRSIG, rrsigRecord(t, TypeSOA, 999, "example.net", inception, expiration)},
		// And one too short to hold its own header, which is skipped rather
		// than read past the end of itself.
		record{q, TypeRRSIG, []byte{0, 6, 13}},
	), 0x1234, q, TypeSOA)
	if err != nil {
		t.Fatalf("a reply carrying a signature this cannot use was refused: %v", err)
	}
	if len(got.soa) != 1 {
		t.Errorf("the record itself was lost: %+v", got.soa)
	}
	if len(got.signatures) != 0 {
		t.Errorf("a signature from elsewhere was kept: %+v", got.signatures)
	}
}

// A signature shorter than its own header is refused rather than read past
// itself.
//
// The record's data is a window into the whole message: the slice has capacity
// beyond its length, so a parser that trusted the length would reslice into the
// bytes that follow and read them as dates. It would not panic, which is what
// makes it worth a test — it would answer, with somebody else's numbers.
func TestAShortSignatureIsRefusedRatherThanReadPastItself(t *testing.T) {
	name, err := encodeName("example.com", false)
	if err != nil {
		t.Fatalf("test data is wrong: %v", err)
	}

	// Three bytes of record, then bytes arranged so that everything a reader
	// past the end would need is there: eighteen bytes of header and a valid
	// name exactly where the signer's would be.
	message := make([]byte, 0, 64)
	message = append(message, 0, 6, 13)
	message = append(message, make([]byte, 15)...)
	message = append(message, name...)

	if _, err := parseRRSIG(message, message[0:3], 0); err == nil {
		t.Error("a signature shorter than its own header was read, out of the bytes after it")
	}
}
