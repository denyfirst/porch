package dnsclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// A signature keeps what checking it needs: the label count, the TTL it was
// signed with, the signer's name as the record carries it, folded, and the
// signature's own bytes. internal/dnsscan checks it; this only reads it.
func TestASignatureKeepsWhatCheckingItNeeds(t *testing.T) {
	q := name(t, "example.com")
	inception := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expiration := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeSOA,
		record{q, TypeSOA, soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
		record{q, TypeRRSIG, rrsigRecord(t, TypeSOA, 53731, "EXAMPLE.com", inception, expiration)},
	), 0x1234, q, TypeSOA)
	if err != nil || len(got.signatures) != 1 {
		t.Fatalf("read %+v, %v", got.signatures, err)
	}
	s := got.signatures[0]
	if s.Labels != 2 || s.OriginalTTL != 3600 {
		t.Errorf("labels %d, original TTL %d", s.Labels, s.OriginalTTL)
	}
	if !bytes.Equal(s.SignerWire, name(t, "example.com")) {
		t.Errorf("the signer's name reads %q, and is kept folded", s.SignerWire)
	}
	if string(s.Signature) != "not a signature" {
		t.Errorf("the signature reads %q", s.Signature)
	}
}

// A signer's name written as a compression pointer, which RFC 4034 §3.1.7
// forbids, still gives the date, and gives no signature: the record's own
// bytes do not say where one would start.
func TestACompressedSignerGivesTheDateAndNoSignature(t *testing.T) {
	q := name(t, "example.com")
	expiration := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	rdata := make([]byte, 0, 32)
	rdata = binary.BigEndian.AppendUint16(rdata, TypeSOA)
	rdata = append(rdata, 13, 2)
	rdata = binary.BigEndian.AppendUint32(rdata, 3600)
	rdata = binary.BigEndian.AppendUint32(rdata, uint32(expiration.Unix()))
	rdata = binary.BigEndian.AppendUint32(rdata, uint32(expiration.AddDate(0, -1, 0).Unix()))
	rdata = binary.BigEndian.AppendUint16(rdata, 53731)
	rdata = append(rdata, 0xC0, headerLen) // the question's name
	rdata = append(rdata, "a signature"...)

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeSOA,
		record{q, TypeSOA, soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
		record{q, TypeRRSIG, rdata},
	), 0x1234, q, TypeSOA)
	if err != nil || len(got.signatures) != 1 {
		t.Fatalf("read %+v, %v", got.signatures, err)
	}
	s := got.signatures[0]
	if s.Signer != "example.com" || !s.Expiration.Equal(expiration) {
		t.Errorf("the header reads %+v", s)
	}
	if s.SignerWire != nil || s.Signature != nil {
		t.Errorf("a signature was located after a compressed name: %q %q", s.SignerWire, s.Signature)
	}
}

// A name inside a record's own bytes is read only where it is written out in
// full, and never past the record.
func TestALiteralNameStaysInsideItsRecord(t *testing.T) {
	for label, rdata := range map[string][]byte{
		"a pointer":          {0xC0, 0x0C},
		"a label past it":    {5, 'a', 'b'},
		"no end":             {1, 'a'},
		"a reserved length":  {0x40, 'a'},
		"nothing":            {},
		"longer than a name": append(bytes.Repeat(append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...), 4), 0),
	} {
		if _, _, ok := literalName(rdata, 0); ok {
			t.Errorf("%s was read as a name", label)
		}
	}
	got, next, ok := literalName([]byte{1, 'A', 0, 9}, 0)
	if !ok || next != 3 || !bytes.Equal(got, []byte{1, 'a', 0}) {
		t.Errorf("read %q to %d, %v", got, next, ok)
	}
}

// The record at the top of the zone is also kept as a signature covers it:
// names expanded and lowercased, then the numbers.
func TestTheTopOfTheZoneIsKeptAsItWasSigned(t *testing.T) {
	q := name(t, "example.com")
	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeSOA,
		record{q, TypeSOA, soaRecord(t, "NS1.Example.NET", "noc.example.com", 7, 7200, 3600, 1209600, 3600)},
	), 0x1234, q, TypeSOA)
	if err != nil || len(got.soa) != 1 {
		t.Fatalf("read %+v, %v", got.soa, err)
	}
	if want := soaRecord(t, "ns1.example.net", "noc.example.com", 7, 7200, 3600, 1209600, 3600); !bytes.Equal(got.soa[0].RDATA, want) {
		t.Errorf("the record reads %x, want %x", got.soa[0].RDATA, want)
	}
}

// Asked unchecked, the query carries the CD bit, and an AD bit on the reply is
// not passed on: a resolver told not to check has vouched for nothing.
func TestAnUncheckedQuestionSetsCDAndBelievesNoAD(t *testing.T) {
	q := name(t, "example.com")
	var flags []uint16
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close() //nolint:errcheck // the test half of a pipe
			buf := make([]byte, udpPayload)
			n, err := server.Read(buf)
			if err != nil || n < headerLen {
				return
			}
			raw := buf[:n]
			flags = append(flags, binary.BigEndian.Uint16(raw[2:4]))
			end, err := skipName(raw, headerLen)
			if err != nil {
				return
			}
			_, _ = server.Write(message(binary.BigEndian.Uint16(raw[0:2]), flagsAnswerValidated, raw[headerLen:end], TypeDNSKEY,
				record{q, TypeDNSKEY, append([]byte{1, 1, 3, 15}, bytes.Repeat([]byte{7}, 32)...)}))
		}()
		return client, nil
	}
	c := &Client{Server: "resolver.invalid:53", Dial: dial}

	checked, err := c.LookupDNSKEY(context.Background(), "example.com")
	if err != nil || !checked.Validated || len(checked.Keys) != 1 {
		t.Fatalf("checked: %+v, %v", checked, err)
	}
	unchecked, err := c.LookupUnchecked(context.Background(), "example.com", TypeDNSKEY)
	if err != nil || len(unchecked.Keys) != 1 {
		t.Fatalf("unchecked: %+v, %v", unchecked, err)
	}
	if unchecked.Validated {
		t.Error("an AD bit on an unchecked answer was passed on")
	}
	const checkingDisabled = 0x0010
	if len(flags) != 2 || flags[0]&checkingDisabled != 0 || flags[1]&checkingDisabled == 0 {
		t.Errorf("the queries carried flags %04x", flags)
	}
}

// A signature record is bytes a resolver chose. Whatever they are, reading
// them ends, and what is kept lies inside the record.
func FuzzParseRRSIG(f *testing.F) {
	f.Add(append(make([]byte, 18), 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 1, 2, 3))
	f.Add(append(make([]byte, 18), 0xC0, 0x00, 1))
	f.Add(make([]byte, 18))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, rdata []byte) {
		got, err := parseRRSIG(rdata, rdata, 0)
		if err != nil {
			return
		}
		if len(got.SignerWire)+len(got.Signature)+18 > len(rdata) {
			t.Errorf("kept %d bytes of a %d-byte record", len(got.SignerWire)+len(got.Signature)+18, len(rdata))
		}
		if (got.SignerWire == nil) != (got.Signature == nil) {
			t.Errorf("a signer without a signature, or the reverse: %q %q", got.SignerWire, got.Signature)
		}
	})
}
