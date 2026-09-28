package dmarcreports

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// zone answers TXT from a table, and records what it was asked.
type zone struct {
	records map[string][]string
	fails   map[string]bool
	asked   []string
}

func (z *zone) LookupTXT(_ context.Context, name string) ([]string, error) {
	z.asked = append(z.asked, name)
	if z.fails[name] {
		return nil, errors.New("the resolver did not answer")
	}
	return z.records[name], nil
}

// A rua tag is read as the places it names, and each is placed inside or
// outside the domain.
//
// The tag is written by whoever is being measured, so every shape it arrives
// in is here: the size suffix RFC 7489 §6.2 allows, a scheme other than
// mailto, an address with no domain at all, and a bare address that is not a
// URI — which is dropped rather than guessed at, because guessing mailto:
// would be this package inventing a destination.
func TestTheTagIsReadAsThePlacesItNames(t *testing.T) {
	got := Read("example.test", strings.Join([]string{
		"mailto:dmarc@example.test",
		" mailto:reports@vendor.example!10m ",
		"https://vendor.example/dmarc?x=1",
		"mailto:broken",
		"not-a-uri",
		// A bare address, which is what somebody writes when they forget the
		// scheme. Dropped rather than read as mailto:, because reading it
		// would be this package deciding what the record meant to say — and a
		// destination it invented would then be asked to authorise itself, and
		// reported as refusing when nobody published it in the first place.
		"dmarc@guessed.example",
		"mailto:sub@mail.example.test",
	}, ","))

	if !got.Asked {
		t.Fatal("a tag that was read reads as no tag at all")
	}
	if got.Dropped != 3 {
		t.Errorf("%d destinations were dropped, want 3", got.Dropped)
	}
	for _, d := range got.Destinations {
		if d.Domain == "guessed.example" {
			t.Errorf("a bare address was read as a destination: %+v", d)
		}
	}
	if len(got.Destinations) != 4 {
		t.Fatalf("the tag came back as %+v", got.Destinations)
	}

	for i, want := range []Destination{
		{Domain: "example.test", Mailbox: "dmarc@example.test", Kind: "mailto"},
		{Domain: "vendor.example", Mailbox: "reports@vendor.example", Kind: "mailto", External: true},
		{Domain: "vendor.example", Kind: "https", External: true},
		{Domain: "mail.example.test", Mailbox: "sub@mail.example.test", Kind: "mailto"},
	} {
		if got.Destinations[i] != want {
			t.Errorf("destination %d is %+v, want %+v", i, got.Destinations[i], want)
		}
	}

	// A tag nobody published is not an empty list of destinations (R4).
	if none := Read("example.test", ""); none.Asked {
		t.Errorf("a record with no rua reads as one that named nowhere: %+v", none)
	}
}

// A record naming more destinations than anybody reads is bounded, and says so.
func TestATagNamingMoreThanAnybodyReadsIsBounded(t *testing.T) {
	var many []string
	for i := 0; i < maxDestinations+3; i++ {
		many = append(many, fmt.Sprintf("mailto:r%d@vendor.example", i))
	}

	got := Read("example.test", strings.Join(many, ","))
	if len(got.Destinations) != maxDestinations {
		t.Errorf("%d destinations were kept, want %d", len(got.Destinations), maxDestinations)
	}
	if got.Dropped != 3 {
		t.Errorf("%d were counted as dropped, want 3", got.Dropped)
	}
}

// An external destination is asked whether it agreed, and one inside the
// domain is not.
//
// RFC 7489 §7.1 exists because a domain cannot volunteer somebody else's
// mailbox to receive its mail. It does not apply where the domain names
// itself, and asking anyway would be a lookup with no question behind it.
func TestAnExternalDestinationIsAskedWhetherItAgreed(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test._report._dmarc.agreed.example": {"v=DMARC1"},
	}}

	got := Verify(context.Background(), z, "example.test", Read("example.test", strings.Join([]string{
		"mailto:dmarc@example.test",
		"mailto:a@agreed.example",
		"mailto:b@silent.example",
	}, ",")))

	inside, agreed, silent := got.Destinations[0], got.Destinations[1], got.Destinations[2]

	if inside.Checked {
		t.Error("a destination inside the domain was asked for an authorisation it does not need")
	}
	if !agreed.Checked || !agreed.Authorised || agreed.Reason != "" {
		t.Errorf("a destination that agreed came back as %+v", agreed)
	}
	if !silent.Checked || silent.Authorised || silent.Reason != "" {
		t.Errorf("a destination that published nothing came back as %+v", silent)
	}

	if want := []string{"silent.example"}; !same(got.Unauthorised(), want) {
		t.Errorf("the destinations that will receive nothing are %v, want %v", got.Unauthorised(), want)
	}
	if len(got.Unread()) != 0 {
		t.Errorf("a destination that answered is reported as unread: %v", got.Unread())
	}

	// The authorisation is asked for under the name RFC 7489 §7.1 gives, and
	// once per destination domain rather than once per address.
	if len(z.asked) != 2 {
		t.Errorf("the resolver was asked %d times: %v", len(z.asked), z.asked)
	}
	if z.asked[0] != "example.test._report._dmarc.agreed.example" {
		t.Errorf("the authorisation was looked for at %q", z.asked[0])
	}
}

// Two addresses at one vendor are one question.
func TestOneVendorIsAskedOnce(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test._report._dmarc.vendor.example": {"v=DMARC1"},
	}}

	got := Verify(context.Background(), z, "example.test",
		Read("example.test", "mailto:a@vendor.example,mailto:b@vendor.example,https://vendor.example/x"))

	if len(z.asked) != 1 {
		t.Errorf("one vendor was asked %d times: %v", len(z.asked), z.asked)
	}
	for _, d := range got.Destinations {
		if !d.Authorised {
			t.Errorf("a destination at an agreeing vendor came back as %+v", d)
		}
	}
}

// A resolver that will not answer is not a destination that declined.
//
// The two send an operator to opposite places: one to their DNS provider, one
// to their reporting vendor. Reporting the first as the second would be this
// program telling somebody their vendor refused when nobody asked it (R4).
func TestAResolverThatWillNotAnswerIsNotARefusal(t *testing.T) {
	z := &zone{fails: map[string]bool{
		"example.test._report._dmarc.vendor.example": true,
	}}

	got := Verify(context.Background(), z, "example.test", Read("example.test", "mailto:a@vendor.example"))

	d := got.Destinations[0]
	if d.Authorised {
		t.Errorf("a destination nothing could be read about is reported as agreeing: %+v", d)
	}
	if d.Reason == "" {
		t.Errorf("a destination nothing could be read about gives no reason: %+v", d)
	}
	if len(got.Unauthorised()) != 0 {
		t.Errorf("a lookup that failed is counted as a refusal: %v", got.Unauthorised())
	}
	if want := []string{"vendor.example"}; !same(got.Unread(), want) {
		t.Errorf("the unread destinations are %v, want %v", got.Unread(), want)
	}
}

// Only a record announcing itself as DMARC is agreement.
func TestOnlyADMARCRecordIsAgreement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"the minimum record", []string{"v=DMARC1"}, true},
		{"with tags after it", []string{"v=DMARC1; rua=mailto:x@vendor.example"}, true},
		{"case and space", []string{"  v=dmarc1 "}, true},
		{"beside something else", []string{"some-other-verification=1", "v=DMARC1"}, true},
		{"nothing at all", nil, false},
		{"a name that exists for something else", []string{"v=spf1 -all"}, false},
		{"a record that mentions DMARC later", []string{"x=1; v=DMARC1"}, false},
	} {
		if got := authorises(tc.values); got != tc.want {
			t.Errorf("%s: %v read as %v", tc.name, tc.values, got)
		}
	}
}

// The addresses can be dropped without dropping the finding.
//
// A domain is not a person and a mailbox is. A deployment scanning names
// nobody proved anything about says where the reports go without carrying
// somebody's address into a report a stranger asked for — and everything the
// finding rests on survives, because the finding is about domains.
func TestTheAddressesCanBeDroppedWithoutTheFinding(t *testing.T) {
	z := &zone{}
	got := Verify(context.Background(), z, "example.test",
		Read("example.test", "mailto:dmarc@example.test,mailto:a@vendor.example"))

	without := got.WithoutMailboxes()
	for _, d := range without.Destinations {
		if d.Mailbox != "" {
			t.Errorf("an address survived: %+v", d)
		}
		if d.Domain == "" {
			t.Errorf("a destination lost the domain it points at: %+v", d)
		}
	}
	if want := []string{"vendor.example"}; !same(without.Unauthorised(), want) {
		t.Errorf("the finding did not survive: %v", without.Unauthorised())
	}

	// And the original is untouched, so a caller holding both is not holding
	// one thing twice.
	if got.Destinations[0].Mailbox == "" {
		t.Error("dropping the addresses changed the list it was taken from")
	}
}

func same(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// A report address cannot act on the display that shows it (R10).
func TestAReportAddressCannotActOnTheDisplay(t *testing.T) {
	for in, want := range map[string]string{
		"mailto:r\u009b2J@example.com": "mailto:r\ufffd2J@example.com",
		"mailto:r@ex\u200bample.com":   "mailto:r@ex\ufffdample.com",
		"mailto:r@example.com":         "mailto:r@example.com",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
