package policy

import (
	"strings"
	"testing"
	"time"
)

var (
	day     = 24 * time.Hour
	issued  = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	retired = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
)

func receipt(log, operator, state string) CTReceipt {
	return CTReceipt{Verified: true, LogID: log, Operator: operator, State: state, Issued: issued}
}

// Chrome's policy, case by case: how many logs a lifetime needs, that two
// operators are needed, and which receipts count.
//
// Each case is one way a count of receipts used to stand in for the question
// and get it wrong. "2 timestamps from 2 logs" read the same for a certificate
// Chrome accepts and for one whose two logs are run by the same operator.
func TestChromesPolicyIsAppliedAsItIsWritten(t *testing.T) {
	short, long := 90*day, 397*day
	for _, tc := range []struct {
		name     string
		receipts []CTReceipt
		lifetime time.Duration
		met      bool
		settled  bool
		needed   int
	}{
		{"two logs, two operators, a 90-day certificate", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("b", "Sectigo", "usable")}, short, true, true, 2},
		{"two logs of one operator", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("b", "Google", "usable")}, short, false, true, 2},
		{"the same log twice", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("a", "Sectigo", "usable")}, short, false, true, 2},
		{"two logs for a certificate longer than 180 days", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("b", "Sectigo", "usable")}, long, false, true, 3},
		{"three logs for a long certificate", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("b", "Sectigo", "qualified"),
			receipt("c", "DigiCert", "readonly")}, long, true, true, 3},
		{"a receipt whose signature failed does not count", []CTReceipt{
			receipt("a", "Google", "usable"), {LogID: "b", Operator: "Sectigo", State: "usable"}}, short, false, true, 2},
		{"a log that is only pending does not count", []CTReceipt{
			receipt("a", "Google", "usable"), receipt("b", "Sectigo", "pending")}, short, false, true, 2},
		{"only static-ct logs do not count", []CTReceipt{
			{Verified: true, LogID: "a", Operator: "Google", State: "usable", Tiled: true},
			{Verified: true, LogID: "b", Operator: "Sectigo", State: "usable", Tiled: true}}, short, false, true, 2},
		{"one log the list does not name may be a newer one", []CTReceipt{
			receipt("a", "Google", "usable"), {LogID: "b", UnknownLog: true}}, short, false, false, 2},
	} {
		got := JudgeChromeCT(tc.receipts, tc.lifetime, "2026-10-01")
		if !got.Judged || got.Met != tc.met || got.Settled != tc.settled || got.Needed != tc.needed {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

// A receipt from a retired log counts if it was issued before the log retired,
// and only embedded.
func TestARetiredLogCountsOnlyForWhatItSignedBeforeRetiring(t *testing.T) {
	before := CTReceipt{Verified: true, LogID: "r", Operator: "Sectigo", State: "retired",
		Since: retired, Issued: retired.Add(-day)}
	after := before
	after.Issued = retired.Add(day)

	if got := JudgeChromeCT([]CTReceipt{receipt("a", "Google", "usable"), before}, 90*day, ""); !got.Met {
		t.Errorf("a receipt signed before the log retired was not counted: %+v", got)
	}
	if got := JudgeChromeCT([]CTReceipt{receipt("a", "Google", "usable"), after}, 90*day, ""); got.Met {
		t.Errorf("a receipt signed after the log retired was counted: %+v", got)
	}
	inHandshake := before
	inHandshake.InHandshake = true
	first := receipt("a", "Google", "usable")
	first.InHandshake = true
	if got := JudgeChromeCT([]CTReceipt{first, inHandshake}, 90*day, ""); got.Met {
		t.Errorf("a retired log's receipt in the handshake was counted: %+v", got)
	}
}

// No receipts is not judged, so nothing is said about a certificate that was
// never compared.
func TestNothingToCompareIsNotAVerdict(t *testing.T) {
	if got := JudgeChromeCT(nil, 90*day, ""); got.Judged || ChromeCTLine(got) != "" || DescribeChromeCT(got) != nil {
		t.Errorf("no receipts were judged: %+v", got)
	}
	untrusted := TransparencyFacts{Embedded: 2, FromLogs: 2, Checked: true,
		Receipts: []CTReceipt{receipt("a", "Google", "usable")}, Lifetime: 90 * day}
	if untrusted.Chrome().Judged {
		t.Error("a certificate outside the public authorities was compared with Chrome's policy")
	}
}

// The line and the note say what was found, in Chrome's name.
func TestTheLineSaysWhetherChromeWouldAccept(t *testing.T) {
	f := TransparencyFacts{Embedded: 2, FromLogs: 2, Trusted: true, Checked: true, Verified: 2,
		ListDate: "2026-10-01", Lifetime: 90 * day,
		Receipts: []CTReceipt{receipt("a", "Google", "usable"), receipt("b", "Sectigo", "usable")}}
	if line := TransparencyLine(f); !strings.Contains(line, "meets Chrome's policy: 2 logs from 2 operators, 2 needed") {
		t.Errorf("the line reads %q", line)
	}

	f.Receipts[1].Operator = "Google"
	line := TransparencyLine(f)
	if !strings.Contains(line, "does not meet Chrome's policy") {
		t.Errorf("one operator twice reads %q", line)
	}
	notes := strings.Join(Texts(DescribeTransparency(f)), " ")
	if !strings.Contains(notes, "Chrome refuses") || !strings.Contains(notes, "2026-10-01") {
		t.Errorf("the notes do not say what Chrome does with it: %s", notes)
	}
}
