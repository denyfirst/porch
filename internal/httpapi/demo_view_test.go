//go:build demo

package httpapi

import "testing"

// The demonstration shows the whole report of its own estate.
//
// Its hosts are compiled in (N6), so every report it draws is about this
// project's own domain, which is ours to show. It showed less than any copy
// somebody runs until 2026-09-28: no page, no security.txt contacts, no MTA-STS
// policy, no exchangers, no records and no word from the zone's own servers —
// a demonstration misrepresenting the product downwards.
func TestTheDemonstrationShowsItsOwnEstateWhole(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	for what, on := range map[string]bool{
		"page":                 s.web.ReadMarkup,
		"security.txt":         s.web.ShowContacts,
		"MTA-STS policy":       s.mail.ReadSTSPolicy,
		"exchangers":           s.mail.ReadExchangers,
		"DMARC mailboxes":      s.mail.ShowReportAddresses,
		"the records":          s.mail.ShowRecords,
		"the zone servers":     s.dns.AskServers,
		"revocation addresses": s.scanner.ShowRevocationURLs,
	} {
		if !on {
			t.Errorf("the demonstration withholds %s about its own estate", what)
		}
	}
}
