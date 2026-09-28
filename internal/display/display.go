// Package display makes a string somebody else chose safe to put in front of
// a person.
//
// Nearly every string in a report was written by whoever is being measured:
// the names in an SPF record, the addresses in a DMARC record or a
// security.txt, the hosts a page links to, what a transparency monitor says a
// certificate is called. A report is printed in a terminal and pasted into
// tickets, so such a string must not be able to act on the display showing it
// (R10). A control byte makes a terminal act — ESC and C1's CSI rewrite the
// lines around them — and a format character makes a reader misread: U+202E
// reverses what follows it in a terminal and a browser alike, and a zero-width
// character makes one name read as another.
//
// internal/certinfo applies the same rule to the certificates a handshake
// carries, and says at length why the whole format category is covered rather
// than a list of the characters known to be dangerous today.
package display

import (
	"strings"
	"unicode"
)

// Mark replaces every character that could act on a display, or make a reader
// misread one, with U+FFFD.
//
// Replaced rather than dropped. Dropping a zero-width space turns a disguised
// name into the name it imitates, which does the disguise's work for it; a
// reader shown a replacement mark can see that something was there.
func Mark(s string) string {
	if strings.IndexFunc(s, acts) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if acts(r) {
			return '\ufffd'
		}
		return r
	}, s)
}

// acts reports whether a character is a control — C0, DEL or C1 — or one of
// Unicode's format characters.
func acts(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r)
}
