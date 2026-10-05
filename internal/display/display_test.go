package display

import "testing"

// Nothing that acts on a display, or makes a reader misread one, survives, and
// nothing else is touched.
func TestNothingCanActOnTheDisplay(t *testing.T) {
	for in, want := range map[string]string{
		"_spf.example.com":        "_spf.example.com",
		"%{ir}.%{v}._spf.example": "%{ir}.%{v}._spf.example",
		"räksmörgås.example":      "räksmörgås.example",
		"esc\x1b[2Khere":          "esc\ufffd[2Khere",
		"csi\u009b2J":             "csi\ufffd2J",
		"safe\u202emoc.example":   "safe\ufffdmoc.example",
		"goo\u200bgle.example":    "goo\ufffdgle.example",
		"line\nbreak":             "line\ufffdbreak",
		"del\x7f":                 "del\ufffd",
		"eight-bit\x9b2J":         "eight-bit\ufffd2J",
		"half\xe2\x80":            "half\ufffd",
	} {
		if got := Mark(in); got != want {
			t.Errorf("Mark(%q) = %q, want %q", in, got, want)
		}
	}
}
