package markup

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/display/displaytest"
)

// A page is whatever the scanned server sends, so the reader is fuzzed: it
// must not panic, and nothing it returns may act on a display (audit
// 2026-10-05, F5). Linear on the worst pages measured that day: a megabyte of
// "<", of open comments or of unclosed attributes took under 100 ms.
func FuzzReadPage(f *testing.F) {
	for _, seed := range []string{
		`<html><script src="http://cdn.example/a.js"></script><form action="http://example.test/"><img src=//a.example/b></html>`,
		`<!-- <a href="x"> --><<<<>>>><scr<script>ipt>`,
		"<meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\"><iframe src=\"http://x\u202e.example/\">",
		"<a href=\"http://evil\x1b[2J.example/\">",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, page string) {
		displaytest.Clean(t, Read(strings.NewReader(page), "example.test"))
	})
}
