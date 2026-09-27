//go:build !demo

package web

import (
	"strings"
	"testing"
)

// The rail marks the page you are standing on, and no other.
//
// A page with no section of its own is filed under the reference one by
// render, which is right for a document and wrong for a part of the
// workspace: /names had none, so somebody who clicked Names watched the mark
// appear on Docs. The mark is the only thing on the page that says where you
// are, and a wrong one is worse than none — it says you are somewhere you are
// not.
func TestTheRailMarksThePageBeingRead(t *testing.T) {
	for path, want := range map[string]string{
		"/":             `href="/" aria-current="page"`,
		"/names":        `href="/names" aria-current="page"`,
		"/domains":      `href="/domains" aria-current="page"`,
		"/history":      `href="/history" aria-current="page"`,
		"/installation": `href="/installation" aria-current="page"`,
		"/docs":         `href="/docs" aria-current="page"`,
	} {
		body := get(t, path).Body.String()
		if !strings.Contains(body, want) {
			t.Errorf("%s does not mark itself in the rail", path)
		}
		if n := strings.Count(body, `aria-current="page"`); n != 1 {
			t.Errorf("%s marks %d rail items, want 1", path, n)
		}
	}
}
