package web

import (
	"strings"
	"testing"
)

// No page served to a reader contains a template action.
//
// `render` parses a fragment as a template only where the page has data for
// it. A fragment with no data is copied through byte for byte — which is
// exactly right for the plain ones, and silent the day one of them gains a
// condition. On 2026-09-27 `assets/names.html` gained `{{if .Demo}}`, the
// demonstration's entry gained a value for it, and the entry every other
// installation reads did not: every self-hosted copy of v0.23.x served the
// word `{{.Target}}` to whoever opened the page, with both halves of the
// condition printed one after the other.
//
// Nothing could have caught that except this. The demonstration's tests read
// the demonstration's page, the self-hosted tests read the sentences they were
// written about, and a template action is not a sentence anybody thought to
// look for. So this looks for the shape rather than for the words: a served
// page with `{{` in it is a page whose data went missing, whatever the page
// and whatever the field.
func TestNoServedPageLeaksATemplateAction(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		for _, leak := range []string{"{{", "}}"} {
			if strings.Contains(body, leak) {
				around := body
				if i := strings.Index(body, leak); i >= 0 {
					from := max(0, i-60)
					to := min(len(body), i+90)
					around = body[from:to]
				}
				t.Errorf("%s serves %q, so its fragment was copied rather than executed "+
					"— the page has a template action and no data:\n…%s…", path, leak, around)
			}
		}
	}
}
