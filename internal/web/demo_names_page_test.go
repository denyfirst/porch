//go:build demo

package web

import (
	"net/http"
	"testing"
)

// The demonstration offers no name inventory, not even the page.
//
// This deployment undertakes that it queries no transparency log (N12), and the
// endpoint refuses accordingly. A page inviting a visitor to list an estate,
// which then refuses every time, would be worse than no page: it advertises a
// capability this deployment has undertaken not to have, and the visitor learns
// that only after typing somebody's domain into it.
func TestTheDemonstrationOffersNoNameInventory(t *testing.T) {
	for _, path := range []string{"/names", "/names/method"} {
		if w := get(t, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s on the demonstration returned %d, want 404", path, w.Code)
		}
		if _, ok := pages[path]; ok {
			t.Errorf("%s is in the demonstration's page table", path)
		}
	}
}
