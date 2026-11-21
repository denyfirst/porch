package access

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func lastIDs(t *testing.T, h http.Handler, cookie *http.Cookie) []string {
	t.Helper()
	w := do(h, http.MethodGet, "/api/v1/session/last", "", cookie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reading the last run: %d %s", w.Code, w.Body)
	}
	var got lastRun
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the last run is not JSON: %v", err)
	}
	if got.IDs == nil {
		t.Fatal("an empty last run reads as null, which a page would have to guard against")
	}
	return got.IDs
}

// The last run on New check lasts as long as the session that ran it.
//
// What was asked for on 2026-11-21: moving to another page and back keeps the
// run, and signing out leaves New check empty, because earlier runs are
// History's to show. So the names are held on the session itself, and go
// when it goes; a second session, the same person's or anyone's, starts
// empty and never reads another's.
func TestTheLastRunLastsAsLongAsItsSessionAndNoLonger(t *testing.T) {
	_, h := behind(t)
	first, _ := signIn(t, h, testPassword)
	if first == nil {
		t.Fatal("no session")
	}
	if got := lastIDs(t, h, first); len(got) != 0 {
		t.Fatalf("a new session starts with a run: %v", got)
	}

	ids := []string{strings.Repeat("a", 32), strings.Repeat("0b", 16)}
	body, _ := json.Marshal(lastRun{IDs: ids})
	if w := do(h, http.MethodPut, "/api/v1/session/last", string(body), first, nil); w.Code != http.StatusNoContent {
		t.Fatalf("setting the last run: %d %s", w.Code, w.Body)
	}
	if got := lastIDs(t, h, first); strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Errorf("the session reads back %v, not %v", got, ids)
	}

	// Another session does not see it.
	second, _ := signIn(t, h, testPassword)
	if got := lastIDs(t, h, second); len(got) != 0 {
		t.Errorf("a second session reads the first one's run: %v", got)
	}

	// Signing out ends it, and signing in again starts empty.
	do(h, http.MethodDelete, "/api/v1/session", "", first, nil)
	if w := do(h, http.MethodGet, "/api/v1/session/last", "", first, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a signed-out session still reads a run: %d", w.Code)
	}
	again, _ := signIn(t, h, testPassword)
	if got := lastIDs(t, h, again); len(got) != 0 {
		t.Errorf("signing in again brings the old run back: %v", got)
	}

	// And an empty list clears it.
	do(h, http.MethodPut, "/api/v1/session/last", string(body), again, nil)
	do(h, http.MethodPut, "/api/v1/session/last", `{"ids":[]}`, again, nil)
	if got := lastIDs(t, h, again); len(got) != 0 {
		t.Errorf("an empty list did not clear the run: %v", got)
	}
}

// What a page may put on its session is History's names and nothing else.
//
// The list is read back into paths under /api/v1/history/, and it is memory
// held for a page, so it is taken only in History's own form, eight at most,
// from this installation's pages, and only from a session.
func TestTheLastRunTakesOnlyHistorysNames(t *testing.T) {
	_, h := behind(t)
	cookie, _ := signIn(t, h, testPassword)
	good := strings.Repeat("c", 32)

	for _, tc := range []struct {
		name, body string
		header     map[string]string
		cookie     *http.Cookie
		want       int
	}{
		{"no session", `{"ids":["` + good + `"]}`, nil, nil, http.StatusUnauthorized},
		{"another site", `{"ids":["` + good + `"]}`, map[string]string{"Sec-Fetch-Site": "cross-site"}, cookie, http.StatusForbidden},
		{"not JSON", `{"ids":["` + good + `"]}`, map[string]string{"Content-Type": "text/plain"}, cookie, http.StatusUnsupportedMediaType},
		{"a path", `{"ids":["../../../etc/passwd"]}`, nil, cookie, http.StatusBadRequest},
		{"uppercase", `{"ids":["` + strings.ToUpper(good) + `"]}`, nil, cookie, http.StatusBadRequest},
		{"too short", `{"ids":["abc"]}`, nil, cookie, http.StatusBadRequest},
		{"not hex", `{"ids":["` + strings.Repeat("z", 32) + `"]}`, nil, cookie, http.StatusBadRequest},
		{"nine", `{"ids":[` + strings.TrimSuffix(strings.Repeat(`"`+good+`",`, 9), ",") + `]}`, nil, cookie, http.StatusBadRequest},
		{"another field", `{"ids":[],"target":"example.com"}`, nil, cookie, http.StatusBadRequest},
		{"too long", `{"ids":["` + strings.Repeat("a", 2048) + `"]}`, nil, cookie, http.StatusBadRequest},
	} {
		if w := do(h, http.MethodPut, "/api/v1/session/last", tc.body, tc.cookie, tc.header); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	if got := lastIDs(t, h, cookie); len(got) != 0 {
		t.Errorf("a refused list was kept: %v", got)
	}

	if w := do(h, http.MethodGet, "/api/v1/session/last", "", nil, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("the last run is read without a session: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/v1/session/last", `{"ids":[]}`, cookie, nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST is answered with %d", w.Code)
	}
	if w := do(h, http.MethodGet, "/api/v1/session/last", "", cookie, nil); w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the last run may be cached")
	}
}
