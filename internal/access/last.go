package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// The last run on New check, for as long as the session that ran it.
//
// New check is a page like any other, so leaving it dropped what it showed,
// and a run takes minutes. What a run found is kept whole in History; held
// here are only the names of those reports, on the session, in this process's
// memory, so that New check can draw the run again when it is opened again.
// They go with the session: on sign-out, when it runs out, when another
// session changes the password, and on restart. Nothing is written to the
// browser or to disk for it, and a new sign-in starts with an empty page,
// because earlier runs are History's to show (asked for on 2026-11-21).
//
//	GET  /api/v1/session/last   {"ids": [...]}, empty when nothing was run
//	PUT  /api/v1/session/last   {"ids": [...]} replaces them; [] clears them

// maxLastRun is how many reports one run can name: one for each check, with
// room to spare, and no more, because this is memory a signed-in page fills.
const maxLastRun = 8

type lastRun struct {
	IDs []string `json:"ids"`
}

func (g *Gate) serveLastRun(w http.ResponseWriter, r *http.Request) {
	secure(w)
	c, err := r.Cookie(CookieName)
	if err != nil || !g.SignedIn(r) {
		refuse(w, http.StatusUnauthorized, "sign_in", "Sign in to use this installation.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		answer(w, lastRun{IDs: g.lastRun(c.Value)})
	case http.MethodPut:
		if !fromThisPage(r) {
			refuse(w, http.StatusForbidden, "cross_site", "Use this installation's own pages.")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			refuse(w, http.StatusUnsupportedMediaType, "unsupported_media", "Send application/json.")
			return
		}
		var body lastRun
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil || len(body.IDs) > maxLastRun {
			refuse(w, http.StatusBadRequest, "invalid_body", "Send the names of at most eight reports.")
			return
		}
		for _, id := range body.IDs {
			if !reportName(id) {
				refuse(w, http.StatusBadRequest, "invalid_body", "That is not the name of a report History keeps.")
				return
			}
		}
		g.setLastRun(c.Value, body.IDs)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT")
		refuse(w, http.StatusMethodNotAllowed, "method", "Read the last run with GET, and set it with PUT.")
	}
}

// reportName accepts the form History names its reports in, thirty-two
// lowercase hexadecimal characters, and nothing else: what is held here is
// read back into a path under /api/v1/history/.
func reportName(id string) bool {
	if len(id) != 32 || id != strings.ToLower(id) {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (g *Gate) lastRun(token string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.sessions[sha256.Sum256([]byte(token))]; ok && g.now().Before(s.until) {
		return append([]string{}, s.last...)
	}
	return []string{}
}

func (g *Gate) setLastRun(token string, ids []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.sessions[sha256.Sum256([]byte(token))]; ok && g.now().Before(s.until) {
		s.last = append([]string(nil), ids...)
	}
}
