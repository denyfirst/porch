package updates

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler answers the pages under /api/v1/updates. porchd puts it behind
// the password, like every route, and nowhere on the demonstration.
//
//	GET  /api/v1/updates        what was last found, and the choice
//	POST /api/v1/updates/check  check now (spaced at least MinInterval apart)
//	POST /api/v1/updates/daily  {"daily": true|false}
//
// A write is refused unless this installation's own page sent it: the
// browser says so in Sec-Fetch-Site, which a script cannot set.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		switch {
		case r.URL.Path == "/api/v1/updates" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, s.State())

		case r.URL.Path == "/api/v1/updates/check" && r.Method == http.MethodPost:
			if !fromThisPage(r) {
				refuse(w, http.StatusForbidden, "cross_site", "Check for updates from this installation's own pages.")
				return
			}
			writeJSON(w, http.StatusOK, s.CheckNow(r.Context()))

		case r.URL.Path == "/api/v1/updates/daily" && r.Method == http.MethodPost:
			if !fromThisPage(r) {
				refuse(w, http.StatusForbidden, "cross_site", "Change this from this installation's own pages.")
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				refuse(w, http.StatusUnsupportedMediaType, "unsupported_media", "Send application/json.")
				return
			}
			var body struct {
				Daily *bool `json:"daily"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&body); err != nil || body.Daily == nil {
				refuse(w, http.StatusBadRequest, "invalid_body", `Send {"daily": true} or {"daily": false}.`)
				return
			}
			if err := s.SetDaily(*body.Daily); err != nil {
				refuse(w, http.StatusInternalServerError, "unavailable", "The choice could not be kept.")
				return
			}
			writeJSON(w, http.StatusOK, s.State())

		default:
			refuse(w, http.StatusNotFound, "not_found", "There is nothing here.")
		}
	})
}

func fromThisPage(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
		return true
	}
	return false
}

// secure sets the headers every API answer here carries: JSON that needs no
// resource and is never cached.
func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]map[string]string{"error": {"code": code, "message": message}})
}
