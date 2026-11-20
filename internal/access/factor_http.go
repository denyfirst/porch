package access

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/qrcode"
)

// errCodeRequired is a sign-in without a code where the second factor is on.
var errCodeRequired = errors.New("a code is required")

const (
	codeRequiredMessage     = "Enter the code from your authenticator app, or one of your recovery codes."
	wrongCredentialsMessage = "The password or the code is not right. After five wrong codes, codes wait five minutes; a recovery code still works."
)

// codeGiven answers a request that carries no code where one is needed, and
// reports whether the request may go on. Nothing is derived to answer it.
func (g *Gate) codeGiven(w http.ResponseWriter, code string) bool {
	on, err := factorOn(g.path)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "unavailable",
			"The password could not be checked. The operator should look at the installation's log.")
		return false
	}
	if on && strings.TrimSpace(code) == "" {
		refuse(w, http.StatusUnauthorized, "code_required", codeRequiredMessage)
		return false
	}
	return true
}

type factorStatus struct {
	On bool `json:"on"`
	// RecoveryLeft is how many recovery codes are still unused.
	RecoveryLeft int `json:"recovery_left"`
	// WrongBefore is how many wrong codes were sent with the right password
	// before this sign-in.
	WrongBefore int `json:"wrong_before"`
	// Fresh is whether this session may change how the installation is
	// signed into without confirming first.
	Fresh bool `json:"fresh"`
}

type factorSetup struct {
	// Secret is the seed in groups of four, for an app that cannot scan.
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	// QR is the code's modules, one string per row from the top, "1" for
	// dark; the page draws them and adds the quiet zone.
	QR []string `json:"qr"`
}

type recoveryAnswer struct {
	Recovery []string `json:"recovery"`
}

// confirmRequiredMessage is what a change to signing in says to a session
// that is not fresh. The page answers it by going to "Confirm it's you".
const confirmRequiredMessage = "Confirm it's you first: this change needs a sign-in, or a confirmation, from the last ten minutes."

// serveFactor answers the second factor's endpoints, for a signed-in session
// only. Every change needs the session to be fresh: signed into, or
// confirmed, within FreshLife. A session left open is enough to read the
// state and not enough to change it.
func (g *Gate) serveFactor(w http.ResponseWriter, r *http.Request) {
	secure(w)
	c, err := r.Cookie(CookieName)
	if err != nil || !g.SignedIn(r) {
		refuse(w, http.StatusUnauthorized, "sign_in", "Sign in to use this installation.")
		return
	}
	if r.URL.Path == "/api/v1/factor" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			refuse(w, http.StatusMethodNotAllowed, "method", "Ask with GET.")
			return
		}
		g.factorStatus(w, c.Value)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		refuse(w, http.StatusMethodNotAllowed, "method", "Send it with POST.")
		return
	}
	if !fromThisPage(r) {
		refuse(w, http.StatusForbidden, "cross_site", "Use this installation's own pages.")
		return
	}
	if !g.fresh(c.Value) {
		refuse(w, http.StatusForbidden, "confirm_required", confirmRequiredMessage)
		return
	}
	if r.URL.Path == "/api/v1/factor/setup" {
		g.factorSetup(w)
		return
	}

	var body passwordRequest
	if r.URL.Path == "/api/v1/factor/on" {
		read, ok := readPassword(w, r)
		if !ok {
			return
		}
		if !sixDigits(appCode(read.Code)) {
			refuse(w, http.StatusBadRequest, "invalid_code", "Enter the six digits the app shows.")
			return
		}
		body = read
		if !g.allow(clientKey(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(attemptInterval/time.Second)))
			refuse(w, http.StatusTooManyRequests, "rate_limited",
				"Too many attempts from this address. Wait a minute and try again.")
			return
		}
	}
	select {
	case g.derive <- struct{}{}:
		defer func() { <-g.derive }()
	case <-time.After(3 * time.Second):
		w.Header().Set("Retry-After", "2")
		refuse(w, http.StatusServiceUnavailable, "busy", "Another sign-in is being checked. Try again in a moment.")
		return
	}
	on, err := factorOn(g.path)
	if err != nil {
		unavailable(w)
		return
	}
	key := g.Key()
	defer clear(key)
	if key == nil {
		unavailable(w)
		return
	}

	switch r.URL.Path {
	case "/api/v1/factor/on":
		if on {
			refuse(w, http.StatusConflict, "already_on", "The second factor is already on.")
			return
		}
		g.factorTurnOn(w, c.Value, key, body)
	case "/api/v1/factor/off":
		if !on {
			refuse(w, http.StatusConflict, "already_off", "The second factor is off.")
			return
		}
		if err := os.Remove(factorPath(g.path)); err != nil {
			unavailable(w)
			return
		}
		g.keepOnly(c.Value)
		w.WriteHeader(http.StatusNoContent)
	case "/api/v1/factor/recovery":
		if !on {
			refuse(w, http.StatusConflict, "already_off", "The second factor is off.")
			return
		}
		st, err := loadFactor(g.path, key)
		if err != nil {
			unavailable(w)
			return
		}
		codes, digests, err := newRecovery(key)
		if err != nil {
			unavailable(w)
			return
		}
		st.Recovery = digests
		if err := saveFactor(g.path, key, st); err != nil {
			unavailable(w)
			return
		}
		answer(w, recoveryAnswer{Recovery: codes})
	default:
		refuse(w, http.StatusNotFound, "not_found", "There is nothing here.")
	}
}

func (g *Gate) factorStatus(w http.ResponseWriter, token string) {
	on, err := factorOn(g.path)
	if err != nil {
		unavailable(w)
		return
	}
	out := factorStatus{On: on, Fresh: g.fresh(token)}
	if on {
		key := g.Key()
		st, err := loadFactor(g.path, key)
		clear(key)
		if err != nil {
			unavailable(w)
			return
		}
		out.RecoveryLeft = len(st.Recovery)
		g.mu.Lock()
		out.WrongBefore = g.wrongBefore
		g.mu.Unlock()
	}
	answer(w, out)
}

// factorSetup makes a seed to scan and holds it, unconfirmed, for setupLife.
// Nothing is written until a code from it is confirmed.
func (g *Gate) factorSetup(w http.ResponseWriter) {
	on, err := factorOn(g.path)
	if err != nil {
		unavailable(w)
		return
	}
	if on {
		refuse(w, http.StatusConflict, "already_on", "The second factor is already on.")
		return
	}
	seed, err := newSeed()
	if err != nil {
		unavailable(w)
		return
	}
	uri := seedURI(seed)
	modules, err := qrcode.Encode([]byte(uri))
	if err != nil {
		unavailable(w)
		return
	}
	rows := make([]string, len(modules))
	for y, row := range modules {
		line := make([]byte, len(row))
		for x, dark := range row {
			line[x] = '0'
			if dark {
				line[x] = '1'
			}
		}
		rows[y] = string(line)
	}
	var groups []string
	for rest := seed; rest != ""; {
		n := min(4, len(rest))
		groups = append(groups, rest[:n])
		rest = rest[n:]
	}

	g.mu.Lock()
	g.setupSeed, g.setupUntil = seed, g.now().Add(setupLife)
	g.mu.Unlock()
	answer(w, factorSetup{Secret: strings.Join(groups, " "), URI: uri, QR: rows})
}

// factorTurnOn confirms the seed shown with a code from it, writes it sealed
// under key, and answers with the recovery codes, once. Every other session
// ends, so one somebody else held does not outlive the change.
func (g *Gate) factorTurnOn(w http.ResponseWriter, session string, key []byte, body passwordRequest) {
	g.mu.Lock()
	seed, until := g.setupSeed, g.setupUntil
	g.mu.Unlock()
	if seed == "" || !g.now().Before(until) {
		refuse(w, http.StatusConflict, "setup_expired",
			"Start again: the code shown to scan is more than ten minutes old, or was never shown.")
		return
	}
	counter, ok := codeCounter(seed, appCode(body.Code), g.now(), -1)
	if !ok {
		refuse(w, http.StatusBadRequest, "wrong_code",
			"That is not the code the app shows now. If it keeps failing, check the phone's clock.")
		return
	}
	codes, digests, err := newRecovery(key)
	if err != nil {
		unavailable(w)
		return
	}
	if err := saveFactor(g.path, key, &factorState{Seed: seed, Last: counter, Recovery: digests}); err != nil {
		unavailable(w)
		return
	}
	g.mu.Lock()
	g.setupSeed, g.setupUntil = "", time.Time{}
	g.wrongCodes, g.wrongBefore = 0, 0
	g.mu.Unlock()
	g.keepOnly(session)
	answer(w, recoveryAnswer{Recovery: codes})
}

// serveConfirm is "Confirm it's you": a signed-in session shows the second
// factor again, or the password where there is none, and is fresh for
// FreshLife. Wrong answers count against the session, and confirmMisses of
// them end it: the person signs in again with the password and the code.
func (g *Gate) serveConfirm(w http.ResponseWriter, r *http.Request) {
	secure(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		refuse(w, http.StatusMethodNotAllowed, "method", "Confirm with POST.")
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil || !g.SignedIn(r) {
		refuse(w, http.StatusUnauthorized, "sign_in", "Sign in to use this installation.")
		return
	}
	body, ok := readPassword(w, r)
	if !ok {
		return
	}
	if !g.allow(clientKey(r)) {
		w.Header().Set("Retry-After", strconv.Itoa(int(attemptInterval/time.Second)))
		refuse(w, http.StatusTooManyRequests, "rate_limited",
			"Too many attempts from this address. Wait a minute and try again.")
		return
	}
	select {
	case g.derive <- struct{}{}:
		defer func() { <-g.derive }()
	case <-time.After(3 * time.Second):
		w.Header().Set("Retry-After", "2")
		refuse(w, http.StatusServiceUnavailable, "busy", "Another sign-in is being checked. Try again in a moment.")
		return
	}
	on, err := factorOn(g.path)
	if err != nil {
		unavailable(w)
		return
	}

	wrong := "That is not this installation's password."
	if on {
		wrong = "That is not the code the app shows now, or an unused recovery code."
		if strings.TrimSpace(body.Code) == "" {
			refuse(w, http.StatusBadRequest, "code_required", codeRequiredMessage)
			return
		}
		key := g.Key()
		_, err = g.confirmFactor(key, body.Code)
		clear(key)
		if err != nil && !errors.Is(err, errWrongCredentials) {
			unavailable(w)
			return
		}
	} else {
		if body.Password == "" {
			refuse(w, http.StatusBadRequest, "password_required", "Enter this installation's password.")
			return
		}
		var key []byte
		key, err = Unlock(g.path, body.Password)
		clear(key)
		if err != nil && !errors.Is(err, ErrWrongPassword) {
			unavailable(w)
			return
		}
	}
	if err != nil {
		if g.missed(c.Value) {
			http.SetCookie(w, expired())
			refuse(w, http.StatusUnauthorized, "signed_out",
				"Five wrong answers: this session has ended. Sign in again.")
			return
		}
		refuse(w, http.StatusUnauthorized, "wrong_confirmation", wrong)
		return
	}
	g.confirmed(c.Value)
	w.WriteHeader(http.StatusNoContent)
}

// missed counts a wrong answer against token's session and reports whether
// that ended it.
func (g *Gate) missed(token string) bool {
	id := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[id]
	if !ok {
		return true
	}
	s.misses++
	if s.misses >= confirmMisses {
		delete(g.sessions, id)
		return true
	}
	return false
}

// confirmed makes token's session fresh again.
func (g *Gate) confirmed(token string) {
	id := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.sessions[id]; ok {
		s.fresh, s.misses = g.now().Add(FreshLife), 0
	}
}

func answer(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func unavailable(w http.ResponseWriter) {
	refuse(w, http.StatusInternalServerError, "unavailable",
		"The second factor could not be read or saved. The operator should look at the installation's log.")
}
