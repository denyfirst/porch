package access

import (
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

// serveFactor answers the second factor's endpoints, for a signed-in
// session only. Turning it on, turning it off and making new recovery codes
// each ask for the password, and the last two for a code as well: a session
// left open is not enough to change how this installation is signed into.
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
		g.factorStatus(w)
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
	if r.URL.Path == "/api/v1/factor/setup" {
		g.factorSetup(w)
		return
	}

	body, ok := readPassword(w, r)
	if !ok {
		return
	}
	if r.URL.Path == "/api/v1/factor/on" && !sixDigits(appCode(body.Code)) {
		refuse(w, http.StatusBadRequest, "invalid_code", "Enter the six digits the app shows.")
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		refuse(w, http.StatusUnauthorized, "code_required", codeRequiredMessage)
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

	switch r.URL.Path {
	case "/api/v1/factor/on":
		if on {
			refuse(w, http.StatusConflict, "already_on", "The second factor is already on.")
			return
		}
		g.factorTurnOn(w, c.Value, body)
	case "/api/v1/factor/off", "/api/v1/factor/recovery":
		if !on {
			refuse(w, http.StatusConflict, "already_off", "The second factor is off.")
			return
		}
		key, err := Unlock(g.path, body.Password)
		var st *factorState
		if err == nil {
			st, err = g.confirmFactor(key, body.Code)
		}
		defer clear(key)
		switch {
		case err == nil:
		case errors.Is(err, ErrWrongPassword), errors.Is(err, errWrongCredentials):
			refuse(w, http.StatusUnauthorized, "wrong_credentials", wrongCredentialsMessage)
			return
		default:
			unavailable(w)
			return
		}
		if r.URL.Path == "/api/v1/factor/off" {
			if err := os.Remove(factorPath(g.path)); err != nil {
				unavailable(w)
				return
			}
			g.keepOnly(c.Value)
			w.WriteHeader(http.StatusNoContent)
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
	}
}

func (g *Gate) factorStatus(w http.ResponseWriter) {
	on, err := factorOn(g.path)
	if err != nil {
		unavailable(w)
		return
	}
	out := factorStatus{On: on}
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
// Nothing is written until a code from it is confirmed with the password.
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

// factorTurnOn confirms the seed shown with a code from it and the password,
// writes it sealed, and answers with the recovery codes, once. Every other
// session ends, so one somebody else held does not outlive the change.
func (g *Gate) factorTurnOn(w http.ResponseWriter, session string, body passwordRequest) {
	g.mu.Lock()
	seed, until := g.setupSeed, g.setupUntil
	g.mu.Unlock()
	if seed == "" || !g.now().Before(until) {
		refuse(w, http.StatusConflict, "setup_expired",
			"Start again: the code shown to scan is more than ten minutes old, or was never shown.")
		return
	}
	key, err := Unlock(g.path, body.Password)
	switch {
	case err == nil:
	case errors.Is(err, ErrWrongPassword):
		refuse(w, http.StatusUnauthorized, "wrong_password", "The password is not right.")
		return
	default:
		unavailable(w)
		return
	}
	defer clear(key)
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

func answer(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func unavailable(w http.ResponseWriter) {
	refuse(w, http.StatusInternalServerError, "unavailable",
		"The second factor could not be read or saved. The operator should look at the installation's log.")
}
