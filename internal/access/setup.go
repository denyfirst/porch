package access

// The first visit: a setup code, not a password.
//
// An installation used to make its own password at first start and print it
// to the log, and the operator signed in with it and changed it. It worked,
// and it left a working password in the container's log until it was
// changed, which nothing made anybody do. Now the first start prints a setup
// code instead, as Keybash does: it works once, for fifteen minutes, and
// what it opens is a page where the operator chooses the password. A log
// read later holds a code that opens nothing.
//
// Only somebody who can read the server's log has the code, so the setup
// page is no race for whoever reaches the address first. The code is held in
// memory as a hash and never written: a restart prints a new one and the old
// one stops working.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// SetupLife is how long a setup code works after it is printed.
const SetupLife = 15 * time.Minute

// NewSetupCode returns 80 random bits as four groups of four letters and
// digits, which a person can read off a log and type.
func NewSetupCode() (string, error) {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer clear(raw)
	text := strings.ToLower(seedEncoding.EncodeToString(raw))
	return text[0:4] + "-" + text[4:8] + "-" + text[8:12] + "-" + text[12:16], nil
}

// setupDigest is what a code is held as, read the way it is written: case,
// spaces and hyphens do not matter.
func setupDigest(code string) [32]byte {
	normal := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7'):
			return r
		}
		return -1
	}, code)
	return sha256.Sum256([]byte("porch/setup/v1/" + normal))
}

// AwaitSetup has the gate take code, until until, to set the first password,
// while no access file exists.
func (g *Gate) AwaitSetup(code string, until time.Time) {
	digest := setupDigest(code)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.setupCode, g.setupCodeUntil, g.setupWaiting = digest, until, true
}

// SetupPending reports whether this installation has no password yet and is
// waiting for its setup code.
func (g *Gate) SetupPending() bool {
	g.mu.Lock()
	waiting := g.setupWaiting
	g.mu.Unlock()
	if !waiting {
		return false
	}
	_, err := os.Lstat(g.path)
	return os.IsNotExist(err)
}

// serveSetup sets the first password with the setup code, signs in, and
// spends the code.
func (g *Gate) serveSetup(w http.ResponseWriter, r *http.Request) {
	secure(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		refuse(w, http.StatusMethodNotAllowed, "method", "Set up with POST.")
		return
	}
	body, ok := readPassword(w, r)
	if !ok {
		return
	}
	if !g.SetupPending() {
		refuse(w, http.StatusConflict, "already_set_up", "This installation already has a password. Sign in with it.")
		return
	}
	if err := checkLength(body.Password); err != nil {
		refuse(w, http.StatusBadRequest, "weak_password",
			"A password has to be at least "+strconv.Itoa(MinPassword)+" characters.")
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

	given := setupDigest(body.Code)
	g.mu.Lock()
	want, until, waiting := g.setupCode, g.setupCodeUntil, g.setupWaiting
	g.mu.Unlock()
	switch {
	case !waiting:
		refuse(w, http.StatusConflict, "already_set_up", "This installation already has a password. Sign in with it.")
		return
	case !g.now().Before(until):
		refuse(w, http.StatusGone, "setup_expired",
			"The setup code has expired. Restart porchd and a new one is printed in the log.")
		return
	case subtle.ConstantTimeCompare(given[:], want[:]) != 1:
		refuse(w, http.StatusUnauthorized, "wrong_setup_code", "That is not this installation's setup code.")
		return
	}

	if err := Create(g.path, body.Password); err != nil {
		if _, statErr := os.Lstat(g.path); statErr == nil {
			refuse(w, http.StatusConflict, "already_set_up", "This installation already has a password. Sign in with it.")
			return
		}
		// The page tells the operator to look here, so it is here. The
		// error names the file and the reason, never the password.
		log.Printf("porchd: the first password could not be saved: %v", err)
		refuse(w, http.StatusInternalServerError, "unavailable",
			"The password could not be saved. The operator should look at the installation's log.")
		return
	}
	g.mu.Lock()
	g.setupCode, g.setupWaiting = [32]byte{}, false
	g.mu.Unlock()

	key, err := Unlock(g.path, body.Password)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "unavailable",
			"The password was saved and could not be read back. Sign in with it.")
		return
	}
	token, err := g.openSession(key)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "unavailable", "Sign in with the password you chose.")
		return
	}
	setSession(w, token)
	w.WriteHeader(http.StatusNoContent)
}
