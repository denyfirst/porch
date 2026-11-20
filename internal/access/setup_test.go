package access

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// awaiting is a gate with no access file yet, waiting for code.
func awaiting(t *testing.T, code string) *factorClock {
	t.Helper()
	g := NewGate(filepath.Join(t.TempDir(), "access"), []string{"/login", "/setup", "/style.css"})
	f := &factorClock{g: g, now: time.Unix(1_800_000_000, 0)}
	g.now = func() time.Time { return f.now }
	f.h = g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("inside")) }))
	g.AwaitSetup(code, f.now.Add(SetupLife))
	return f
}

func setupBody(code, password string) string {
	body, _ := json.Marshal(passwordRequest{Code: code, Password: password})
	return string(body)
}

// A setup code is 80 random bits a person can read off a log and type.
func TestASetupCodeIsReadable(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){3}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, err := NewSetupCode()
		if err != nil || !shape.MatchString(code) || seen[code] {
			t.Fatalf("setup code %q, %v", code, err)
		}
		seen[code] = true
	}
}

// Until the first password is set, every page is the setup page and nothing
// else answers; the code sets the password once, signs in, and is spent.
func TestTheSetupCodeSetsTheFirstPasswordOnce(t *testing.T) {
	const code = "abcd-efgh-ijkl-mnop"
	f := awaiting(t, code)

	for _, path := range []string{"/", "/history", "/login"} {
		if w := f.send(http.MethodGet, path, "", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
			t.Errorf("GET %s before setup: %d to %q, want /setup", path, w.Code, w.Header().Get("Location"))
		}
	}
	if w := f.send(http.MethodGet, "/setup", "", nil); w.Body.String() != "inside" {
		t.Errorf("the setup page was not let through: %d", w.Code)
	}
	if _, w := f.signIn(t, "anything at all", ""); errorCode(t, w) != "setup_required" {
		t.Errorf("a sign-in before setup: %d %s", w.Code, w.Body)
	}

	if w := f.send(http.MethodPost, "/api/v1/setup", setupBody("abcd-efgh-ijkl-mnoq", "a long new password"), nil); errorCode(t, w) != "wrong_setup_code" {
		t.Errorf("a wrong code: %d %s", w.Code, w.Body)
	}
	if w := f.send(http.MethodPost, "/api/v1/setup", setupBody(code, "short"), nil); errorCode(t, w) != "weak_password" {
		t.Errorf("a short password: %d %s", w.Code, w.Body)
	}
	if !f.g.SetupPending() {
		t.Fatal("a failed attempt spent the code")
	}

	// Typed as a person reads it: capitals and spaces do not matter.
	w := f.send(http.MethodPost, "/api/v1/setup", setupBody("ABCD EFGH IJKL MNOP", "a long new password"), nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("setting up: %d %s", w.Code, w.Body)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.Value != "" {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || !session.Secure {
		t.Fatal("setting up did not sign in")
	}
	if w := f.send(http.MethodGet, "/history", "", session); w.Body.String() != "inside" {
		t.Error("the session setup opened does not reach the installation")
	}
	if _, err := Unlock(f.g.path, "a long new password"); err != nil {
		t.Errorf("the chosen password does not open the access file: %v", err)
	}
	if len(f.g.Key()) != 32 {
		t.Error("setting up did not hold the data key")
	}

	// Spent: the code sets nothing again, and the pages are the ordinary ones.
	if w := f.send(http.MethodPost, "/api/v1/setup", setupBody(code, "another long password"), nil); errorCode(t, w) != "already_set_up" {
		t.Errorf("the code worked twice: %d %s", w.Code, w.Body)
	}
	if w := f.send(http.MethodGet, "/setup", "", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("GET /setup after setup: %d to %q", w.Code, w.Header().Get("Location"))
	}
	if c, w := f.signIn(t, "a long new password", ""); c == nil {
		t.Errorf("the chosen password does not sign in: %d %s", w.Code, w.Body)
	}
}

// A code works for SetupLife and not after, and is never written down.
func TestASetupCodeExpires(t *testing.T) {
	const code = "abcd-efgh-ijkl-mnop"
	f := awaiting(t, code)
	f.now = f.now.Add(SetupLife + time.Second)
	if w := f.send(http.MethodPost, "/api/v1/setup", setupBody(code, "a long new password"), nil); errorCode(t, w) != "setup_expired" || !strings.Contains(w.Body.String(), "Restart") {
		t.Errorf("an expired code: %d %s", w.Code, w.Body)
	}
	if !f.g.SetupPending() {
		t.Error("an expired code ended the wait; a restart is what prints a new one")
	}
}

// An installation that already has a password is not waiting, whatever it
// was told: the setup page sends to the sign-in page.
func TestAnInstallationWithAPasswordIsNotSetUpAgain(t *testing.T) {
	g, h := behind(t)
	g.AwaitSetup("abcd-efgh-ijkl-mnop", time.Now().Add(SetupLife))
	if g.SetupPending() {
		t.Error("an installation with an access file waits for a setup code")
	}
	if w := do(h, http.MethodGet, "/history", "", nil, nil); w.Header().Get("Location") != "/login" {
		t.Errorf("GET /history: to %q, want /login", w.Header().Get("Location"))
	}
}
