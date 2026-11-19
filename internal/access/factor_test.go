package access

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RFC 4226's appendix D: the secret "12345678901234567890", counters 0 to 9.
func TestHOTPIsRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := hotp([]byte("12345678901234567890"), uint64(counter)); got != code {
			t.Errorf("counter %d: %s, want %s", counter, got, code)
		}
	}
}

// RFC 6238's appendix B, SHA1, read at six digits: 94287082 at 59 seconds,
// 07081804 at 1111111109. A code is accepted once, and one step either side.
func TestTOTPIsRFC6238(t *testing.T) {
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if counter, ok := codeCounter(seed, "287082", time.Unix(59, 0), -1); !ok || counter != 1 {
		t.Errorf("59 s: %d %v", counter, ok)
	}
	if counter, ok := codeCounter(seed, "081804", time.Unix(1111111109, 0), -1); !ok || counter != 37037036 {
		t.Errorf("1111111109 s: %d %v", counter, ok)
	}
	if _, ok := codeCounter(seed, "081804", time.Unix(1111111109, 0), 37037036); ok {
		t.Error("a code was accepted a second time")
	}
	if _, ok := codeCounter(seed, "081804", time.Unix(1111111109+60, 0), -1); ok {
		t.Error("a code two steps old was accepted")
	}
	for _, bad := range []string{"", "28708", "2870822", "28708a", " 287082"} {
		if _, ok := codeCounter(seed, bad, time.Unix(59, 0), -1); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The key URI names denyfirst as the issuer and porch as the account, and
// nothing about the installation; it asks for no image, which an app would
// fetch from wherever the URI said.
func TestTheKeyURINamesNoOtherCompanyAndNoHost(t *testing.T) {
	uri := seedURI("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if uri != "otpauth://totp/denyfirst:porch?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=denyfirst" {
		t.Errorf("key URI %q", uri)
	}
	for _, never := range []string{"image=", "Porch", "localhost"} {
		if strings.Contains(uri, never) {
			t.Errorf("the key URI carries %q", never)
		}
	}
}

// factorClock is a gate whose clock the test moves.
type factorClock struct {
	g    *Gate
	h    http.Handler
	now  time.Time
	next int
}

func newFactorClock(t *testing.T) *factorClock {
	t.Helper()
	g, h := behind(t)
	f := &factorClock{g: g, h: h, now: time.Unix(1_800_000_000, 0)}
	g.now = func() time.Time { return f.now }
	return f
}

// send asks from a fresh address each time, so the per-address allowance is
// not what a test measures unless it means to.
func (f *factorClock) send(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	f.next++
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100." + strconv.Itoa(f.next%250+1) + ":5000"
	r.Host = "localhost:8080"
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *factorClock) signIn(t *testing.T, password, code string) (*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(passwordRequest{Password: password, Code: code})
	w := f.send(http.MethodPost, "/api/v1/session", string(body), nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.Value != "" {
			return c, w
		}
	}
	return nil, w
}

// code is what the app shows now for seed.
func (f *factorClock) code(t *testing.T, seed string) string {
	t.Helper()
	key, err := seedEncoding.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(key, uint64(f.now.Unix()/30))
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error.Code
}

// turnOn sets the second factor up for a signed-in session and returns the
// seed and the recovery codes.
func (f *factorClock) turnOn(t *testing.T, session *http.Cookie) (string, []string) {
	t.Helper()
	w := f.send(http.MethodPost, "/api/v1/factor/setup", "", session)
	var setup factorSetup
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &setup) != nil {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	seed := strings.ReplaceAll(setup.Secret, " ", "")
	if !validSeed(seed) || setup.URI != seedURI(seed) {
		t.Fatalf("setup showed %q and %q", setup.Secret, setup.URI)
	}
	if n := len(setup.QR); n < 21 || n > 57 || (n-17)%4 != 0 {
		t.Fatalf("the code to scan is %d rows", n)
	}
	for _, row := range setup.QR {
		if len(row) != len(setup.QR) || strings.Trim(row, "01") != "" {
			t.Fatal("the code to scan is not a square of modules")
		}
	}
	body, _ := json.Marshal(passwordRequest{Password: testPassword, Code: f.code(t, seed)})
	w = f.send(http.MethodPost, "/api/v1/factor/on", string(body), session)
	var got recoveryAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("turning on: %d %s", w.Code, w.Body)
	}
	return seed, got.Recovery
}

// Turning it on takes the password and a code from what was scanned, writes
// nothing readable, gives ten recovery codes once, and ends every other
// session.
func TestTurningTheSecondFactorOn(t *testing.T) {
	f := newFactorClock(t)
	session, _ := f.signIn(t, testPassword, "")
	other, _ := f.signIn(t, testPassword, "")
	if session == nil || other == nil {
		t.Fatal("could not sign in")
	}

	if w := f.send(http.MethodPost, "/api/v1/factor/on", `{"password":"`+testPassword+`","code":"123456"}`, session); errorCode(t, w) != "setup_expired" {
		t.Errorf("turned on with nothing shown to scan: %d %s", w.Code, w.Body)
	}
	w := f.send(http.MethodPost, "/api/v1/factor/setup", "", session)
	var setup factorSetup
	_ = json.Unmarshal(w.Body.Bytes(), &setup)
	seed := strings.ReplaceAll(setup.Secret, " ", "")
	if w := f.send(http.MethodPost, "/api/v1/factor/on", `{"password":"`+testPassword+`","code":"000000"}`, session); errorCode(t, w) != "wrong_code" {
		t.Errorf("a wrong code turned it on: %d %s", w.Code, w.Body)
	}
	if w := f.send(http.MethodPost, "/api/v1/factor/on", `{"password":"not it at all","code":"`+f.code(t, seed)+`"}`, session); errorCode(t, w) != "wrong_password" {
		t.Errorf("a wrong password turned it on: %d %s", w.Code, w.Body)
	}
	if on, _ := factorOn(f.g.path); on {
		t.Fatal("a failed attempt wrote the second factor")
	}
	body, _ := json.Marshal(passwordRequest{Password: testPassword, Code: f.code(t, seed)})
	w = f.send(http.MethodPost, "/api/v1/factor/on", string(body), session)
	var got recoveryAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("turning on: %d %s", w.Code, w.Body)
	}
	shape := regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){5}$`)
	seen := map[string]bool{}
	for _, c := range got.Recovery {
		if !shape.MatchString(c) || seen[c] {
			t.Errorf("recovery code %q", c)
		}
		seen[c] = true
	}
	if len(got.Recovery) != recoveryCount {
		t.Errorf("%d recovery codes", len(got.Recovery))
	}

	raw, err := os.ReadFile(factorPath(f.g.path))
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(factorPath(f.g.path)); info.Mode().Perm() != 0o600 {
		t.Errorf("the file is %v", info.Mode().Perm())
	}
	for _, secret := range append([]string{seed, strings.ToLower(seed)}, got.Recovery...) {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the file holds %q in the clear", secret)
		}
	}
	if w := f.send(http.MethodGet, "/history", "", other); w.Code != http.StatusSeeOther {
		t.Error("another session outlived turning the second factor on")
	}
	if w := f.send(http.MethodGet, "/history", "", session); w.Body.String() != "inside" {
		t.Error("the session that turned it on was ended")
	}
	if w := f.send(http.MethodPost, "/api/v1/factor/setup", "", session); errorCode(t, w) != "already_on" {
		t.Errorf("set up again while on: %d", w.Code)
	}
}

// With it on, a sign-in without a code is told so before the password is
// read; a wrong password and a wrong code are one answer; a code is taken
// once; a recovery code once.
func TestSigningInWithTheSecondFactor(t *testing.T) {
	f := newFactorClock(t)
	session, _ := f.signIn(t, testPassword, "")
	seed, recovery := f.turnOn(t, session)

	for i := 0; i < attemptBurst+3; i++ {
		if _, w := f.signIn(t, "anything at all", ""); errorCode(t, w) != "code_required" {
			t.Fatalf("a sign-in without a code: %d %s", w.Code, w.Body)
		}
	}

	f.now = f.now.Add(30 * time.Second)
	_, wrongPassword := f.signIn(t, "not it at all", f.code(t, seed))
	_, wrongCode := f.signIn(t, testPassword, "000000")
	if wrongPassword.Code != http.StatusUnauthorized || wrongPassword.Body.String() != wrongCode.Body.String() {
		t.Errorf("a wrong password and a wrong code answer differently:\n%s\n%s", wrongPassword.Body, wrongCode.Body)
	}

	code := f.code(t, seed)
	if c, w := f.signIn(t, testPassword, code); c == nil {
		t.Fatalf("the right password and code: %d %s", w.Code, w.Body)
	}
	if c, _ := f.signIn(t, testPassword, code); c != nil {
		t.Error("the same code was accepted twice")
	}

	upper := strings.ToUpper(strings.ReplaceAll(recovery[0], "-", " "))
	if c, w := f.signIn(t, testPassword, upper); c == nil {
		t.Errorf("a recovery code typed in capitals with spaces: %d %s", w.Code, w.Body)
	}
	if c, _ := f.signIn(t, testPassword, recovery[0]); c != nil {
		t.Error("a recovery code was accepted twice")
	}

	// The wrong codes since the sign-in before are shown after the next: the
	// reused recovery code, and not the ones before the sign-ins between.
	f.now = f.now.Add(30 * time.Second)
	fresh, _ := f.signIn(t, testPassword, f.code(t, seed))
	w := f.send(http.MethodGet, "/api/v1/factor", "", fresh)
	var status factorStatus
	_ = json.Unmarshal(w.Body.Bytes(), &status)
	if !status.On || status.RecoveryLeft != recoveryCount-1 || status.WrongBefore != 1 {
		t.Errorf("status %+v, want on, %d left, 1 wrong before", status, recoveryCount-1)
	}
}

// Past five wrong codes in five minutes, across every address, codes wait and
// say nothing different; a recovery code still opens.
func TestWrongCodesWaitForTheWholeInstallation(t *testing.T) {
	f := newFactorClock(t)
	session, _ := f.signIn(t, testPassword, "")
	seed, recovery := f.turnOn(t, session)
	f.now = f.now.Add(30 * time.Second)

	for i := 0; i < codeFailLimit; i++ {
		if c, _ := f.signIn(t, testPassword, "000000"); c != nil {
			t.Fatal("a wrong code opened a session")
		}
	}
	if c, w := f.signIn(t, testPassword, f.code(t, seed)); c != nil || errorCode(t, w) != "wrong_credentials" {
		t.Errorf("the right code was taken while codes wait: %d %s", w.Code, w.Body)
	}
	if c, _ := f.signIn(t, testPassword, recovery[1]); c == nil {
		t.Error("a recovery code was refused while codes wait")
	}
	f.now = f.now.Add(codeFailWindow + 30*time.Second)
	if c, w := f.signIn(t, testPassword, f.code(t, seed)); c == nil {
		t.Errorf("codes still wait after the window: %d %s", w.Code, w.Body)
	}
}

// Changing the password, turning the factor off and making new recovery
// codes each want the password and a code. Off removes the file and ends
// other sessions; new codes replace every old one.
func TestTheSecondFactorGuardsItsOwnChanges(t *testing.T) {
	f := newFactorClock(t)
	session, _ := f.signIn(t, testPassword, "")
	seed, recovery := f.turnOn(t, session)
	f.now = f.now.Add(30 * time.Second)

	if w := f.send(http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"another long password"}`, session); errorCode(t, w) != "code_required" {
		t.Errorf("the password changed without a code: %d %s", w.Code, w.Body)
	}
	// A new password too short is refused before the code is spent, so the
	// same code then changes the password; spaced as some apps show it.
	code := f.code(t, seed)
	short, _ := json.Marshal(passwordRequest{Password: testPassword, Next: "short", Code: code})
	if w := f.send(http.MethodPost, "/api/v1/password", string(short), session); errorCode(t, w) != "weak_password" {
		t.Errorf("a short new password: %d %s", w.Code, w.Body)
	}
	change, _ := json.Marshal(passwordRequest{Password: testPassword, Next: "another long password", Code: code[:3] + " " + code[3:]})
	if w := f.send(http.MethodPost, "/api/v1/password", string(change), session); w.Code != http.StatusNoContent {
		t.Fatalf("changing the password with a code: %d %s", w.Code, w.Body)
	}
	change, _ = json.Marshal(passwordRequest{Password: "another long password", Next: testPassword, Code: recovery[3]})
	if w := f.send(http.MethodPost, "/api/v1/password", string(change), session); w.Code != http.StatusNoContent {
		t.Fatalf("changing it back with a recovery code: %d %s", w.Code, w.Body)
	}
	f.now = f.now.Add(30 * time.Second)

	if w := f.send(http.MethodPost, "/api/v1/factor/off", `{"password":"`+testPassword+`"}`, session); errorCode(t, w) != "code_required" {
		t.Errorf("turned off without a code: %d %s", w.Code, w.Body)
	}
	if w := f.send(http.MethodPost, "/api/v1/factor/off", `{"password":"`+testPassword+`","code":"000000"}`, session); errorCode(t, w) != "wrong_credentials" {
		t.Errorf("turned off with a wrong code: %d %s", w.Code, w.Body)
	}

	body, _ := json.Marshal(passwordRequest{Password: testPassword, Code: f.code(t, seed)})
	w := f.send(http.MethodPost, "/api/v1/factor/recovery", string(body), session)
	var fresh recoveryAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &fresh) != nil || len(fresh.Recovery) != recoveryCount {
		t.Fatalf("new recovery codes: %d %s", w.Code, w.Body)
	}
	if c, _ := f.signIn(t, testPassword, recovery[0]); c != nil {
		t.Error("an old recovery code still opens after new ones were made")
	}

	other, _ := f.signIn(t, testPassword, fresh.Recovery[0])
	body, _ = json.Marshal(passwordRequest{Password: testPassword, Code: fresh.Recovery[1]})
	if w := f.send(http.MethodPost, "/api/v1/factor/off", string(body), session); w.Code != http.StatusNoContent {
		t.Fatalf("turning off: %d %s", w.Code, w.Body)
	}
	if on, _ := factorOn(f.g.path); on {
		t.Error("the file is still there")
	}
	if w := f.send(http.MethodGet, "/history", "", other); w.Code != http.StatusSeeOther {
		t.Error("another session outlived turning the second factor off")
	}
	if c, w := f.signIn(t, testPassword, ""); c == nil {
		t.Errorf("the password alone does not open once it is off: %d %s", w.Code, w.Body)
	}
}

// The endpoints are for a signed-in session on this installation's pages.
func TestTheSecondFactorIsOnlyForASignedInSession(t *testing.T) {
	f := newFactorClock(t)
	for _, path := range []string{"/api/v1/factor/setup", "/api/v1/factor/on", "/api/v1/factor/off", "/api/v1/factor/recovery"} {
		if w := f.send(http.MethodPost, path, `{"password":"`+testPassword+`","code":"123456"}`, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d", path, w.Code)
		}
	}
	if w := f.send(http.MethodGet, "/api/v1/factor", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("status without a session: %d", w.Code)
	}

	session, _ := f.signIn(t, testPassword, "")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/factor/setup", nil)
	r.Host = "localhost:8080"
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(session)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a cross-site setup: %d", w.Code)
	}
	if w := f.send(http.MethodGet, "/api/v1/factor", "", session); !strings.Contains(w.Body.String(), `"on":false`) {
		t.Errorf("status: %s", w.Body)
	}
}
