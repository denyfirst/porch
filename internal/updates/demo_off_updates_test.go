//go:build !demo

package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "sshsig", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The key compiled in is the key strangers verify with: the releases line of
// .allowed_signers. A rotated key changes both, in the open, or this fails.
func TestTheCompiledKeyIsTheReleaseKey(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "releases@denyfirst.dev" && f[1] == "ssh-ed25519" {
			if f[2] != ReleaseKey {
				t.Errorf("the compiled key is not the key in .allowed_signers")
			}
			return
		}
	}
	t.Fatal(".allowed_signers names no release key")
}

// release serves a release's two files the way GitHub's store does, and
// counts the requests.
func release(t *testing.T, sums, sig []byte) (*Checker, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("User-Agent") != "porch" {
			t.Errorf("the request carried %q and %q", r.Header.Get("Cookie"), r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write(sums)
		case "/SHA256SUMS.sig":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &Checker{Client: srv.Client(), Base: srv.URL + "/"}, &asked
}

// A signed list gives its version, and only a signed list does.
func TestOnlyASignedListIsRead(t *testing.T) {
	sums, sig := testdata(t, "SHA256SUMS"), testdata(t, "SHA256SUMS.sig")

	c, _ := release(t, sums, sig)
	got, err := c.Check(context.Background())
	if err != nil || got != "v0.27.1" {
		t.Fatalf("the release's own list read %q, %v", got, err)
	}

	// The same list with one name changed, as a channel that served a later
	// version under the old signature would: refused, and said as tampering.
	forged := bytes.ReplaceAll(sums, []byte("v0.27.1"), []byte("v0.99.0"))
	c, _ = release(t, forged, sig)
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrNotVerified) {
		t.Errorf("a changed list read %v", err)
	}

	// Another key's signature over the real list.
	c, _ = release(t, sums, testdata(t, "other-key.sig"))
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrNotVerified) {
		t.Errorf("another key's signature read %v", err)
	}

	// A list too long to be one is not read, rather than cut and refused.
	c, _ = release(t, bytes.Repeat([]byte("a"), maxSums+1), sig)
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrUnreadable) {
		t.Errorf("an oversized list read %v", err)
	}

	// No files at all.
	c, _ = release(t, sums, sig)
	c.Base += "missing/"
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("a release with no files read %v", err)
	}
}

// The version is read from the signed names, and every one has to agree.
func TestTheVersionIsTheOneEveryNameAgreesOn(t *testing.T) {
	if v, err := LatestVersion(testdata(t, "SHA256SUMS")); err != nil || v != "v0.27.1" {
		t.Errorf("the real list reads %q, %v", v, err)
	}
	for name, sums := range map[string]string{
		"two versions":   "aa  porchd_v1.2.3_linux_amd64\nbb  porch-scan_v1.2.4_linux_amd64\n",
		"no artifact":    "aa  BUILD\nbb  docker-compose.yml\n",
		"empty":          "",
		"not a version":  "aa  porchd_v1.2_linux_amd64\n",
		"too many parts": "aa  porchd_v1.2.3.4_linux_amd64\n",
		"too long":       "aa  porchd_v12345.0.0_linux_amd64\n",
		"a path":         "aa  ../porchd_v1.2.3_linux_amd64\n",
		"a suffix":       "aa  porchd_v1.2.3_linux_amd64.sh\n",
		"an extra part":  "aa  porchd_v1.2.3_linux_amd64_x\n",
	} {
		if v, err := LatestVersion([]byte(sums)); err == nil {
			t.Errorf("%s read as %q", name, v)
		}
	}
}

// Newer compares release names and nothing else.
func TestNewerComparesReleases(t *testing.T) {
	for _, c := range []struct {
		running, latest string
		newer           bool
	}{
		{"v0.27.3", "v0.28.0", true},
		{"v0.27.3", "v0.27.10", true},
		{"v0.27.3", "v1.0.0", true},
		{"v0.27.3", "v0.27.3", false},
		{"v0.28.0", "v0.27.9", false},
		// A build not made by build.sh is never said to be behind.
		{"(unknown: not built by scripts/build.sh)", "v0.28.0", false},
		{"v0.27.3", "v0.28.0-rc1", false},
		{"v0.27.3", "", false},
	} {
		if got := Newer(c.running, c.latest); got != c.newer {
			t.Errorf("Newer(%q, %q) = %v", c.running, c.latest, got)
		}
	}
}

// A redirect is followed to GitHub's hosts over HTTPS, and nowhere else.
func TestARedirectStaysOnGitHub(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://github.com/denyfirst/porch/releases/download/v0.28.0/SHA256SUMS": true,
		"https://objects.githubusercontent.com/x":                                 true,
		"https://release-assets.githubusercontent.com/x":                          true,
		"https://GitHub.com/x":                                                    true,
		"http://github.com/x":                                                     false,
		"https://github.com:8443/x":                                               false,
		"https://user@github.com/x":                                               false,
		"https://github.com.example/x":                                            false,
		"https://example.com/x":                                                   false,
		"https://127.0.0.1/x":                                                     false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if allowedURL(u) != ok {
			t.Errorf("%s: allowed %v, want %v", raw, !ok, ok)
		}
	}
	via := make([]*http.Request, maxRedirect)
	next, _ := http.NewRequest(http.MethodGet, "https://github.com/x", nil)
	if checkRedirect(next, via) == nil {
		t.Error("a sixth redirect was followed")
	}
	if c := (&Checker{}).client(); c.CheckRedirect == nil || c.Transport.(*http.Transport).Proxy != nil {
		t.Error("the default client follows any redirect, or goes through a proxy")
	}
}

// Checks are spaced apart however often the button is pressed, an error is
// said without losing what a verified list said, and the state reads newer
// only against the running release.
func TestCheckingNowIsSpacedAndKeepsWhatVerified(t *testing.T) {
	sums, sig := testdata(t, "SHA256SUMS"), testdata(t, "SHA256SUMS.sig")
	c, asked := release(t, sums, sig)
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	s := &Service{Checker: c, Settings: &Settings{}, Running: "v0.27.0", now: func() time.Time { return now }}

	st := s.CheckNow(context.Background())
	if st.Latest != "v0.27.1" || !st.Newer || st.Error != "" || st.CheckedAt.IsZero() {
		t.Fatalf("the first check reads %+v", st)
	}
	before := asked.Load()
	s.CheckNow(context.Background())
	if asked.Load() != before {
		t.Error("a second check within a minute asked GitHub again")
	}

	now = now.Add(2 * time.Minute)
	c.Base += "missing/"
	st = s.CheckNow(context.Background())
	if st.Error == "" || st.Latest != "v0.27.1" || st.Tampered {
		t.Errorf("a failed check reads %+v", st)
	}

	// A list that does not verify is said as tampering, and the version it
	// names is not taken.
	forged, _ := release(t, bytes.ReplaceAll(sums, []byte("v0.27.1"), []byte("v0.99.0")), sig)
	s.Checker = forged
	now = now.Add(2 * time.Minute)
	st = s.CheckNow(context.Background())
	if !st.Tampered || st.Latest != "v0.27.1" {
		t.Errorf("a forged list reads %+v", st)
	}

	s.Running = "v0.27.1"
	if s.State().Newer {
		t.Error("the running release is said to be behind itself")
	}
}

// The daily choice is off until made, kept on disk readable by this user
// alone, and off again for a file this version did not write.
func TestTheDailyChoiceIsKeptAndOffByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updates.json")
	s := &Settings{Path: path}
	if err := s.Load(); err != nil || s.Daily() {
		t.Fatalf("a missing file reads %v, %v", s.Daily(), err)
	}
	if err := s.SetDaily(true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file is %v, %v", info, err)
	}
	again := &Settings{Path: path}
	if err := again.Load(); err != nil || !again.Daily() {
		t.Errorf("the choice did not survive: %v, %v", again.Daily(), err)
	}
	for _, body := range []string{"{", `{"daily": true, "url": "https://example.com"}`, `{"daily": "yes"}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		bad := &Settings{Path: path}
		if err := bad.Load(); err == nil || bad.Daily() {
			t.Errorf("%q reads %v, %v", body, bad.Daily(), err)
		}
	}
}

// The handler answers its three routes, and only from this installation's
// pages for the two that change something.
func TestTheHandlerAnswersOnlyItsOwnPages(t *testing.T) {
	sums, sig := testdata(t, "SHA256SUMS"), testdata(t, "SHA256SUMS.sig")
	c, asked := release(t, sums, sig)
	s := &Service{Checker: c, Settings: &Settings{Path: filepath.Join(t.TempDir(), "u.json")}, Running: "v0.27.0"}
	h := s.Handler()

	do := func(method, path, site, ctype, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodGet, "/api/v1/updates", "same-origin", "", "")
	var st State
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Running != "v0.27.0" || st.Daily {
		t.Fatalf("GET read %d %s", w.Code, w.Body.String())
	}
	for _, h := range []string{"Content-Security-Policy", "Cache-Control", "X-Content-Type-Options"} {
		if w.Header().Get(h) == "" {
			t.Errorf("the answer has no %s", h)
		}
	}

	if w := do(http.MethodPost, "/api/v1/updates/check", "cross-site", "", ""); w.Code != http.StatusForbidden || asked.Load() != 0 {
		t.Errorf("a check another site asked for answered %d after %d requests", w.Code, asked.Load())
	}
	if w := do(http.MethodPost, "/api/v1/updates/check", "same-origin", "", ""); w.Code != 200 || asked.Load() == 0 {
		t.Errorf("a check from the page answered %d", w.Code)
	}

	if w := do(http.MethodPost, "/api/v1/updates/daily", "cross-site", "application/json", `{"daily":true}`); w.Code != http.StatusForbidden || s.Settings.Daily() {
		t.Errorf("another site turned the daily check on: %d", w.Code)
	}
	for _, body := range []string{`{}`, `{"daily":1}`, `{"daily":true,"x":1}`, strings.Repeat(" ", 100) + `{"daily":true}`} {
		if w := do(http.MethodPost, "/api/v1/updates/daily", "same-origin", "application/json", body); w.Code != http.StatusBadRequest || s.Settings.Daily() {
			t.Errorf("%q answered %d", body, w.Code)
		}
	}
	if w := do(http.MethodPost, "/api/v1/updates/daily", "same-origin", "text/plain", `{"daily":true}`); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form post answered %d", w.Code)
	}
	if w := do(http.MethodPost, "/api/v1/updates/daily", "same-origin", "application/json", `{"daily":true}`); w.Code != 200 || !s.Settings.Daily() {
		t.Errorf("turning it on from the page answered %d", w.Code)
	}
	if w := do(http.MethodDelete, "/api/v1/updates", "same-origin", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("DELETE answered %d", w.Code)
	}
}
