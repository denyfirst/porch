// Package updates says whether a newer signed release of Porch exists, when
// the operator asks or once a day if they turned that on, and never installs
// anything.
//
// # What it does, and nothing else
//
// It asks GitHub for two public files of the latest release, SHA256SUMS and
// SHA256SUMS.sig, checks the signature with the release key compiled into
// this binary (the key in .allowed_signers; a test holds the two equal), and
// reads the version from the names the signed list carries. The version is
// the only thing taken from the network, and only once the list verifies.
//
// It never downloads a release, never runs a command, and never writes to
// this binary or to anything outside its one settings file. Updating stays a
// thing the operator does, in their own terminal, with the commands the page
// shows — which are written into the page, not fetched — and which check the
// signature again before anything is replaced. A compromised release channel
// can therefore show a banner at most, and only a banner whose list verifies.
//
// The request carries no cookie, no version and nothing about this
// installation or its scans. GitHub sees this server's address and that it
// asked, which is why the daily check is off until the operator turns it on,
// and why the pages say so.
//
// Not on the demonstration, which connects only to hosts this project owns
// (N6): Check refuses there, and porchd does not build a Service for it.
package updates

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/sshsig"
)

// ReleaseKey is the release signing key, the base64 field of the
// releases@denyfirst.dev line in .allowed_signers. Compiled in rather than
// fetched: a key fetched beside the files it vouches for vouches for nothing.
const ReleaseKey = "AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR"

// Where the latest release's files are. GitHub answers with a redirect to
// the release's own address and then to its file store.
const latestBase = "https://github.com/denyfirst/porch/releases/latest/download/"

const (
	maxSums     = 16 << 10
	timeout     = 20 * time.Second
	maxRedirect = 5
	userAgent   = "porch"
)

// allowedHosts are the only hosts a check may be redirected to.
var allowedHosts = map[string]bool{
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// What a check can fail with. The pages show the message as written here;
// nothing a server sent is repeated.
var (
	ErrUnreachable = errors.New("GitHub could not be reached")
	ErrNotVerified = errors.New("the release list GitHub served does not verify with the release key: do not update, and see docs/verify.md")
	ErrUnreadable  = errors.New("the release list could not be read")
	ErrDemo        = errors.New("the demonstration does not check for updates")
)

// version is a release name: v, then three numbers of at most four digits.
var version = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// artifact is a release file whose name carries the version, matched whole:
// a binary is name_version_os_arch, with .exe on Windows, and the image is
// porch-image_version.tar. A name with anything else in it is not read.
var artifact = regexp.MustCompile(`^(?:porch-scan|porchd|porchd-demonstration|porch-image)_(v\d{1,4}\.\d{1,4}\.\d{1,4})(?:_[a-z0-9]{1,16}_[a-z0-9]{1,16}(?:\.exe)?|\.tar)$`)

// Checker fetches and verifies the latest release's list.
type Checker struct {
	// Client is used for both requests. Nil builds one that dials through
	// safedial, port 443 only, with Roots.
	Client *http.Client

	// Roots judges GitHub's certificate. Nil means the system store.
	Roots *x509.CertPool

	// Base is where the files are fetched from. Empty means GitHub's latest
	// release; tests point it elsewhere.
	Base string
}

// Check returns the version the latest signed list names.
func (c *Checker) Check(ctx context.Context) (string, error) {
	if demo.Enabled {
		return "", ErrDemo
	}
	key, err := sshsig.ParseKey(ReleaseKey)
	if err != nil {
		return "", ErrUnreadable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := c.Client
	if client == nil {
		client = c.client()
	}
	base := c.Base
	if base == "" {
		base = latestBase
	}
	sums, err := fetch(ctx, client, base+"SHA256SUMS", maxSums)
	if err != nil {
		return "", err
	}
	sig, err := fetch(ctx, client, base+"SHA256SUMS.sig", sshsig.MaxArmored)
	if err != nil {
		return "", err
	}
	if sshsig.Verify(key, "file", sums, sig) != nil {
		return "", ErrNotVerified
	}
	return LatestVersion(sums)
}

func (c *Checker) client() *http.Client {
	d := &safedial.Dialer{Timeout: 10 * time.Second, AllowedPorts: []string{"443"}}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: c.Roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     5 * time.Second,
		},
	}
}

// checkRedirect follows GitHub's redirects and nothing else: HTTPS, to a host
// on the list, a few times at most.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirect {
		return ErrUnreachable
	}
	if !allowedURL(req.URL) {
		return ErrUnreachable
	}
	return nil
}

func allowedURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && allowedHosts[strings.ToLower(u.Hostname())] &&
		(u.Port() == "" || u.Port() == "443")
}

// fetch reads one file, refusing anything over limit rather than cutting it:
// a cut list would fail the signature and read as tampering.
func fetch(ctx context.Context, client *http.Client, raw string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, ErrUnreadable
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrUnreachable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, ErrUnreachable
	}
	if int64(len(body)) > limit {
		return nil, ErrUnreadable
	}
	return body, nil
}

// LatestVersion reads the version a signed list names. Every versioned file
// on it has to name the same one, or the list is not read at all.
func LatestVersion(sums []byte) (string, error) {
	found := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		m := artifact.FindStringSubmatch(strings.TrimPrefix(fields[1], "*"))
		if m == nil {
			continue
		}
		if found != "" && m[1] != found {
			return "", ErrUnreadable
		}
		found = m[1]
	}
	if found == "" || !version.MatchString(found) {
		return "", ErrUnreadable
	}
	return found, nil
}

// Newer reports whether latest is a later release than running. A running
// version that is not a release name (a build not made by build.sh) is
// never behind: the page then shows the latest and claims nothing.
func Newer(running, latest string) bool {
	a, okA := parse(running)
	b, okB := parse(latest)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if b[i] != a[i] {
			return b[i] > a[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	m := version.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// State is what the pages are told.
type State struct {
	Running   string    `json:"running"`
	Latest    string    `json:"latest,omitempty"`
	Newer     bool      `json:"newer"`
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	Daily     bool      `json:"daily"`
	Error     string    `json:"error,omitempty"`

	// Tampered says the last list GitHub served did not verify with the
	// release key. The pages say it as a warning, never as an update.
	Tampered bool `json:"tampered,omitempty"`
}

// Service holds what was last found, runs the daily check when it is on, and
// spaces checks apart however often somebody presses the button.
type Service struct {
	Checker  *Checker
	Settings *Settings
	Running  string

	// MinInterval is the least time between two checks. Zero means a minute.
	MinInterval time.Duration

	mu       sync.Mutex
	checking sync.Mutex
	state    State
	wake     chan struct{}
	now      func() time.Time
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) minInterval() time.Duration {
	if s.MinInterval > 0 {
		return s.MinInterval
	}
	return time.Minute
}

// State returns what was last found.
func (s *Service) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	out.Running = s.Running
	out.Daily = s.Settings.Daily()
	out.Newer = out.Latest != "" && Newer(s.Running, out.Latest)
	return out
}

// CheckNow checks, unless a check finished less than MinInterval ago, in
// which case it returns what that one found. Two at once wait for one.
func (s *Service) CheckNow(ctx context.Context) State {
	s.checking.Lock()
	defer s.checking.Unlock()
	s.mu.Lock()
	recent := !s.state.CheckedAt.IsZero() && s.clock().Sub(s.state.CheckedAt) < s.minInterval()
	s.mu.Unlock()
	if !recent {
		latest, err := s.Checker.Check(ctx)
		s.mu.Lock()
		s.state.CheckedAt = s.clock().UTC().Truncate(time.Second)
		if err != nil {
			s.state.Error = err.Error()
			s.state.Tampered = errors.Is(err, ErrNotVerified)
			// A list that does not verify says nothing about the latest
			// release; what an earlier check found is kept only if it
			// verified, which it did.
		} else {
			s.state.Error = ""
			s.state.Tampered = false
			s.state.Latest = latest
		}
		s.mu.Unlock()
	}
	return s.State()
}

// SetDaily turns the daily check on or off, and keeps the choice.
func (s *Service) SetDaily(on bool) error {
	if err := s.Settings.SetDaily(on); err != nil {
		return err
	}
	s.mu.Lock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	wake := s.wake
	s.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
	return nil
}

// Run checks once a day while the daily check is on, until ctx ends. The
// first check comes a few minutes after start, and each one after about a
// day later, at a time no two installations share. Turning it on checks at
// once, in the handler, so the first one here is a day after that.
func (s *Service) Run(ctx context.Context) {
	s.mu.Lock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	wake := s.wake
	s.mu.Unlock()

	next := s.clock().Add(between(time.Minute, 10*time.Minute))
	for {
		// Off: wait to be turned on, or for the end. On: wait for the next
		// check as well. One timer at a time, stopped before the next.
		var t *time.Timer
		var due <-chan time.Time
		if s.Settings.Daily() {
			t = time.NewTimer(time.Until(next))
			due = t.C
		}
		select {
		case <-ctx.Done():
			if t != nil {
				t.Stop()
			}
			return
		case <-wake:
			if t != nil {
				t.Stop()
			}
			next = s.clock().Add(between(time.Minute, 10*time.Minute))
		case <-due:
			// A check since this was planned, from Check now or from turning
			// the daily check on, is the day's check: the next is a day after
			// it, not a second request to GitHub minutes later.
			if last, recent := s.checkedWithinADay(); recent {
				next = last.Add(23*time.Hour + between(0, 2*time.Hour))
				continue
			}
			if s.Settings.Daily() {
				s.CheckNow(ctx)
			}
			next = s.clock().Add(23*time.Hour + between(0, 2*time.Hour))
		}
	}
}

// checkedWithinADay reports when the last check finished, and whether that
// was less than a day ago.
func (s *Service) checkedWithinADay() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.state.CheckedAt
	return last, !last.IsZero() && s.clock().Sub(last) < 23*time.Hour
}

// between is a random duration in [lo, hi), from crypto/rand, so the hour an
// installation asks is not something another can predict.
func between(lo, hi time.Duration) time.Duration {
	span := hi - lo
	if span <= 0 {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return lo + span/2
	}
	return lo + time.Duration(n.Int64())
}
