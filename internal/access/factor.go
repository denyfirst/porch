package access

// The second factor: a code from an authenticator app (RFC 6238), asked for
// with the password once the operator has turned it on, and ten recovery
// codes for a phone that is lost.
//
// What it is kept in, and why there:
//
//   - The seed is sealed with AES-256-GCM under the data key, in a file beside
//     the access file. The data key exists only once the password has opened
//     the access file, so the code is checked after the password and never
//     instead of it, and a copy of the disk holds no readable seed.
//   - Whether a code is asked for is whether that file exists, which can be
//     answered before the password is derived. A sign-in without a code is
//     told to send one without its password being checked, so the answer
//     says nothing about the password.
//   - With the second factor on, a wrong password and a wrong code are one
//     answer, word for word, so the page is not a way to test passwords.
//   - A code is accepted once: the last counter accepted is kept, and only a
//     later one is taken. A recovery code is a random 120-bit value, kept
//     only as an HMAC under the data key, and goes when it is used.
//   - Wrong codes are bounded for the whole installation, not per address,
//     because whoever sends them already has the password and any number of
//     addresses. Past the bound codes are refused, the same way; a recovery
//     code is still accepted, being unguessable. The number of wrong codes
//     sent with the right password is shown to the operator after the next
//     sign-in, which is how a leaked password is noticed. It is held in
//     memory: a failure writes nothing, because a write takes time an
//     attacker could measure, and the time would say the password was right.
//   - Somebody who can run commands on the server removes the file to turn
//     the second factor off. That is no weaker than it was: they could read
//     the process's memory.
//
// HMAC-SHA1 is what RFC 6238 and every authenticator app compute. HMAC's
// security does not rest on SHA-1's collision resistance.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 4226 and 6238 fix HMAC-SHA1 for authenticator apps; HMAC does not rely on SHA-1's collision resistance.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FactorFile is the name of the second factor's file, beside the access file.
const FactorFile = "second-factor"

// factorLabel is authenticated with the sealed state, so nothing else sealed
// under the data key opens as it.
const factorLabel = "porch-second-factor-v1"

const (
	// recoveryCount is how many recovery codes are made at a time.
	recoveryCount = 10

	// codeFailLimit wrong codes in codeFailWindow, across the installation,
	// and codes wait until the window ends.
	codeFailLimit  = 5
	codeFailWindow = 5 * time.Minute

	// setupLife is how long a seed shown for scanning waits to be confirmed.
	setupLife = 10 * time.Minute
)

// errWrongCredentials is a sign-in that failed with the second factor on,
// whether the password or the code was wrong.
var errWrongCredentials = errors.New("the password or the code is not right")

// factorState is what the file seals.
type factorState struct {
	Seed string `json:"seed"`
	// Last is the counter of the last code accepted.
	Last int64 `json:"last"`
	// Recovery holds the HMAC of each recovery code not yet used.
	Recovery [][]byte `json:"recovery"`
}

type factorBox struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Box     []byte `json:"box"`
}

func factorPath(accessPath string) string {
	return filepath.Join(filepath.Dir(accessPath), FactorFile)
}

// factorOn reports whether the second factor is on. A file that cannot be
// looked at is an error, never "off".
func factorOn(accessPath string) (bool, error) {
	_, err := os.Lstat(factorPath(accessPath))
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	}
	return false, fmt.Errorf("the second factor's file could not be read: %w", err)
}

func factorAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func loadFactor(accessPath string, key []byte) (*factorState, error) {
	// #nosec G304 -- beside the operator-supplied access file, never request-supplied
	body, err := os.ReadFile(factorPath(accessPath))
	if err != nil {
		return nil, fmt.Errorf("the second factor's file could not be read: %w", err)
	}
	var box factorBox
	if json.Unmarshal(body, &box) != nil || box.Version != 1 || len(box.Nonce) != 12 {
		return nil, errors.New("the second factor's file is not one this program wrote")
	}
	gcm, err := factorAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, box.Nonce, box.Box, []byte(factorLabel))
	if err != nil {
		return nil, errors.New("the second factor's file does not open with this installation's key")
	}
	defer clear(plain)
	var st factorState
	if json.Unmarshal(plain, &st) != nil || !validSeed(st.Seed) {
		return nil, errors.New("the second factor's file is not one this program wrote")
	}
	return &st, nil
}

// saveFactor replaces the file by a rename, so it is never half-written.
func saveFactor(accessPath string, key []byte, st *factorState) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	defer clear(plain)
	gcm, err := factorAEAD(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("a nonce could not be generated: %w", err)
	}
	body, err := json.Marshal(factorBox{Version: 1, Nonce: nonce, Box: gcm.Seal(nil, nonce, plain, []byte(factorLabel))})
	if err != nil {
		return err
	}
	path := factorPath(accessPath)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".second-factor-*")
	if err != nil {
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("the second factor could not be saved: %w", err)
	}
	return nil
}

var seedEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func validSeed(seed string) bool {
	b, err := seedEncoding.DecodeString(seed)
	return err == nil && len(b) == 20 && seedEncoding.EncodeToString(b) == seed
}

// newSeed is 160 random bits, the length RFC 4226 recommends.
func newSeed() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("a seed could not be generated: %w", err)
	}
	defer clear(raw)
	return seedEncoding.EncodeToString(raw), nil
}

// seedURI is the key URI authenticator apps read. SHA1, six digits and thirty
// seconds are the format's defaults and exactly what codeCounter checks, so
// they stay implicit. The account is the product's name and nothing about the
// installation: the app's list, and any backup of it, learns no host name.
func seedURI(seed string) string {
	return "otpauth://totp/Porch:porch?secret=" + seed + "&issuer=Porch"
}

// hotp is RFC 4226: HMAC-SHA1 of the big-endian counter, dynamic truncation
// to 31 bits, the low six decimal digits.
func hotp(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key) // #nosec G401 -- RFC 4226 HMAC-SHA1, as authenticator apps compute it.
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	at := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[at:at+4])&0x7fffffff)%1000000)
}

// codeCounter checks code against the thirty-second steps either side of
// now, as RFC 6238 allows for a clock that drifts, compares in constant time,
// and returns the latest matching counter above last.
func codeCounter(seed, code string, now time.Time, last int64) (int64, bool) {
	if !validSeed(seed) || !sixDigits(code) || now.Unix() < 30 {
		return 0, false
	}
	key, err := seedEncoding.DecodeString(seed)
	if err != nil {
		return 0, false
	}
	defer clear(key)
	current := now.Unix() / 30
	matched := int64(-1)
	for _, counter := range []int64{current - 1, current, current + 1} {
		if counter <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(counter))), []byte(code)) == 1 {
			matched = max(matched, counter)
		}
	}
	return matched, matched >= 0
}

// appCode reads a code as an app shows it: some show "123 456", and the
// space is typed too. Anything else is left for the recovery codes.
func appCode(code string) string {
	code = strings.TrimSpace(code)
	if compact := strings.ReplaceAll(code, " ", ""); sixDigits(compact) {
		return compact
	}
	return code
}

func sixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// newRecovery makes recoveryCount codes, each 120 random bits as six groups
// of four letters and digits, and their HMACs under key.
func newRecovery(key []byte) ([]string, [][]byte, error) {
	codes := make([]string, recoveryCount)
	digests := make([][]byte, recoveryCount)
	for i := range codes {
		raw := make([]byte, 15)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("a recovery code could not be generated: %w", err)
		}
		text := strings.ToLower(seedEncoding.EncodeToString(raw))
		clear(raw)
		var groups []string
		for len(text) > 0 {
			groups = append(groups, text[:4])
			text = text[4:]
		}
		codes[i] = strings.Join(groups, "-")
		digests[i] = recoveryDigest(key, codes[i])
	}
	return codes, digests, nil
}

// recoveryDigest is the HMAC a recovery code is kept as. What is typed is
// read as the code would be written: case, spaces and hyphens do not matter.
func recoveryDigest(key []byte, code string) []byte {
	normal := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7'):
			return r
		}
		return -1
	}, code)
	var groups []string
	for len(normal) >= 4 {
		groups = append(groups, normal[:4])
		normal = normal[4:]
	}
	if normal != "" {
		groups = append(groups, normal)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("porch/recovery/v1/" + strings.Join(groups, "-")))
	return mac.Sum(nil)
}

// useRecovery takes code from st if it is one of its unused recovery codes.
func useRecovery(st *factorState, key []byte, code string) bool {
	if len(code) > 64 {
		return false
	}
	digest := recoveryDigest(key, code)
	found := -1
	for i, d := range st.Recovery {
		if subtle.ConstantTimeCompare(d, digest) == 1 {
			found = i
		}
	}
	if found < 0 {
		return false
	}
	st.Recovery = append(st.Recovery[:found], st.Recovery[found+1:]...)
	return true
}

// codesWait reports whether wrong codes have used up the window.
func (g *Gate) codesWait() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.now().Sub(g.codeWindow) >= codeFailWindow {
		g.codeWindow, g.codeFails = g.now(), 0
	}
	return g.codeFails >= codeFailLimit
}

func (g *Gate) codeFailed() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.now().Sub(g.codeWindow) >= codeFailWindow {
		g.codeWindow, g.codeFails = g.now(), 0
	}
	g.codeFails++
}

// checkCode accepts code against st: a code from the app while codes are not
// waiting, or an unused recovery code at any time. A use changes st, which
// the caller saves; a failure changes nothing on disk.
func (g *Gate) checkCode(st *factorState, key []byte, code string) bool {
	code = appCode(code)
	if sixDigits(code) {
		if !g.codesWait() {
			if counter, ok := codeCounter(st.Seed, code, g.now(), st.Last); ok {
				st.Last = counter
				return true
			}
		}
		g.codeFailed()
	} else if useRecovery(st, key, code) {
		return true
	}
	g.mu.Lock()
	g.wrongCodes++
	g.mu.Unlock()
	return false
}

// confirmFactor opens the second factor with key and checks code against it,
// saving only what an accepted code changed. It is called with the
// derivation slot held, so no two of these read and write the file at once.
func (g *Gate) confirmFactor(key []byte, code string) (*factorState, error) {
	st, err := loadFactor(g.path, key)
	if err != nil {
		return nil, err
	}
	if !g.checkCode(st, key, code) {
		return nil, errWrongCredentials
	}
	if err := saveFactor(g.path, key, st); err != nil {
		return nil, err
	}
	return st, nil
}
