// Package sshsig checks an SSH signature the way `ssh-keygen -Y verify` does,
// for the one kind this project makes: an Ed25519 key signing a file.
//
// The format is OpenSSH's PROTOCOL.sshsig. A release's SHA256SUMS is signed
// with `ssh-keygen -Y sign -n file` on the maintainer's machine, and every
// stranger checks it with `ssh-keygen -Y verify`. This is the same check,
// written so that porchd can make it without a shell, a binary on the PATH,
// or a dependency: the standard library has Ed25519 and SHA-512, and the
// envelope around them is a few length-prefixed strings.
//
// # What it accepts, and nothing else
//
// One key type (ssh-ed25519), one hash (sha512, ssh-keygen's default and the
// one the release is signed with), one namespace, given by the caller, and
// one key, given by the caller and compared byte for byte with the key the
// signature names. Anything else is refused rather than understood: a
// verifier that grew a second key type or a second hash would be one whose
// security is the weaker of the two, and nothing here needs either.
//
// Input is bounded before it is read, every length is checked against what
// is left, and a signature with anything after it is refused, so a parser
// fed whatever a server chose to send fails closed (see FuzzVerify).
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// MaxArmored bounds the armored signature read. An Ed25519 signature is a
// little over 300 bytes armored; anything near this is not one.
const MaxArmored = 4 << 10

const (
	magic      = "SSHSIG"
	version    = 1
	keyType    = "ssh-ed25519"
	hashName   = "sha512"
	beginArmor = "-----BEGIN SSH SIGNATURE-----"
	endArmor   = "-----END SSH SIGNATURE-----"
)

// ErrInvalid is every way a signature can fail to verify. The reasons are
// not told apart to the caller: what it does is the same for each, and a
// reason is a hint to whoever is trying to make one pass.
var ErrInvalid = errors.New("the signature does not verify with the release key")

// ParseKey reads the base64 body of an OpenSSH ed25519 public key, the
// middle field of a line in allowed_signers or authorized_keys.
func ParseKey(b64 string) (ed25519.PublicKey, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("sshsig: the key is not base64")
	}
	r := reader{b: blob}
	typ, ok1 := r.string()
	key, ok2 := r.string()
	if !ok1 || !ok2 || string(typ) != keyType || len(key) != ed25519.PublicKeySize || len(r.b) != 0 {
		return nil, errors.New("sshsig: the key is not an ssh-ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

// Verify reports whether armored is a signature by key over message, in
// namespace. It returns nil only for a signature that verifies, and
// ErrInvalid for everything else.
func Verify(key ed25519.PublicKey, namespace string, message, armored []byte) error {
	if len(key) != ed25519.PublicKeySize || namespace == "" || len(armored) > MaxArmored {
		return ErrInvalid
	}
	blob, ok := unarmor(armored)
	if !ok {
		return ErrInvalid
	}

	r := reader{b: blob}
	if !r.literal(magic) {
		return ErrInvalid
	}
	if v, ok := r.uint32(); !ok || v != version {
		return ErrInvalid
	}
	pub, ok := r.string()
	if !ok || !sameKey(pub, key) {
		return ErrInvalid
	}
	ns, ok := r.string()
	if !ok || string(ns) != namespace {
		return ErrInvalid
	}
	reserved, ok := r.string()
	if !ok {
		return ErrInvalid
	}
	hash, ok := r.string()
	if !ok || string(hash) != hashName {
		return ErrInvalid
	}
	sigBlob, ok := r.string()
	if !ok || len(r.b) != 0 {
		return ErrInvalid
	}

	s := reader{b: sigBlob}
	typ, ok1 := s.string()
	sig, ok2 := s.string()
	if !ok1 || !ok2 || string(typ) != keyType || len(sig) != ed25519.SignatureSize || len(s.b) != 0 {
		return ErrInvalid
	}

	// What was signed: the magic, then the namespace, the reserved field, the
	// hash's name and the hash of the message, each length-prefixed.
	digest := sha512.Sum512(message)
	var signed bytes.Buffer
	signed.WriteString(magic)
	putString(&signed, ns)
	putString(&signed, reserved)
	putString(&signed, hash)
	putString(&signed, digest[:])

	if !ed25519.Verify(key, signed.Bytes(), sig) {
		return ErrInvalid
	}
	return nil
}

// sameKey reports whether a public key blob is the ssh-ed25519 key given.
func sameKey(blob []byte, key ed25519.PublicKey) bool {
	r := reader{b: blob}
	typ, ok1 := r.string()
	k, ok2 := r.string()
	return ok1 && ok2 && len(r.b) == 0 && string(typ) == keyType && bytes.Equal(k, key)
}

// unarmor takes the base64 between the armor lines. The lines have to be
// there, in order, and nothing but whitespace may surround them.
func unarmor(armored []byte) ([]byte, bool) {
	text := strings.TrimSpace(string(armored))
	body, ok := strings.CutPrefix(text, beginArmor)
	if !ok {
		return nil, false
	}
	body, ok = strings.CutSuffix(body, endArmor)
	if !ok {
		return nil, false
	}
	body = strings.Join(strings.Fields(body), "")
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(blob) == 0 {
		return nil, false
	}
	return blob, true
}

// reader takes SSH wire-format fields off the front of b.
type reader struct{ b []byte }

func (r *reader) literal(s string) bool {
	if len(r.b) < len(s) || string(r.b[:len(s)]) != s {
		return false
	}
	r.b = r.b[len(s):]
	return true
}

func (r *reader) uint32() (uint32, bool) {
	if len(r.b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, true
}

// string reads a length-prefixed field, refusing a length longer than what
// is left: the length is read from the input and is not to be trusted.
func (r *reader) string() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || uint64(n) > uint64(len(r.b)) {
		return nil, false
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s, true
}

// putString writes a length-prefixed field. Every field written is a slice
// of a blob Verify bounded to MaxArmored before decoding, or a 64-byte digest.
func putString(w *bytes.Buffer, s []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s))) // #nosec G115 -- bounded by MaxArmored, see above
	w.Write(n[:])
	w.Write(s)
}
