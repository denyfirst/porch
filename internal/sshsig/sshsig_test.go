package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// releaseKey is the key in .allowed_signers at the root of this repository,
// read from there so the test checks against the key strangers use.
func releaseKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", ".allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "releases@denyfirst.dev" && fields[1] == "ssh-ed25519" {
			key, err := ParseKey(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return key
		}
	}
	t.Fatal(".allowed_signers names no release key")
	return nil
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A real release's list verifies with the release key, as `ssh-keygen -Y
// verify -n file` says it does (v0.27.1's, published and reproduced).
func TestAReleaseSignatureVerifies(t *testing.T) {
	key := releaseKey(t)
	sums, sig := testdata(t, "SHA256SUMS"), testdata(t, "SHA256SUMS.sig")
	if err := Verify(key, "file", sums, sig); err != nil {
		t.Fatalf("the release's own signature was refused: %v", err)
	}
}

// Everything that is not that signature over that list, by that key, in that
// namespace, with that hash, is refused.
func TestEverythingElseIsRefused(t *testing.T) {
	key := releaseKey(t)
	sums, sig := testdata(t, "SHA256SUMS"), testdata(t, "SHA256SUMS.sig")

	other, err := ParseKey(strings.TrimSpace(string(testdata(t, "other-key.pub"))))
	if err != nil {
		t.Fatal(err)
	}
	// The throwaway key's own signature is good, so each refusal below is
	// about the one thing that differs, not a broken test vector.
	if err := Verify(other, "file", sums, testdata(t, "other-key.sig")); err != nil {
		t.Fatalf("the test key's signature does not verify with the test key: %v", err)
	}

	tampered := bytes.Replace(sums, []byte("porchd_v0.27.1_linux_amd64"), []byte("porchd_v0.27.9_linux_amd64"), 1)
	cases := map[string]struct {
		key ed25519.PublicKey
		ns  string
		msg []byte
		sig []byte
	}{
		"another key's signature":                    {key, "file", sums, testdata(t, "other-key.sig")},
		"the release's under a key it does not name": {other, "file", sums, sig},
		"another namespace asked":                    {key, "git", sums, sig},
		"signed in another namespace":                {other, "file", sums, testdata(t, "other-key-git-namespace.sig")},
		"signed with sha256":                         {other, "file", sums, testdata(t, "other-key-sha256.sig")},
		"a changed list":                             {key, "file", tampered, sig},
		"an empty list":                              {key, "file", nil, sig},
		"no signature":                               {key, "file", sums, nil},
		"no armor":                                   {key, "file", sums, bytes.ReplaceAll(sig, []byte("-----"), nil)},
		"text after the armor":                       {key, "file", sums, append(append([]byte{}, sig...), []byte("x")...)},
		"a cut signature":                            {key, "file", sums, sig[:len(sig)/2]},
		"an oversized signature":                     {key, "file", sums, bytes.Repeat([]byte("A"), MaxArmored+1)},
		"no namespace asked":                         {key, "", sums, sig},
		"a short key":                                {key[:16], "file", sums, sig},
	}
	for name, c := range cases {
		if err := Verify(c.key, c.ns, c.msg, c.sig); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// A key that is not an ssh-ed25519 public key is not read as one.
func TestOnlyAnEd25519KeyIsAKey(t *testing.T) {
	for _, bad := range []string{
		"", "not base64!",
		// An ssh-rsa key's opening, which is base64 and the wrong type.
		"AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
	} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q was read as a key", bad)
		}
	}
}

// Whatever a server sends as a signature, Verify returns and refuses it
// unless it is the release's: no panic, no read past the input.
func FuzzVerify(f *testing.F) {
	sums, err := os.ReadFile(filepath.Join("testdata", "SHA256SUMS"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"SHA256SUMS.sig", "other-key.sig", "other-key-sha256.sig"} {
		sig, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(sig)
	}
	f.Add([]byte(beginArmor + "\nU1NIU0lH\n" + endArmor))
	f.Add([]byte(beginArmor + "\nU1NIU0lHAAAAAf////8=\n" + endArmor))

	body, err := os.ReadFile(filepath.Join("..", "..", ".allowed_signers"))
	if err != nil {
		f.Fatal(err)
	}
	var key ed25519.PublicKey
	for _, line := range strings.Split(string(body), "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 && fields[0] == "releases@denyfirst.dev" {
			if key, err = ParseKey(fields[2]); err != nil {
				f.Fatal(err)
			}
		}
	}
	real, err := os.ReadFile(filepath.Join("testdata", "SHA256SUMS.sig"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, sig []byte) {
		err := Verify(key, "file", sums, sig)
		if err == nil && !bytes.Equal(bytes.TrimSpace(sig), bytes.TrimSpace(real)) {
			// Base64 and armor whitespace may vary; the decoded blob may not.
			a, _ := unarmor(sig)
			b, _ := unarmor(real)
			if !bytes.Equal(a, b) {
				t.Fatalf("a signature other than the release's verified: %q", sig)
			}
		}
	})
}
