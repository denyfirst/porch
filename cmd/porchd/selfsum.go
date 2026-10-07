package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
)

// programSum is the SHA-256 of the file this process was started from, as
// SHA256SUMS writes it, or "" when that file cannot be read.
//
// On Linux it reads /proc/self/exe, which is the program running even after a
// deploy has moved another file into its place; elsewhere, the path the
// process was started by.
func programSum() string {
	path := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		p, err := os.Executable()
		if err != nil {
			return ""
		}
		path = p
	}
	// #nosec G304 -- the path is this process's own executable, never input.
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
