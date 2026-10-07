package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// The sum the front page shows is the program's own file, as sha256sum would
// print it for the same file.
func TestProgramSumIsTheProgramsFile(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Skip("this platform cannot say where the test binary is")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got, want := programSum(), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("programSum is %s, and the file this test runs from hashes to %s", got, want)
	}
}
