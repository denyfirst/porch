package knownnames

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A list somebody gives is taken as given, cleaned, and held to the domain.
//
// This is the source that asks nothing, so everything it does is done to the
// list itself: one spelling per host, the domain's own apex dropped, another
// estate counted rather than listed, and anything that is not a host name left
// out rather than carried into a report saying a host exists.
func TestTheListIsTakenAsGivenAndHeldToTheDomain(t *testing.T) {
	found := From("example.test", []string{
		"bitrix.example.test",
		"BITRIX.example.test.", // one host, two spellings
		"  api.example.test  ",
		"example.test",           // the apex, which was the question
		"www.example.org",        // somebody else's estate
		"https://x.example.test", // pasted out of a browser
		"",
		"deep.api.example.test",
	})

	if !found.Asked {
		t.Error("a list that was given reads as no list at all")
	}
	if found.Reason != "" {
		t.Errorf("a list that was read reports %q", found.Reason)
	}

	want := []string{"api.example.test", "bitrix.example.test", "deep.api.example.test"}
	if len(found.Names) != len(want) {
		t.Fatalf("the list came back as %v", found.Names)
	}
	for i := range want {
		if found.Names[i] != want[i] {
			t.Errorf("name %d is %q, want %q", i, found.Names[i], want[i])
		}
	}
	if found.Foreign != 1 {
		t.Errorf("%d names were counted as another estate's, want 1", found.Foreign)
	}
}

// No list is not an empty list.
//
// The difference every source here is held to (R4). A report where nobody
// handed over a list and a report where somebody handed over a list of hosts
// that are all gone are the same empty set of extra names, and only Asked
// says which happened.
func TestNoListIsNotAnEmptyList(t *testing.T) {
	var none Found
	if none.Asked {
		t.Error("a source nobody used reads as used")
	}

	given := From("example.test", nil)
	if !given.Asked {
		t.Error("an empty list that was given reads as no list")
	}
	if len(given.Names) != 0 {
		t.Errorf("an empty list produced %v", given.Names)
	}
}

// A list longer than an estate is refused, and says the rule.
//
// The bound is the line between a list and a dictionary, so it is the one
// place this mode could quietly turn into the thing it refuses to be (N7). It
// is refused whole rather than cut to size, because a list that was shortened
// without saying so is an inventory that is quietly incomplete (R4), and the
// message says what the rule is rather than echoing what was sent (I6).
func TestAListLongerThanAnEstateIsRefused(t *testing.T) {
	long := make([]string, MaxNames+1)
	for i := range long {
		long[i] = fmt.Sprintf("host%d.example.test", i)
	}

	found := From("example.test", long)
	if found.Reason == "" {
		t.Fatal("a wordlist was accepted as an estate")
	}
	if len(found.Names) != 0 {
		t.Errorf("a refused list produced %d names", len(found.Names))
	}
	if strings.Contains(found.Reason, "host0.example.test") {
		t.Errorf("the reason echoes what was sent: %q", found.Reason)
	}
	if !strings.Contains(found.Reason, fmt.Sprint(MaxNames)) {
		t.Errorf("the reason does not say what the rule is: %q", found.Reason)
	}

	// And one below the bound is an estate.
	if found := From("example.test", long[:MaxNames]); found.Reason != "" {
		t.Errorf("a list at the bound was refused: %q", found.Reason)
	}
}

// A file is one name to a line, with room for the notes beside them.
//
// An operator's list is a file they keep rather than a file they write for
// this program, so it reads the shapes such a file already has: a comment at
// the top, a blank line between groups, and a column of notes after the name.
func TestAFileIsOneNameToALineWithRoomForNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	body := "# our estate, exported 2026-09-28\n" +
		"\n" +
		"bitrix.example.test    the intranet portal\n" +
		"api.example.test\n" +
		"   \n" +
		"#old.example.test\n" +
		"vpn.example.test\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	names, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	want := []string{"bitrix.example.test", "api.example.test", "vpn.example.test"}
	if len(names) != len(want) {
		t.Fatalf("the file read as %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("line %d read as %q, want %q", i, names[i], want[i])
		}
	}
}

// A file that is not a list of names is refused, and no path is echoed.
func TestAFileThatIsNotAListIsRefused(t *testing.T) {
	dir := t.TempDir()

	if _, err := ReadFile(filepath.Join(dir, "there-is-no-such-file.txt")); err == nil {
		t.Error("a file that does not exist was read")
	} else if strings.Contains(err.Error(), "there-is-no-such-file") {
		t.Errorf("the error echoes the path it was given: %v", err)
	}

	// A file of a hundred thousand lines is a wordlist, and is refused for
	// the reason MaxNames exists.
	path := filepath.Join(dir, "wordlist.txt")
	var b strings.Builder
	for i := 0; i <= MaxNames; i++ {
		fmt.Fprintf(&b, "host%d.example.test\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Error("a wordlist in a file was read as an estate")
	}

	// And one enormous line is refused rather than held in memory.
	long := filepath.Join(dir, "long.txt")
	if err := os.WriteFile(long, []byte(strings.Repeat("a", 4096)+".example.test\n"), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	if _, err := ReadFile(long); err == nil {
		t.Error("a line longer than any name was read")
	}
}
