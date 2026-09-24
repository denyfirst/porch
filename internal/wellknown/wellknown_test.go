package wellknown

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every address under /.well-known that this project asks for is named here.
//
// The list is what makes N7's line hold. A well-known URI is not a guess — RFC
// 8615 created the space as the register of addresses a server offers to anyone
// who asks — but that argument only survives while the list is short and every
// entry carries the document that defines it. Three constants in three packages
// is not a list; it is three decisions nobody made together, and the fourth is
// the one that arrives without being noticed.
//
// This walks the source rather than trusting the packages to register
// themselves, because a package that forgot to register would be exactly the
// case worth catching.
func TestEveryWellKnownAddressInTheSourceIsNamedHere(t *testing.T) {
	root := filepath.Join("..", "..")
	pattern := regexp.MustCompile(`"(/\.well-known/[A-Za-z0-9._-]+)"`)

	found := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The repository's own machinery, not the program.
			if name := d.Name(); name == ".git" || name == "dist" || name == "tmp" {
				return fs.SkipDir
			}
			return nil
		}
		// Go that ships. A test fixture may hold any address at all — that is
		// what a fixture is for — and the rule is about what the program asks
		// of somebody else's server.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// And not the list itself, which names every address by definition. A
		// walk that reads this file finds each entry in the source and so
		// counts the entry as used — meaning an address nothing fetches could
		// be added here and the half of this test that refuses an unused entry
		// would never fire again. Found by sabotage on 2026-09-24, when
		// exactly that was tried and only a second test noticed.
		if filepath.Base(path) == "wellknown.go" {
			return nil
		}

		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range pattern.FindAllStringSubmatch(string(body), -1) {
			found[m[1]] = append(found[m[1]], path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the source: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("no address under /.well-known was found in the source, which cannot be right")
	}
	for address, files := range found {
		if !Covers(address) {
			t.Errorf("%s is requested by %v and is not named in this package", address, files)
		}
	}

	// And nothing is named here that the program no longer asks for: a list
	// with an entry nobody uses is a list somebody will trust for the wrong
	// address.
	for _, p := range append(append([]Path{}, Requested...), Served...) {
		if _, ok := found[p.Path]; !ok {
			t.Errorf("%s is named here and nothing in the source requests it", p.Path)
		}
		if p.Document == "" || p.Why == "" {
			t.Errorf("%s is named without a document or without a reason", p.Path)
		}
	}
}

// retired is the promise this project made and stopped keeping. Case is
// ignored because a sabotage on 2026-09-24 walked straight past this guard by
// starting the sentence — which is how the sentence is usually written.
var retired = regexp.MustCompile(`(?i)no guessing under`)

// n7 is the section of the invariants that states the rule, cut out from the
// heading to the next one. The whole file is the wrong unit: a path removed
// from N7 was still found elsewhere in it, by a paragraph about mail policy
// that happens to quote a URL, so the check passed while the rule had stopped
// naming what the code fetches. A rule is a section, not a search.
var n7 = regexp.MustCompile(`(?s)### N7 — .*?\n### `)

// The list and the promise made to the people being scanned agree.
//
// N7's argument is not that these addresses are harmless in general; it is
// that this project's list is short, deliberate, and written down where the
// scanned party can read it. A list that grew without the pages growing with
// it would leave the method page making a promise the binary no longer keeps,
// which is worse than never having promised.
//
// The method page carried exactly that fault until 2026-09-24: it said no
// guessing under /.well-known while two paths under it were already being
// fetched, one of them for months.
func TestTheListAndTheWrittenPromiseAgree(t *testing.T) {
	for _, doc := range []string{
		filepath.Join("..", "..", "docs", "invariants.md"),
		filepath.Join("..", "..", "internal", "web", "assets", "web-method.html"),
	} {
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("reading %s: %v", doc, err)
		}
		// The retired sentence, in either face. Both files still carry the
		// words, because both say plainly what they used to promise and when
		// they stopped — so what is refused is the sentence standing as a
		// promise, not the sentence quoted as a correction. A quotation says
		// when it ended; a promise does not.
		for _, at := range retired.FindAllStringIndex(string(body), -1) {
			tail := string(body)[at[1]:min(at[1]+120, len(body))]
			if !strings.Contains(tail, "until") {
				t.Errorf("%s promises no guessing under /.well-known without saying when that stopped being true, and this project fetches two paths there", doc)
			}
		}
	}

	invariants, err := os.ReadFile(filepath.Join("..", "..", "docs", "invariants.md"))
	if err != nil {
		t.Fatalf("reading the invariants: %v", err)
	}
	rule := n7.FindString(string(invariants))
	if rule == "" {
		t.Fatal("N7 was not found in the invariants, so nothing here checked anything")
	}
	for _, p := range Requested {
		if !strings.Contains(rule, p.Path) {
			t.Errorf("%s is fetched and N7 does not name it, so the rule and the code disagree", p.Path)
		}
	}
}

// Covers refuses an address that is in neither list, and the two lists stay on
// their own sides.
//
// The walk above can only notice an address it finds in the source, so a
// Covers that answered yes to everything passed it — the sabotage that proved
// this escaped on 2026-09-24. The walk asks "is this named?"; nothing asked
// "and would it say no?" Both halves are needed, because Covers is the
// function anything else in this project would call to decide whether a path
// is one of ours.
func TestCoversRefusesAnAddressNobodyDecidedOn(t *testing.T) {
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/acme-challenge/x",
		"/.well-known/",
		"/admin",
		"",
	} {
		if Covers(path) {
			t.Errorf("%q is in neither list and Covers claims it is named", path)
		}
	}

	// And the split holds: the address this project answers at is not on the
	// side that says what it asks other people's servers for. N7's whole
	// clarification rests on that line, so it is asserted rather than left to
	// the comments.
	for _, p := range Requested {
		if p.Path == "/.well-known/security.txt" {
			t.Error("security.txt is published by this project, not requested of anybody, and it has moved to the asked-for list")
		}
	}
	if !Covers("/.well-known/security.txt") {
		t.Error("the address this project serves is not named at all")
	}
	for _, p := range Served {
		for _, q := range Requested {
			if p.Path == q.Path {
				t.Errorf("%s is on both sides, which makes the split say nothing", p.Path)
			}
		}
	}
}
